package ingest

import (
	"math"
	"time"

	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	MinStep    = 10
	MaxStep    = 3600
	MaxBuckets = 500
	MaxSpan    = 31 * 24 * time.Hour
)

// Point is one chart sample. V is nil when the bucket has no data.
type Point struct {
	T time.Time
	V *float64
}

// Series is one named line in a metrics response.
type Series struct {
	Name   string
	Unit   string
	Points []Point
}

// ChooseStep picks the bucket width. requested 0 means the default that aims
// for at most 500 points, clamped to 10–3600 seconds. A span that still
// exceeds 500 points at 3600 seconds keeps 3600, which is the contract maximum.
func ChooseStep(from, to time.Time, requested int) (int, error) {
	if !to.After(from) {
		return 0, &Reject{Reason: "bad_range"}
	}
	if to.Sub(from) > MaxSpan {
		return 0, &Reject{Reason: "range_too_long"}
	}
	if requested == 0 {
		span := to.Sub(from).Seconds()
		requested = int(math.Ceil(span / 500))
		if requested < MinStep {
			requested = MinStep
		}
		if requested > MaxStep {
			requested = MaxStep
		}
		return requested, nil
	}
	if requested < MinStep || requested > MaxStep {
		return 0, &Reject{Reason: "bad_step"}
	}
	return requested, nil
}

// Bucket aggregates raw samples into the series for measurement m.
func Bucket(m string, from, to time.Time, stepSec int, samples []store.Sample) ([]Series, error) {
	step := time.Duration(stepSec) * time.Second
	n := bucketCount(from, to, step)
	switch m {
	case "cpu":
		return []Series{avgSeries("usage_percent", "%", from, step, n, samples, func(s store.Sample) (float64, bool) {
			idle, ok := s.Floats["usage_idle"]
			if !ok {
				return 0, false
			}
			return 100 - idle, true
		})}, nil
	case "mem":
		return []Series{
			avgSeries("used_percent", "%", from, step, n, samples, floatField("used_percent")),
			avgSeries("used", "bytes", from, step, n, samples, intField("used")),
			avgSeries("total", "bytes", from, step, n, samples, intField("total")),
		}, nil
	case "disk":
		filtered := filterTags(samples, func(s store.Sample) bool { return s.Tags["path"] == "/" })
		return []Series{avgSeries("used_percent", "%", from, step, n, filtered, floatField("used_percent"))}, nil
	case "diskio":
		return []Series{
			rateSeries("read_bps", "bytes/s", from, step, n, samples, "name", "read_bytes"),
			rateSeries("write_bps", "bytes/s", from, step, n, samples, "name", "write_bytes"),
		}, nil
	case "net":
		filtered := filterTags(samples, func(s store.Sample) bool { return s.Tags["interface"] != "lo" })
		return []Series{
			rateSeries("rx_bps", "bytes/s", from, step, n, filtered, "interface", "bytes_recv"),
			rateSeries("tx_bps", "bytes/s", from, step, n, filtered, "interface", "bytes_sent"),
		}, nil
	case "system":
		return []Series{
			avgSeries("load1", "", from, step, n, samples, floatField("load1")),
			avgSeries("load5", "", from, step, n, samples, floatField("load5")),
			avgSeries("load15", "", from, step, n, samples, floatField("load15")),
			avgSeries("uptime", "s", from, step, n, samples, intField("uptime")),
		}, nil
	case "temp":
		return []Series{avgSeries("celsius", "°C", from, step, n, samples, floatField("celsius"))}, nil
	default:
		return nil, &Reject{Reason: "unknown_measurement"}
	}
}

func bucketCount(from, to time.Time, step time.Duration) int {
	span := to.Sub(from)
	n := int(span / step)
	if span%step != 0 {
		n++
	}
	if n < 1 {
		n = 1
	}
	if n > MaxBuckets {
		n = MaxBuckets
	}
	return n
}

func indexOf(t, from time.Time, step time.Duration, n int) int {
	if t.Before(from) {
		return -1
	}
	i := int(t.Sub(from) / step)
	if i < 0 || i >= n {
		return -1
	}
	return i
}

type valueFn func(store.Sample) (float64, bool)

func floatField(name string) valueFn {
	return func(s store.Sample) (float64, bool) {
		v, ok := s.Floats[name]
		return v, ok
	}
}

func intField(name string) valueFn {
	return func(s store.Sample) (float64, bool) {
		v, ok := s.Ints[name]
		return float64(v), ok
	}
}

func avgSeries(name, unit string, from time.Time, step time.Duration, n int, samples []store.Sample, pick valueFn) Series {
	sum := make([]float64, n)
	cnt := make([]int, n)
	for _, s := range samples {
		v, ok := pick(s)
		if !ok {
			continue
		}
		i := indexOf(s.T, from, step, n)
		if i < 0 {
			continue
		}
		sum[i] += v
		cnt[i]++
	}
	return Series{Name: name, Unit: unit, Points: points(from, step, n, func(i int) *float64 {
		if cnt[i] == 0 {
			return nil
		}
		v := sum[i] / float64(cnt[i])
		return &v
	})}
}

// rateSeries sums, per bucket, each series' own (latest-earliest)/dt.
// A negative delta or a single sample (dt <= 0) is dropped for that series.
// This matches the SQL charts: one delta per series per time_bucket, then a sum.
func rateSeries(name, unit string, from time.Time, step time.Duration, n int, samples []store.Sample, tagKey, field string) Series {
	type span struct {
		firstT, lastT time.Time
		firstV, lastV int64
		has           bool
	}
	byTag := map[string][]span{}
	for _, s := range samples {
		v, ok := s.Ints[field]
		if !ok {
			continue
		}
		i := indexOf(s.T, from, step, n)
		if i < 0 {
			continue
		}
		key := s.Tags[tagKey]
		buckets := byTag[key]
		if buckets == nil {
			buckets = make([]span, n)
			byTag[key] = buckets
		}
		sp := &buckets[i]
		if !sp.has {
			sp.firstT, sp.lastT = s.T, s.T
			sp.firstV, sp.lastV = v, v
			sp.has = true
			continue
		}
		if s.T.Before(sp.firstT) {
			sp.firstT = s.T
			sp.firstV = v
		}
		if !s.T.Before(sp.lastT) {
			sp.lastT = s.T
			sp.lastV = v
		}
	}
	sum := make([]float64, n)
	has := make([]bool, n)
	for _, buckets := range byTag {
		for i, sp := range buckets {
			if !sp.has {
				continue
			}
			dt := sp.lastT.Sub(sp.firstT).Seconds()
			delta := float64(sp.lastV - sp.firstV)
			if dt <= 0 || delta < 0 {
				continue
			}
			sum[i] += delta / dt
			has[i] = true
		}
	}
	return Series{Name: name, Unit: unit, Points: points(from, step, n, func(i int) *float64 {
		if !has[i] {
			return nil
		}
		v := sum[i]
		return &v
	})}
}

func points(from time.Time, step time.Duration, n int, val func(int) *float64) []Point {
	out := make([]Point, n)
	for i := 0; i < n; i++ {
		out[i] = Point{T: from.Add(time.Duration(i) * step).UTC(), V: val(i)}
	}
	return out
}

func filterTags(samples []store.Sample, keep func(store.Sample) bool) []store.Sample {
	out := make([]store.Sample, 0, len(samples))
	for _, s := range samples {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}
