package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const chartBucketLimit = 500

type gaugeSpec struct {
	name, unit, expr, table, filter string
}

type rateSpec struct {
	name, unit, table, series, value, filter string
}

// QueryChart aggregates in SQL. It never scans raw metric rows into Go.
// Counter rates are per series: value at the latest time in the bucket minus
// the value at the earliest time, divided by that series' own dt. Negative
// deltas are dropped, then the rates are summed. max(v)-min(v) is not used,
// because that quantity cannot be negative.
func (d *DB) QueryChart(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time, stepSec int) ([]store.ChartSeries, error) {
	if stepSec < 1 {
		return nil, fmt.Errorf("bad step")
	}
	switch measurement {
	case "cpu":
		return d.gaugeCharts(ctx, hostID, from, to, stepSec, []gaugeSpec{{
			name: "usage_percent", unit: "%", expr: "avg(100 - usage_idle)",
			table: "metrics.host_cpu", filter: "cpu = 'cpu-total' AND usage_idle IS NOT NULL",
		}})
	case "mem":
		return d.gaugeCharts(ctx, hostID, from, to, stepSec, []gaugeSpec{
			{name: "used_percent", unit: "%", expr: "avg(used_percent)", table: "metrics.host_mem", filter: "used_percent IS NOT NULL"},
			{name: "used", unit: "bytes", expr: "avg(used)", table: "metrics.host_mem", filter: "used IS NOT NULL"},
			{name: "total", unit: "bytes", expr: "avg(total)", table: "metrics.host_mem", filter: "total IS NOT NULL"},
		})
	case "disk":
		return d.gaugeCharts(ctx, hostID, from, to, stepSec, []gaugeSpec{{
			name: "used_percent", unit: "%", expr: "avg(used_percent)",
			table: "metrics.host_disk", filter: "path = '/' AND used_percent IS NOT NULL",
		}})
	case "diskio":
		return d.rateCharts(ctx, hostID, from, to, stepSec, []rateSpec{
			{name: "read_bps", unit: "bytes/s", table: "metrics.host_diskio", series: "name", value: "read_bytes", filter: "read_bytes IS NOT NULL"},
			{name: "write_bps", unit: "bytes/s", table: "metrics.host_diskio", series: "name", value: "write_bytes", filter: "write_bytes IS NOT NULL"},
		})
	case "net":
		return d.rateCharts(ctx, hostID, from, to, stepSec, []rateSpec{
			{name: "rx_bps", unit: "bytes/s", table: "metrics.host_net", series: "interface", value: "bytes_recv", filter: "interface <> 'lo' AND bytes_recv IS NOT NULL"},
			{name: "tx_bps", unit: "bytes/s", table: "metrics.host_net", series: "interface", value: "bytes_sent", filter: "interface <> 'lo' AND bytes_sent IS NOT NULL"},
		})
	case "system":
		return d.gaugeCharts(ctx, hostID, from, to, stepSec, []gaugeSpec{
			{name: "load1", unit: "", expr: "avg(load1)", table: "metrics.host_system", filter: "load1 IS NOT NULL"},
			{name: "load5", unit: "", expr: "avg(load5)", table: "metrics.host_system", filter: "load5 IS NOT NULL"},
			{name: "load15", unit: "", expr: "avg(load15)", table: "metrics.host_system", filter: "load15 IS NOT NULL"},
			{name: "uptime", unit: "s", expr: "avg(uptime)", table: "metrics.host_system", filter: "uptime IS NOT NULL"},
		})
	case "temp":
		return d.gaugeCharts(ctx, hostID, from, to, stepSec, []gaugeSpec{{
			name: "celsius", unit: "°C", expr: "avg(celsius)", table: "metrics.host_temp", filter: "celsius IS NOT NULL",
		}})
	default:
		return nil, store.ErrUnknownMeasurement
	}
}

func (d *DB) gaugeCharts(ctx context.Context, hostID uuid.UUID, from, to time.Time, stepSec int, specs []gaugeSpec) ([]store.ChartSeries, error) {
	out := make([]store.ChartSeries, 0, len(specs))
	for _, spec := range specs {
		points, err := d.queryBuckets(ctx, gaugeSQL(spec), hostID, from, to, stepSec)
		if err != nil {
			return nil, err
		}
		out = append(out, store.ChartSeries{Name: spec.name, Unit: spec.unit, Points: points})
	}
	return out, nil
}

func (d *DB) rateCharts(ctx context.Context, hostID uuid.UUID, from, to time.Time, stepSec int, specs []rateSpec) ([]store.ChartSeries, error) {
	out := make([]store.ChartSeries, 0, len(specs))
	for _, spec := range specs {
		points, err := d.queryBuckets(ctx, rateSQL(spec), hostID, from, to, stepSec)
		if err != nil {
			return nil, err
		}
		out = append(out, store.ChartSeries{Name: spec.name, Unit: spec.unit, Points: points})
	}
	return out, nil
}

func (d *DB) queryBuckets(ctx context.Context, sql string, hostID uuid.UUID, from, to time.Time, stepSec int) ([]store.ChartPoint, error) {
	rows, err := d.pool.Query(ctx, sql, hostID.String(), from, stepSec, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	points := []store.ChartPoint{}
	for rows.Next() {
		var p store.ChartPoint
		if err := rows.Scan(&p.T, &p.V); err != nil {
			return nil, mapErr(err)
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return points, nil
}

func gaugeSQL(spec gaugeSpec) string {
	return fmt.Sprintf(`
WITH grid AS (
    SELECT gs AS bucket
    FROM generate_series(
        time_bucket(make_interval(secs => $3), $2::timestamptz),
        $4::timestamptz - interval '1 microsecond',
        make_interval(secs => $3)
    ) AS gs
    LIMIT %d
),
agg AS (
    SELECT time_bucket(make_interval(secs => $3), time) AS bucket, %s AS v
    FROM %s
    WHERE host_id = $1::uuid AND time >= $2 AND time < $4 AND %s
    GROUP BY 1
)
SELECT grid.bucket, agg.v
FROM grid
LEFT JOIN agg ON agg.bucket = grid.bucket
ORDER BY grid.bucket
LIMIT %d
`, chartBucketLimit, spec.expr, spec.table, spec.filter, chartBucketLimit)
}

func rateSQL(spec rateSpec) string {
	return fmt.Sprintf(`
WITH grid AS (
    SELECT gs AS bucket
    FROM generate_series(
        time_bucket(make_interval(secs => $3), $2::timestamptz),
        $4::timestamptz - interval '1 microsecond',
        make_interval(secs => $3)
    ) AS gs
    LIMIT %d
),
bounds AS (
    SELECT time_bucket(make_interval(secs => $3), time) AS bucket,
           %s AS series,
           (array_agg(%s ORDER BY time DESC))[1] AS last_v,
           (array_agg(%s ORDER BY time ASC))[1] AS first_v,
           EXTRACT(EPOCH FROM (max(time) - min(time))) AS dt
    FROM %s
    WHERE host_id = $1::uuid AND time >= $2 AND time < $4 AND %s
    GROUP BY 1, 2
),
rates AS (
    SELECT bucket, ((last_v - first_v)::float8 / dt) AS rate
    FROM bounds
    WHERE dt > 0 AND last_v >= first_v
),
agg AS (
    SELECT bucket, sum(rate) AS v
    FROM rates
    GROUP BY bucket
)
SELECT grid.bucket, agg.v
FROM grid
LEFT JOIN agg ON agg.bucket = grid.bucket
ORDER BY grid.bucket
LIMIT %d
`, chartBucketLimit, spec.series, spec.value, spec.value, spec.table, spec.filter, chartBucketLimit)
}

// DeleteOldBatches removes ingest idempotency rows older than the cutoff.
func (d *DB) DeleteOldBatches(ctx context.Context, before time.Time) error {
	if err := exec(ctx, d.pool, `
DELETE FROM metrics.ingest_batches WHERE received_at < $1
`, before); err != nil {
		return mapErr(err)
	}
	return nil
}
