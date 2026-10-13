// Package ingest checks agent samples against the phase-1 allowlists and
// remembers batch ids for 24 hours.
package ingest

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const MaxSamples = 5000

var (
	diskName  = regexp.MustCompile(`^(mmcblk\d+|nvme\d+n\d+|sd[a-z]+|vd[a-z]+)$`)
	virtualFS = map[string]bool{
		"tmpfs": true, "overlay": true, "squashfs": true,
		"proc": true, "sysfs": true, "devtmpfs": true,
	}
	healthResults = map[string]bool{
		"success": true, "status_mismatch": true, "timeout": true,
		"connection_refused": true, "error": true,
	}
)

type kind int

const (
	kindFloat kind = iota
	kindInt
	kindString
)

type field struct {
	name string
	kind kind
}

type measurement struct {
	tags     []string
	optional map[string]bool
	fields   []field
}

var measurements = map[string]measurement{
	"cpu": {
		tags:   []string{"cpu"},
		fields: []field{{"usage_user", kindFloat}, {"usage_system", kindFloat}, {"usage_idle", kindFloat}, {"usage_iowait", kindFloat}},
	},
	"mem": {
		fields: []field{{"total", kindInt}, {"available", kindInt}, {"used", kindInt}, {"used_percent", kindFloat}},
	},
	"disk": {
		tags:   []string{"path", "fstype"},
		fields: []field{{"total", kindInt}, {"used", kindInt}, {"free", kindInt}, {"used_percent", kindFloat}},
	},
	"diskio": {
		tags:   []string{"name"},
		fields: []field{{"read_bytes", kindInt}, {"write_bytes", kindInt}},
	},
	"net": {
		tags:   []string{"interface"},
		fields: []field{{"bytes_recv", kindInt}, {"bytes_sent", kindInt}},
	},
	"system": {
		fields: []field{{"load1", kindFloat}, {"load5", kindFloat}, {"load15", kindFloat}, {"uptime", kindInt}, {"n_cpus", kindInt}},
	},
	"temp": {
		tags:   []string{"sensor"},
		fields: []field{{"celsius", kindFloat}},
	},
	"process": {
		tags:     []string{"pid", "process_name", "user", "cmdline", "service"},
		optional: map[string]bool{"service": true},
		fields: []field{
			{"cpu_usage", kindFloat}, {"memory_rss", kindInt}, {"memory_usage", kindFloat},
			{"num_threads", kindInt}, {"started_at", kindString},
		},
	},
	"health": {
		tags: []string{"service", "check_id", "protocol", "port"},
		fields: []field{
			{"result", kindString}, {"http_status", kindInt}, {"latency_ms", kindFloat},
		},
	},
}

// Reject is a batch the server must not ack.
type Reject struct {
	Reason string
}

func (r *Reject) Error() string { return r.Reason }

type rawSample struct {
	M      string                     `json:"m"`
	T      string                     `json:"t"`
	Tags   map[string]json.RawMessage `json:"tags"`
	F      map[string]json.RawMessage `json:"f"`
	HostID json.RawMessage            `json:"host_id"` // accepted and ignored; the host comes from the socket
}

// ValidateBatch checks every sample. One bad sample rejects the batch.
// Host identity is not read from the samples.
func ValidateBatch(batchID string, raw json.RawMessage) (uuid.UUID, []store.Sample, error) {
	id, err := uuid.Parse(batchID)
	if err != nil {
		return uuid.Nil, nil, &Reject{Reason: "bad_batch_id"}
	}
	if len(raw) == 0 || string(raw) == "null" {
		return uuid.Nil, nil, &Reject{Reason: "bad_samples"}
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return uuid.Nil, nil, &Reject{Reason: "bad_samples"}
	}
	if len(items) > MaxSamples {
		return uuid.Nil, nil, &Reject{Reason: "too_many_samples"}
	}
	out := make([]store.Sample, 0, len(items))
	for _, item := range items {
		sample, err := validateOne(item)
		if err != nil {
			return uuid.Nil, nil, err
		}
		out = append(out, sample)
	}
	return id, out, nil
}

func validateOne(raw json.RawMessage) (store.Sample, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in rawSample
	if err := dec.Decode(&in); err != nil {
		return store.Sample{}, &Reject{Reason: "bad_sample"}
	}
	spec, ok := measurements[in.M]
	if !ok {
		return store.Sample{}, &Reject{Reason: "unknown_measurement"}
	}
	t, err := time.Parse(time.RFC3339Nano, in.T)
	if err != nil {
		return store.Sample{}, &Reject{Reason: "bad_time"}
	}
	if in.Tags == nil {
		in.Tags = map[string]json.RawMessage{}
	}
	if in.F == nil {
		return store.Sample{}, &Reject{Reason: "missing_fields"}
	}
	allowedTags := map[string]bool{}
	for _, name := range spec.tags {
		allowedTags[name] = true
	}
	tags := map[string]string{}
	for name, rawTag := range in.Tags {
		if !allowedTags[name] {
			return store.Sample{}, &Reject{Reason: "unknown_tag"}
		}
		val, err := tagString(name, rawTag)
		if err != nil {
			return store.Sample{}, err
		}
		tags[name] = val
	}
	for _, name := range spec.tags {
		if spec.optional[name] {
			continue
		}
		if _, ok := tags[name]; !ok {
			return store.Sample{}, &Reject{Reason: "missing_tag"}
		}
	}
	allowedFields := map[string]kind{}
	for _, f := range spec.fields {
		allowedFields[f.name] = f.kind
	}
	sample := store.Sample{
		M:      in.M,
		T:      t.UTC(),
		Tags:   tags,
		Floats: map[string]float64{},
		Ints:   map[string]int64{},
		Strs:   map[string]string{},
		Nulls:  map[string]bool{},
	}
	for name, rawField := range in.F {
		kind, ok := allowedFields[name]
		if !ok {
			return store.Sample{}, &Reject{Reason: "unknown_field"}
		}
		if string(rawField) == "null" {
			if in.M == "health" && name == "http_status" {
				sample.Nulls[name] = true
				continue
			}
			return store.Sample{}, &Reject{Reason: "bad_type"}
		}
		switch kind {
		case kindFloat:
			v, err := parseFloat(rawField)
			if err != nil {
				return store.Sample{}, err
			}
			sample.Floats[name] = v
		case kindInt:
			v, err := parseInt(rawField)
			if err != nil {
				return store.Sample{}, err
			}
			sample.Ints[name] = v
		case kindString:
			var s string
			if err := json.Unmarshal(rawField, &s); err != nil {
				return store.Sample{}, &Reject{Reason: "bad_type"}
			}
			sample.Strs[name] = s
		}
	}
	if err := extra(sample); err != nil {
		return store.Sample{}, err
	}
	return sample, nil
}

func extra(s store.Sample) error {
	switch s.M {
	case "cpu":
		if s.Tags["cpu"] != "cpu-total" {
			return &Reject{Reason: "bad_cpu"}
		}
	case "disk":
		if virtualFS[s.Tags["fstype"]] {
			return &Reject{Reason: "virtual_fs"}
		}
		if s.Tags["path"] == "" || len(s.Tags["path"]) > 512 {
			return &Reject{Reason: "bad_path"}
		}
	case "diskio":
		if !diskName.MatchString(s.Tags["name"]) {
			return &Reject{Reason: "bad_disk"}
		}
	case "net":
		if s.Tags["interface"] == "" || s.Tags["interface"] == "lo" {
			return &Reject{Reason: "bad_interface"}
		}
		if len(s.Tags["interface"]) > 64 {
			return &Reject{Reason: "bad_interface"}
		}
	case "temp":
		if s.Tags["sensor"] == "" || len(s.Tags["sensor"]) > 128 {
			return &Reject{Reason: "bad_sensor"}
		}
	case "process":
		pid, err := strconv.Atoi(s.Tags["pid"])
		if err != nil || pid < 1 || pid > math.MaxInt32 {
			return &Reject{Reason: "bad_pid"}
		}
		if s.Tags["process_name"] == "" || len(s.Tags["process_name"]) > 128 {
			return &Reject{Reason: "bad_process_name"}
		}
		if len(s.Tags["user"]) > 256 {
			return &Reject{Reason: "bad_user"}
		}
		if utf8.RuneCountInString(s.Tags["cmdline"]) > 1024 {
			return &Reject{Reason: "cmdline_too_long"}
		}
		s.Tags["cmdline"] = RedactCmdline(s.Tags["cmdline"])
		if name := s.Tags["service"]; name != "" && len(name) > 63 {
			return &Reject{Reason: "bad_service"}
		}
		if started, ok := s.Strs["started_at"]; ok && started != "" {
			if _, err := time.Parse(time.RFC3339Nano, started); err != nil {
				return &Reject{Reason: "bad_started_at"}
			}
		}
	case "health":
		if _, err := uuid.Parse(s.Tags["check_id"]); err != nil {
			return &Reject{Reason: "bad_check_id"}
		}
		if s.Tags["protocol"] != "http" && s.Tags["protocol"] != "tcp" {
			return &Reject{Reason: "bad_protocol"}
		}
		port, err := strconv.Atoi(s.Tags["port"])
		if err != nil || port < 1 || port > 65535 {
			return &Reject{Reason: "bad_port"}
		}
		if s.Tags["service"] == "" {
			return &Reject{Reason: "bad_service"}
		}
		if result, ok := s.Strs["result"]; !ok || !healthResults[result] {
			return &Reject{Reason: "bad_result"}
		}
	}
	return nil
}

func tagString(_ string, raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", &Reject{Reason: "bad_tag_type"}
	}
	return s, nil
}

func parseNumber(raw json.RawMessage) (json.Number, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return "", err
	}
	return n, nil
}

func parseFloat(raw json.RawMessage) (float64, error) {
	n, err := parseNumber(raw)
	if err != nil {
		return 0, &Reject{Reason: "bad_type"}
	}
	v, err := n.Float64()
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, &Reject{Reason: "bad_type"}
	}
	return v, nil
}

func parseInt(raw json.RawMessage) (int64, error) {
	n, err := parseNumber(raw)
	if err != nil {
		return 0, &Reject{Reason: "bad_type"}
	}
	v, err := n.Int64()
	if err != nil {
		return 0, &Reject{Reason: "bad_type"}
	}
	return v, nil
}
