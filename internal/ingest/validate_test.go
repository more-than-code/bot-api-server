package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateAllowlist(t *testing.T) {
	id := uuid.New().String()
	ok := `[{"m":"cpu","t":"2026-10-13T00:00:00Z","tags":{"cpu":"cpu-total"},"f":{"usage_idle":90.5}}]`
	if _, samples, err := ValidateBatch(id, json.RawMessage(ok)); err != nil || len(samples) != 1 {
		t.Fatalf("valid cpu: %v %#v", err, samples)
	}
	cases := []struct {
		name string
		body string
		want string
	}{
		{"unknown m", `[{"m":"nope","t":"2026-10-13T00:00:00Z","f":{"usage_idle":1}}]`, "unknown_measurement"},
		{"unknown field", `[{"m":"cpu","t":"2026-10-13T00:00:00Z","tags":{"cpu":"cpu-total"},"f":{"temp":1}}]`, "unknown_field"},
		{"bad type", `[{"m":"cpu","t":"2026-10-13T00:00:00Z","tags":{"cpu":"cpu-total"},"f":{"usage_idle":"high"}}]`, "bad_type"},
		{"loopback", `[{"m":"net","t":"2026-10-13T00:00:00Z","tags":{"interface":"lo"},"f":{"bytes_recv":1}}]`, "bad_interface"},
		{"tmpfs", `[{"m":"disk","t":"2026-10-13T00:00:00Z","tags":{"path":"/run","fstype":"tmpfs"},"f":{"used_percent":1}}]`, "virtual_fs"},
		{"partition", `[{"m":"diskio","t":"2026-10-13T00:00:00Z","tags":{"name":"sda1"},"f":{"read_bytes":1}}]`, "bad_disk"},
		{"whole disk", `[{"m":"diskio","t":"2026-10-13T00:00:00Z","tags":{"name":"sda"},"f":{"read_bytes":1}}]`, ""},
		{"unknown tag", `[{"m":"cpu","t":"2026-10-13T00:00:00Z","tags":{"cpu":"cpu-total","core":"0"},"f":{"usage_idle":1}}]`, "unknown_tag"},
		{"cpu core", `[{"m":"cpu","t":"2026-10-13T00:00:00Z","tags":{"cpu":"cpu0"},"f":{"usage_idle":1}}]`, "bad_cpu"},
		{"numeric port", `[{"m":"health","t":"2026-10-13T00:00:00Z","tags":{"service":"api","check_id":"11111111-1111-1111-1111-111111111111","protocol":"http","port":8080},"f":{"result":"success"}}]`, "bad_tag_type"},
		{"numeric pid", `[{"m":"process","t":"2026-10-13T00:00:00Z","tags":{"pid":1,"process_name":"x","user":"u","cmdline":"x"},"f":{}}]`, "bad_tag_type"},
	}
	for _, tc := range cases {
		_, _, err := ValidateBatch(id, json.RawMessage(tc.body))
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		var rej *Reject
		if !errors.As(err, &rej) || rej.Reason != tc.want {
			t.Fatalf("%s: got %v, want %s", tc.name, err, tc.want)
		}
	}
}

func TestHostIDInSampleIsIgnored(t *testing.T) {
	body := `[{"m":"cpu","t":"2026-10-13T00:00:00Z","host_id":"11111111-1111-1111-1111-111111111111","tags":{"cpu":"cpu-total"},"f":{"usage_idle":1}}]`
	if _, samples, err := ValidateBatch(uuid.New().String(), json.RawMessage(body)); err != nil || len(samples) != 1 {
		t.Fatalf("host_id in a sample must be acked: %v", err)
	}
}

func TestCmdlineRedactedOnIngest(t *testing.T) {
	body := `[{"m":"process","t":"2026-10-13T00:00:00Z","tags":{"pid":"7","process_name":"app","user":"bot","cmdline":"app --token=sekret --ok"},"f":{"cpu_usage":1}}]`
	_, samples, err := ValidateBatch(uuid.New().String(), json.RawMessage(body))
	if err != nil || len(samples) != 1 {
		t.Fatal(err)
	}
	got := samples[0].Tags["cmdline"]
	if strings.Contains(got, "sekret") || got != "app --token=[REDACTED] --ok" {
		t.Fatalf("cmdline %q", got)
	}
}

func TestValidateBatchLimit(t *testing.T) {
	one := `{"m":"mem","t":"2026-10-13T00:00:00Z","f":{"used":1}}`
	body := "[" + strings.TrimRight(strings.Repeat(one+",", MaxSamples+1), ",") + "]"
	_, _, err := ValidateBatch(uuid.New().String(), json.RawMessage(body))
	var rej *Reject
	if !errors.As(err, &rej) || rej.Reason != "too_many_samples" {
		t.Fatalf("got %v", err)
	}
}
