package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDockerHealthSample(t *testing.T) {
	const at = "2026-10-13T00:00:00Z"
	ok := `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker"},"f":{"result":"success","http_status":null,"latency_ms":null}}]`
	_, samples, err := ValidateBatch(uuid.New().String(), json.RawMessage(ok), true)
	if err != nil || len(samples) != 1 {
		t.Fatalf("accepted: %v %#v", err, samples)
	}
	s := samples[0]
	if s.Tags["protocol"] != "docker" || s.Tags["service"] != "api" || s.Strs["result"] != "success" {
		t.Fatalf("sample %#v", s)
	}
	if _, ok := s.Tags["check_id"]; ok {
		t.Fatal("docker sample stored check_id")
	}
	if _, ok := s.Tags["port"]; ok {
		t.Fatal("docker sample stored port")
	}
	if !s.Nulls["http_status"] || !s.Nulls["latency_ms"] {
		t.Fatalf("nulls %#v", s.Nulls)
	}
	if _, ok := s.Floats["latency_ms"]; ok {
		t.Fatal("null latency stored as a number")
	}

	_, _, err = ValidateBatch(uuid.New().String(), json.RawMessage(ok), false)
	var rej *Reject
	if !errors.As(err, &rej) || rej.Reason != "docker_health" {
		t.Fatalf("ungated: %v", err)
	}

	unhealthy := strings.Replace(ok, `"success"`, `"unhealthy"`, 1)
	if _, _, err := ValidateBatch(uuid.New().String(), json.RawMessage(unhealthy), true); err != nil {
		t.Fatalf("unhealthy: %v", err)
	}

	cases := []struct {
		name string
		body string
		gate bool
		want string
	}{
		{"check id", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker","check_id":"11111111-1111-1111-1111-111111111111"},"f":{"result":"success","http_status":null,"latency_ms":null}}]`, true, "bad_check_id"},
		{"port", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker","port":"80"},"f":{"result":"success","http_status":null,"latency_ms":null}}]`, true, "bad_port"},
		{"latency number", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker"},"f":{"result":"success","http_status":null,"latency_ms":1}}]`, true, "bad_type"},
		{"status missing", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker"},"f":{"result":"success","latency_ms":null}}]`, true, "bad_type"},
		{"bad result", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker"},"f":{"result":"timeout","http_status":null,"latency_ms":null}}]`, true, "bad_result"},
		{"ungated form", `[{"m":"health","t":"` + at + `","tags":{"service":"api","protocol":"docker"},"f":{"result":"starting","http_status":null,"latency_ms":null}}]`, false, "bad_result"},
		{"http unhealthy", `[{"m":"health","t":"` + at + `","tags":{"service":"api","check_id":"11111111-1111-1111-1111-111111111111","protocol":"http","port":"80"},"f":{"result":"unhealthy","latency_ms":1}}]`, true, "bad_result"},
		{"http null latency", `[{"m":"health","t":"` + at + `","tags":{"service":"api","check_id":"11111111-1111-1111-1111-111111111111","protocol":"http","port":"80"},"f":{"result":"success","latency_ms":null}}]`, true, "bad_type"},
		{"http ok", `[{"m":"health","t":"` + at + `","tags":{"service":"api","check_id":"11111111-1111-1111-1111-111111111111","protocol":"http","port":"80"},"f":{"result":"success","http_status":200,"latency_ms":1.5}}]`, false, ""},
	}
	for _, tc := range cases {
		_, samples, err := ValidateBatch(uuid.New().String(), json.RawMessage(tc.body), tc.gate)
		if tc.want == "" {
			if err != nil || len(samples) != 1 || samples[0].Floats["latency_ms"] != 1.5 {
				t.Fatalf("%s: %v %#v", tc.name, err, samples)
			}
			continue
		}
		rej = nil
		if !errors.As(err, &rej) || rej.Reason != tc.want {
			t.Fatalf("%s: got %v, want %s", tc.name, err, tc.want)
		}
	}
}
