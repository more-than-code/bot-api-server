package ingest

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/google/uuid"
)

func TestRedactionPatternsAreRE2(t *testing.T) {
	for _, p := range []string{urlUserinfoPattern, keywordPattern} {
		if _, err := regexp.Compile(p); err != nil {
			t.Fatalf("RE2 compile %q: %v", p, err)
		}
	}
}

func TestRedactionVectorsV102(t *testing.T) {
	vectors := []struct {
		name string
		in   string
		out  string
	}{
		{"authorization bearer", "Authorization: Bearer abc123", "Authorization=[REDACTED]"},
		{"aws secret key", "AWS_SECRET_ACCESS_KEY=AKIAxyz", "AWS_SECRET_ACCESS_KEY=[REDACTED]"},
		{"quoted password", `password="two words" next`, "password=[REDACTED] next"},
		{"postgres userinfo", "postgres://app:s3cret@127.0.0.1/db", "postgres://app:[REDACTED]@127.0.0.1/db"},
		{"redis without userinfo", "redis://localhost:6379", "redis://localhost:6379"},
		{"plain argv", "/usr/bin/node build", "/usr/bin/node build"},
		{"ps line", "postgres: joe tour_agent 127.0.0.1(5000) idle", "postgres: joe tour_agent 127.0.0.1(5000) idle"},
		{"redis empty user", "redis://:s3cret@127.0.0.1:6379", "redis://:[REDACTED]@127.0.0.1:6379"},
		{"password contains at", "https://user:p@ss@host/db", "https://user:[REDACTED]@host/db"},
		{"ssh user only", "ssh://git@host:22/repo", "ssh://git@host:22/repo"},
		{"http host port", "http://127.0.0.1:3031/health", "http://127.0.0.1:3031/health"},
		{"two urls", "a://u:p@h/x b://c:d@e/y", "a://u:[REDACTED]@h/x b://c:[REDACTED]@e/y"},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactCmdline(tc.in); got != tc.out {
				t.Fatalf("RedactCmdline %q", got)
			}

			encoded, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			body := `[{"m":"process","t":"2026-10-13T00:00:00Z","tags":{"pid":"7","process_name":"app","user":"bot","cmdline":` + string(encoded) + `},"f":{"cpu_usage":1}}]`
			_, samples, err := ValidateBatch(uuid.New().String(), json.RawMessage(body), false)
			if err != nil || len(samples) != 1 {
				t.Fatalf("ingest: %v", err)
			}
			if samples[0].Tags["cmdline"] != tc.out {
				t.Fatalf("ingest cmdline %q", samples[0].Tags["cmdline"])
			}

			snap := `{"sampled_at":"2026-10-13T00:00:00Z","top":[{"pid":1,"process_name":"app","user":"joe","cmdline":` + string(encoded) + `}]}`
			gotPayload := RedactPayload(json.RawMessage(snap))
			var parsed struct {
				Top []struct {
					Cmdline string `json:"cmdline"`
					User    string `json:"user"`
				} `json:"top"`
			}
			if err := json.Unmarshal(gotPayload, &parsed); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Top) != 1 || parsed.Top[0].Cmdline != tc.out || parsed.Top[0].User != "joe" {
				t.Fatalf("snapshot %s", gotPayload)
			}
		})
	}
}
