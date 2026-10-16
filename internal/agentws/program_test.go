package agentws

import (
	"encoding/json"
	"testing"
)

func TestParseProgramsFiles(t *testing.T) {
	absent, ok := parsePrograms(json.RawMessage(`{"enabled":true,"run_as":["joe"],"allow_shell":false,"policy_hash":"abc","images":true,"docker":true}`))
	if !ok || absent == nil || absent.Files {
		t.Fatalf("absent files %#v %v", absent, ok)
	}
	on, ok := parsePrograms(json.RawMessage(`{"enabled":true,"run_as":[],"allow_shell":false,"policy_hash":"abc","images":false,"docker":false,"files":true}`))
	if !ok || on == nil || !on.Files || on.RunAs == nil {
		t.Fatalf("files true %#v %v", on, ok)
	}
	if _, ok := parsePrograms(json.RawMessage(`{"enabled":true,"files":"yes"}`)); ok {
		t.Fatal("non-bool files accepted")
	}
}

func TestPolicyDeniedMapping(t *testing.T) {
	code, msg := rejectCode("policy_denied")
	if code != "forbidden" || msg != "forbidden" {
		t.Fatalf("reject %s %s", code, msg)
	}
	denied := failedTask("policy_denied", json.RawMessage(`{"lines":["secret"]}`))
	if denied.Code != "forbidden" || denied.Msg != "forbidden" || denied.Payload != nil {
		t.Fatalf("failed policy %#v", denied)
	}
	failed := failedTask("start_failed", json.RawMessage(`{"lines":["boom"]}`))
	if failed.Code != "error" || failed.Msg != "start_failed" || string(failed.Payload) != `{"lines":["boom"]}` {
		t.Fatalf("start_failed %#v", failed)
	}
	for _, tc := range []struct{ in, code, msg string }{
		{"forbidden", "forbidden", "forbidden"},
		{"unknown_service", "not_found", "not found"},
		{"bad_spec", "bad_request", "bad request"},
		{"busy", "unavailable", "host unavailable"},
		{"other", "error", "internal error"},
	} {
		got, text := rejectCode(tc.in)
		if got != tc.code || text != tc.msg {
			t.Fatalf("%s → %s %s", tc.in, got, text)
		}
	}
}
