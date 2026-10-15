package agentws

import (
	"encoding/json"
	"testing"
)

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
