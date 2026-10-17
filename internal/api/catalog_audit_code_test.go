package api

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// TestCatalogImageAuditErrorCode checks catalog.deploy, catalog.rollback, and
// catalog.remove rows written after the agent answers. error_code is the
// outcome unless that outcome is succeeded or unchanged.
func TestCatalogImageAuditErrorCode(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	digest := shaDigest(4)
	var mu sync.Mutex
	next := "succeeded"
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	watchTasks(t, conn, func(msg map[string]any) map[string]any {
		mu.Lock()
		outcome := next
		mu.Unlock()
		return imageAuditReply(msg, outcome, digest)
	})
	host := sc.host.ID.String()
	cases := []struct {
		action  string
		outcome string
	}{
		{"deploy", "succeeded"},
		{"deploy", "forbidden_spec"},
		{"deploy", "rolled_back"},
		{"deploy", "unchanged"},
		{"rollback", "forbidden_spec"},
		{"rollback", "rolled_back"},
		{"rollback", "succeeded"},
		{"rollback", "unchanged"},
		{"remove", "forbidden_spec"},
		{"remove", "rolled_back"},
		{"remove", "succeeded"},
		{"remove", "unchanged"},
	}
	for i, tc := range cases {
		mu.Lock()
		next = tc.outcome
		mu.Unlock()
		var extra map[string]any
		if tc.action == "rollback" {
			extra = map[string]any{"digest": digest}
		}
		before := auditActionCount(t, w, sc.project.ID, catalogAuditAction(tc.action))
		status, env, _ := postImage(t, w, tok, project, "web", tc.action, host, fmt.Sprintf("aud-%02d", i), extra)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		if tc.action != "remove" {
			got, _ := objectPayload(t, env)["deploy"].(map[string]any)
			if got["outcome"] != tc.outcome {
				t.Fatalf("%s %s body %#v", tc.action, tc.outcome, got)
			}
		}
		action := catalogAuditAction(tc.action)
		if auditActionCount(t, w, sc.project.ID, action) != before+1 {
			t.Fatalf("%s %s did not write one audit row", tc.action, tc.outcome)
		}
		checkImageAuditCode(t, latestAudit(t, w, sc.project.ID, action), tc.outcome)
	}
}

func imageAuditReply(msg map[string]any, outcome, digest string) map[string]any {
	kind, _ := msg["kind"].(string)
	if kind == "image_remove" {
		status := map[string]any{"container": "web", "state": "running", "restart_count": 0, "ports": []int{}}
		// Remove carries no payload outcome. A failed task's error_code is the outcome, including unchanged.
		if outcome == "succeeded" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"status": status},
			}
		}
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed",
			"error_code": outcome,
			"payload":    map[string]any{"status": status},
		}
	}
	reply := map[string]any{
		"v": 1, "type": "task_result", "task_id": msg["task_id"],
		"payload": map[string]any{
			"outcome": outcome, "digest": digest, "exit_code": 0,
			"status": map[string]any{
				"container": "web", "state": "running", "restart_count": 0,
				"exit_code": nil, "started_at": nil, "finished_at": nil,
				"digest": digest, "ports": []int{},
			},
			"lines": []string{"done"},
		},
	}
	if outcome == "succeeded" || outcome == "unchanged" {
		reply["state"] = "succeeded"
		return reply
	}
	reply["state"] = "failed"
	reply["error_code"] = outcome
	return reply
}

func catalogAuditAction(action string) string {
	return "catalog." + action
}

func auditActionCount(t *testing.T, w *world, projectID uuid.UUID, action string) int {
	t.Helper()
	n := 0
	for _, row := range auditRows(t, w, projectID) {
		if row.Action == action {
			n++
		}
	}
	return n
}

func latestAudit(t *testing.T, w *world, projectID uuid.UUID, action string) store.AuditEntry {
	t.Helper()
	for _, row := range auditRows(t, w, projectID) {
		if row.Action == action {
			return row
		}
	}
	t.Fatalf("missing audit %s", action)
	return store.AuditEntry{}
}

func checkImageAuditCode(t *testing.T, row store.AuditEntry, outcome string) {
	t.Helper()
	if row.Decision != "allowed" {
		t.Errorf("%s %s decision %s", row.Action, outcome, row.Decision)
	}
	if row.Result == nil || *row.Result != outcome {
		t.Errorf("%s %s result %s", row.Action, outcome, shownAudit(row.Result))
	}
	wantCode := outcome != "succeeded" && outcome != "unchanged"
	switch {
	case !wantCode && row.ErrorCode != nil:
		t.Errorf("%s %s error_code %q, want null", row.Action, outcome, *row.ErrorCode)
	case wantCode && (row.ErrorCode == nil || *row.ErrorCode != outcome):
		t.Errorf("%s %s error_code %s, want %s", row.Action, outcome, shownAudit(row.ErrorCode), outcome)
	}
}

func shownAudit(v *string) string {
	if v == nil {
		return "<nil>"
	}
	return *v
}
