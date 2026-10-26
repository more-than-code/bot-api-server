package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// putEnvMode sends the v1.19 dotenv PUT with an optional mode and new_keys_secret.
func putEnvMode(t *testing.T, w *world, tok, project, set, dotenv string, mode *string, newKeysSecret *bool) (int, envelope, string) {
	t.Helper()
	body := map[string]any{"dotenv": dotenv}
	if mode != nil {
		body["mode"] = *mode
	}
	if newKeysSecret != nil {
		body["new_keys_secret"] = *newKeysSecret
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return mustCall(t, w, tok, http.MethodPut, envPath(project, set), string(raw))
}

func TestEnvSetPutModes(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	const kept = "kept-secret-value-1"
	const fresh = "fresh-secret-value-2"

	// Default (no mode) and "replace" still replace the set.
	status, env, _ := putEnvMode(t, w, tok, project, "svc", "OLD="+kept+"\nVIS=v1\n", nil, nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = putEnvMode(t, w, tok, project, "svc", "ONLY=x\n", strPtr("replace"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if got := keysByName(t, env); len(got) != 1 || got["ONLY"] == nil {
		t.Fatalf("replace kept other keys %#v", got)
	}

	// create on a new name creates.
	status, env, _ = putEnvMode(t, w, tok, project, "app", "TOKEN="+kept+"\n", strPtr("create"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["TOKEN"], catalog.SecretPreview(kept))
	status, env, _ = putKey(t, w, tok, project, "app", "VISIBLE", "plain-1", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")

	// create on an existing name is a conflict and changes nothing.
	auditsBefore := len(w.mem.AllAudits())
	status, env, raw := putEnvMode(t, w, tok, project, "app", "TOKEN=should-not-echo-c\n", strPtr("create"), nil)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "env set app already exists")
	if strings.Contains(raw, "should-not-echo-c") {
		t.Fatalf("conflict echoed a value %s", raw)
	}
	if len(w.mem.AllAudits()) != auditsBefore {
		t.Fatal("refused create wrote an audit row")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "app"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := keysByName(t, env)
	if len(got) != 2 {
		t.Fatalf("create conflict changed keys %#v", got)
	}
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(kept))
	assertPlainKey(t, got["VISIBLE"], "plain-1")

	// merge keeps other keys and flags; new keys follow new_keys_secret.
	status, env, raw = putEnvMode(t, w, tok, project, "app", "VISIBLE=plain-2\nNEWPLAIN=np\n", strPtr("merge"), boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got = keysByName(t, env)
	if len(got) != 3 {
		t.Fatalf("merge keys %#v", got)
	}
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(kept))
	assertPlainKey(t, got["VISIBLE"], "plain-2")
	assertPlainKey(t, got["NEWPLAIN"], "np")
	if strings.Contains(raw, kept) {
		t.Fatal("merge returned a secret")
	}
	status, env, raw = putEnvMode(t, w, tok, project, "app", "TOKEN="+fresh+"\nNEWSECRET="+fresh+"\nNEWPLAIN=np2\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got = keysByName(t, env)
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(fresh))
	assertSecretKey(t, got["NEWSECRET"], catalog.SecretPreview(fresh))
	assertPlainKey(t, got["NEWPLAIN"], "np2")
	assertPlainKey(t, got["VISIBLE"], "plain-2")
	if strings.Contains(raw, fresh) {
		t.Fatal("merge returned a secret")
	}

	// merge with new_keys_secret=false keeps an existing secret key secret.
	status, env, raw = putEnvMode(t, w, tok, project, "app", "TOKEN="+fresh+"\n", strPtr("merge"), boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["TOKEN"], catalog.SecretPreview(fresh))
	if strings.Contains(raw, fresh) {
		t.Fatal("merge returned a secret")
	}

	// create with new_keys_secret=false stores plain keys.
	status, env, _ = putEnvMode(t, w, tok, project, "plainset", "P=pv\n", strPtr("create"), boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPlainKey(t, keysByName(t, env)["P"], "pv")

	// merge on a missing set is not_found and creates nothing.
	status, env, _ = putEnvMode(t, w, tok, project, "nope", "A=1\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "no env set nope")
	if _, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "nope"); err != store.ErrNotFound {
		t.Fatal("merge on a missing set created it")
	}

	// merge with an empty value for an existing secret key writes nothing.
	auditsBefore = len(w.mem.AllAudits())
	status, env, raw = putEnvMode(t, w, tok, project, "app", "VISIBLE=plain-3\nTOKEN=\nADDED=should-not-echo-e\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "a secret value cannot be empty; delete the key instead")
	if strings.Contains(raw, "should-not-echo-e") {
		t.Fatalf("refusal echoed a value %s", raw)
	}
	if len(w.mem.AllAudits()) != auditsBefore {
		t.Fatal("refused merge wrote an audit row")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "app"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got = keysByName(t, env)
	if len(got) != 4 || got["ADDED"] != nil {
		t.Fatalf("refused merge wrote keys %#v", got)
	}
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(fresh))
	assertPlainKey(t, got["VISIBLE"], "plain-2")

	// An empty value for an existing plain key, or a new key, is fine.
	status, env, _ = putEnvMode(t, w, tok, project, "app", "VISIBLE=\nBLANK=\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got = keysByName(t, env)
	assertPlainKey(t, got["VISIBLE"], "")
	assertSecretKey(t, got["BLANK"], "••••")

	// Unknown mode.
	for _, body := range []string{`{"dotenv":"A=1\n","mode":"append"}`, `{"dotenv":"A=1\n","mode":""}`, `{"dotenv":"A=1\n","mode":5}`} {
		status, env, _ = mustCall(t, w, tok, http.MethodPut, envPath(project, "app"), body)
		if status != http.StatusBadRequest || env.Code != "bad_request" {
			t.Fatalf("mode body %s: %d %#v", body, status, env)
		}
	}
	if _, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "app"); err != nil {
		t.Fatal(err)
	}

	// Audit: merge rows hold names only.
	var merges []map[string]any
	for _, row := range auditRows(t, w, sc.project.ID) {
		for _, secret := range []string{kept, fresh, "should-not-echo", "plain-1", "plain-2", "np2"} {
			if strings.Contains(string(row.Detail), secret) {
				t.Fatalf("audit held a value %s", row.Detail)
			}
		}
		if row.Action == audit.ActionEnvSetMerge {
			if row.Via != audit.ViaConsole || row.Decision != audit.DecisionAllowed {
				t.Fatalf("merge row %#v", row)
			}
			merges = append(merges, detailMap(t, row.Detail))
		}
	}
	// ListAudit is newest first.
	if len(merges) != 4 {
		t.Fatalf("merge audits %#v", merges)
	}
	wantMerge := []struct{ keys, created string }{
		{`["BLANK","VISIBLE"]`, `["BLANK"]`},
		{`["TOKEN"]`, `[]`},
		{`["NEWPLAIN","NEWSECRET","TOKEN"]`, `["NEWSECRET"]`},
		{`["NEWPLAIN","VISIBLE"]`, `["NEWPLAIN"]`},
	}
	for i, want := range wantMerge {
		keys, _ := json.Marshal(merges[i]["keys"])
		created, _ := json.Marshal(merges[i]["created"])
		if merges[i]["set"] != "app" || len(merges[i]) != 3 || string(keys) != want.keys || string(created) != want.created {
			t.Fatalf("merge audit %d %#v", i, merges[i])
		}
	}
}

func TestEnvSetMergeApprovals(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	guestUser := w.user("guest@ex.com", "Guest")
	guest, err := w.mem.CreateProject(context.Background(), guestUser.ID, "Guest", "guest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(context.Background(), sc.host.ID, guest.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	tok := w.token(guestUser.ID)
	project := guest.ID.String()
	host := sc.host.ID.String()
	status, env, _ := putEnvMode(t, w, tok, project, "lock", "KEY="+envSecret+"\nOTHER=1\n", strPtr("create"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	created := createImage(t, w, tok, guest.ID, "web", `{"kind":"service","image":"nginx","env_sets":["lock"]}`)
	hash, _ := created["spec_hash"].(string)
	entryID, _ := created["id"].(string)
	approve := func(specHash string) {
		t.Helper()
		status, env, _ := mustCall(t, w, w.token(owner.ID), http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+specHash+`"}`)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	approve(hash)

	status, env, _ = putEnvMode(t, w, tok, project, "lock", "KEY="+envSecret+"-other\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if createImageGet(t, w, tok, guest.ID, "web")["spec_hash"] != hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 1 {
		t.Fatal("value-only merge changed the hash or dropped the approval")
	}
	status, env, _ = putEnvMode(t, w, tok, project, "lock", "BAR=1\n", strPtr("merge"), nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if createImageGet(t, w, tok, guest.ID, "web")["spec_hash"] == hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 0 {
		t.Fatal("merge adding a key kept the hash or the approval")
	}
}

func TestEnvSetModesDelegated(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	project := sc.project.ID.String()
	status, env, _ := putEnvMode(t, w, w.token(owner.ID), project, "svc", "KEEP=1\n", nil, nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	for _, tc := range []struct{ set, mode string }{{"svc", "merge"}, {"fresh", "create"}} {
		before := len(w.mem.AllAudits())
		status, env, _ = putEnvMode(t, w, delegated, project, tc.set, "NEW=nope-delegated\n", strPtr(tc.mode), nil)
		mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		rows := w.mem.AllAudits()
		if len(rows) != before+1 {
			t.Fatalf("%s delegated audits %d", tc.mode, len(rows)-before)
		}
		// The refusal comes before the body is read, so every mode records
		// the route's env_set.replace denial.
		row := rows[len(rows)-1]
		if row.Action != audit.ActionEnvSetReplace || row.Decision != audit.DecisionDenied || row.Via != audit.ViaMCP || strings.Contains(string(row.Detail), "nope-delegated") {
			t.Fatalf("%s delegated audit %#v", tc.mode, row)
		}
	}
	if _, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "fresh"); err != store.ErrNotFound {
		t.Fatal("delegated create wrote a set")
	}
	set, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc")
	if err != nil || len(set.Keys) != 1 || set.Keys[0].Key != "KEEP" {
		t.Fatalf("delegated merge wrote keys %#v %v", set, err)
	}
}
