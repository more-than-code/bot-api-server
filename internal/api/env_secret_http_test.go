package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	plainLong  = "plain-long-value-0123456789"
	plainShort = "short-pv"
	plainStay  = "stays-plain"
)

// TestEnvKeysSecret covers api-v1 v1.17 item 1 on the owner path: two plain
// keys become secret, the response and a fresh GET show previews, the stored
// ciphertext opens to the old value, audit rows name the keys only, and the
// entry hash and host approval survive.
func TestEnvKeysSecret(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "LONG="+plainLong+"\nSHORT="+plainShort+"\nSTAY="+plainStay+"\n", false)
	putKey(t, w, tok, project, "svc", "TOKEN", envSecret, nil)

	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"]}`)
	hash, _ := created["spec_hash"].(string)
	entryID, _ := created["id"].(string)
	status, env, _ := mustCall(t, w, tok, http.MethodPost, "/v1/hosts/"+sc.host.ID.String()+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+hash+`"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	before, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	setClock(w, time.Minute)

	status, env, raw := markSecret(t, w, tok, project, "svc", "LONG", "SHORT", "TOKEN")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	posted := keysByName(t, env)
	assertSecretKey(t, posted["LONG"], catalog.SecretPreview(plainLong))
	assertSecretKey(t, posted["SHORT"], catalog.SecretPreview(plainShort))
	assertSecretKey(t, posted["TOKEN"], catalog.SecretPreview(envSecret))
	assertPlainKey(t, posted["STAY"], plainStay)
	if len(posted) != 4 {
		t.Fatalf("keys %#v", posted)
	}
	payload := objectPayload(t, env)
	if payload["name"] != "svc" || payload["updated_at"] == nil || payload["updated_by"] != owner.ID.String() {
		t.Fatalf("set shape %#v", payload)
	}
	if strings.Contains(raw, plainLong) || strings.Contains(raw, plainShort) || strings.Contains(raw, envSecret) {
		t.Fatalf("response held a value %s", raw)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := keysByName(t, env)
	assertSecretKey(t, got["LONG"], catalog.SecretPreview(plainLong))
	assertSecretKey(t, got["SHORT"], catalog.SecretPreview(plainShort))
	assertPlainKey(t, got["STAY"], plainStay)
	if strings.Contains(raw, plainLong) {
		t.Fatal("get returned the value")
	}

	mats, err := w.mem.ListEnvMaterial(context.Background(), sc.project.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	for _, mat := range mats {
		want := map[string]string{"LONG": plainLong, "SHORT": plainShort}[mat.Key]
		if want == "" {
			continue
		}
		if !mat.IsSecret || mat.Plain != "" || mat.KeyVersion != seal.KeyVersion {
			t.Fatalf("%s stored %#v", mat.Key, mat)
		}
		opened, err := w.srv.Secrets.Open(seal.EnvAAD(project, "svc", mat.Key), mat.Nonce, mat.Ciphertext)
		if err != nil || string(opened) != want {
			t.Fatalf("%s opened %q %v", mat.Key, opened, err)
		}
	}
	after, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc")
	if err != nil || !after.UpdatedAt.After(before.UpdatedAt) || after.UpdatedBy != owner.ID {
		t.Fatalf("updated_at %s -> %s %v", before.UpdatedAt, after.UpdatedAt, err)
	}

	secretRows := map[string]int{}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action != audit.ActionEnvSetKeySecret {
			continue
		}
		detail := detailMap(t, row.Detail)
		key, _ := detail["key"].(string)
		if row.Decision != audit.DecisionAllowed || row.Via != audit.ViaConsole || detail["set"] != "svc" || len(detail) != 2 {
			t.Fatalf("key_secret row %#v %#v", row, detail)
		}
		for _, v := range []string{plainLong, plainShort, envSecret} {
			if strings.Contains(string(row.Detail), v) {
				t.Fatalf("audit held a value %s", row.Detail)
			}
		}
		secretRows[key]++
	}
	if len(secretRows) != 2 || secretRows["LONG"] != 1 || secretRows["SHORT"] != 1 {
		t.Fatalf("key_secret rows %#v (TOKEN was already secret)", secretRows)
	}

	for _, row := range w.mem.AllAudits() {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{plainLong, plainShort, plainStay, envSecret} {
			if strings.Contains(string(raw), v) {
				t.Fatalf("audit row %s held a test value", row.Action)
			}
		}
	}
	if createImageGet(t, w, tok, sc.project.ID, "web")["spec_hash"] != hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 1 {
		t.Fatal("make secret changed the hash or dropped the approval")
	}

	// A repeat changes nothing: no audit rows and no updated_at move.
	auditsBefore := countAction(w.mem.AllAudits(), audit.ActionEnvSetKeySecret)
	setClock(w, 2*time.Minute)
	status, env, _ = markSecret(t, w, tok, project, "svc", "LONG", "SHORT")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["LONG"], catalog.SecretPreview(plainLong))
	again, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc")
	if err != nil || !again.UpdatedAt.Equal(after.UpdatedAt) {
		t.Fatalf("repeat moved updated_at %s -> %s %v", after.UpdatedAt, again.UpdatedAt, err)
	}
	if countAction(w.mem.AllAudits(), audit.ActionEnvSetKeySecret) != auditsBefore {
		t.Fatal("repeat wrote audit rows")
	}

	// v1.17 item 2: the key PUT still refuses a flag change both ways.
	status, env, raw = putKey(t, w, tok, project, "svc", "LONG", "zz-flag-value", boolPtr(false))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "secret flag is fixed; delete and re-add the key")
	status, env, _ = putKey(t, w, tok, project, "svc", "STAY", "zz-flag-value", boolPtr(true))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "secret flag is fixed; delete and re-add the key")
	if strings.Contains(raw, "zz-flag-value") {
		t.Fatal("flag error echoed the value")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["LONG"], catalog.SecretPreview(plainLong))
	assertPlainKey(t, keysByName(t, env)["STAY"], plainStay)
}

func TestEnvKeysSecretValidation(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "A="+plainLong+"\nB="+plainShort+"\n", false)
	snap := envSnap(t, w, sc.project.ID, "svc")
	path := envPath(project, "svc") + "/secret"

	tooMany := make([]string, 201)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("K%d", i)
	}
	manyBody, err := json.Marshal(map[string]any{"keys": tooMany})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, code, msg string
		status                int
	}{
		{"empty", `{"keys":[]}`, "bad_request", "keys must list 1 to 200 keys", http.StatusBadRequest},
		{"absent", `{}`, "bad_request", "keys must list 1 to 200 keys", http.StatusBadRequest},
		{"null", `{"keys":null}`, "bad_request", "keys must list 1 to 200 keys", http.StatusBadRequest},
		{"too many", string(manyBody), "bad_request", "keys must list 1 to 200 keys", http.StatusBadRequest},
		{"duplicate", `{"keys":["A","B","A"]}`, "bad_request", "duplicate key A", http.StatusBadRequest},
		{"bad key", `{"keys":["A","1NO"]}`, "bad_request", "invalid env key", http.StatusBadRequest},
		{"reserved", `{"keys":["PATH"]}`, "bad_request", "PATH is reserved", http.StatusBadRequest},
		{"unknown field", `{"keys":["A"],"value":"x"}`, "bad_request", "invalid json", http.StatusBadRequest},
		{"not json", `keys`, "bad_request", "invalid json", http.StatusBadRequest},
		{"unknown key", `{"keys":["A","GONE","B"]}`, "not_found", "key GONE not found", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, env, _ := mustCall(t, w, tok, http.MethodPost, path, tc.body)
			mustHTTP(t, status, env, tc.status, tc.code, tc.msg)
			if got := envSnap(t, w, sc.project.ID, "svc"); got != snap {
				t.Fatalf("set changed %s -> %s", snap, got)
			}
		})
	}
	// 200 keys pass validation and reach the store, which names the first missing key.
	exact, err := json.Marshal(map[string]any{"keys": append([]string{"A"}, tooMany[:199]...)})
	if err != nil {
		t.Fatal(err)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodPost, path, string(exact))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "key K0 not found")

	status, env, _ = markSecret(t, w, tok, project, "missing", "A")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tok, http.MethodPost, envPath(project, "BAD")+"/secret", `{"keys":["A"]}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid name")
	if got := envSnap(t, w, sc.project.ID, "svc"); got != snap {
		t.Fatalf("set changed %s -> %s", snap, got)
	}
	if n := countAction(w.mem.AllAudits(), audit.ActionEnvSetKeySecret); n != 0 {
		t.Fatalf("refused calls wrote %d audit rows", n)
	}

	w.srv.Secrets = nil
	status, env, _ = markSecret(t, w, tok, project, "svc", "A")
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	if got := envSnap(t, w, sc.project.ID, "svc"); got != snap {
		t.Fatalf("set changed without a key %s -> %s", snap, got)
	}
}

func TestEnvKeysSecretRoles(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("a@ex.com", "A")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "A="+plainLong+"\nB="+plainShort+"\n", false)
	snap := envSnap(t, w, sc.project.ID, "svc")
	path := envPath(project, "svc") + "/secret"
	body := `{"keys":["A"]}`

	status, env := w.do(w.token(sc.spare.ID), http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(sc.extra.ID), http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = w.do("", http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusUnauthorized, "unauthorized", "unauthorized")

	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	before := len(w.mem.AllAudits())
	status, env = w.do(delegated, http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	rows := w.mem.AllAudits()
	if len(rows) != before+1 {
		t.Fatalf("delegated audits %d", len(rows)-before)
	}
	assertDelegatedDenied(t, rows[len(rows)-1], owner.ID, "POST /v1/projects/{id}/env-sets/{set}/secret")
	if got := envSnap(t, w, sc.project.ID, "svc"); got != snap {
		t.Fatalf("refused caller changed the set %s -> %s", snap, got)
	}
	if n := countAction(w.mem.AllAudits(), audit.ActionEnvSetKeySecret); n != 0 {
		t.Fatalf("refused callers wrote %d key_secret rows", n)
	}

	status, env, _ = markSecret(t, w, w.token(admin.ID), project, "svc", "A")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["A"], catalog.SecretPreview(plainLong))
	assertPlainKey(t, keysByName(t, env)["B"], plainShort)
	status, env, _ = markSecret(t, w, tok, project, "svc", "B")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["B"], catalog.SecretPreview(plainShort))
}

func markSecret(t *testing.T, w *world, tok, project, set string, keys ...string) (int, envelope, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return mustCall(t, w, tok, http.MethodPost, envPath(project, set)+"/secret", string(raw))
}

// setClock moves the server clock to the world start plus d.
func setClock(w *world, d time.Duration) {
	at := w.now.Add(d)
	w.srv.Now = func() time.Time { return at }
}

// TestEnvKeysSecretDeploy is spec AC5 over HTTP: after the change the next
// deploy lists the key in secret_keys and shows its preview in task output.
func TestEnvKeysSecretDeploy(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "LONG="+plainLong+"\nSTAY="+plainStay+"\n", false)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"]}`)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		reply := imageDeployReply(msg, shaDigest(6))
		reply["payload"].(map[string]any)["lines"] = []string{"value " + plainLong}
		return reply
	})
	host := sc.host.ID.String()

	status, env, _ := postImage(t, w, tok, project, "web", "deploy", host, "before-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec, _ := log.raw(0)["spec"].(map[string]any)
	if keys, ok := spec["secret_keys"].([]any); !ok || len(keys) != 0 {
		t.Fatalf("plain secret_keys %#v", spec["secret_keys"])
	}
	assertPreviewLines(t, "plain deploy", env, "", []string{"value " + plainLong}, nil)

	status, env, _ = markSecret(t, w, tok, project, "svc", "LONG")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")

	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "after-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec, _ = log.raw(1)["spec"].(map[string]any)
	if got := strings.Join(stringList(spec["secret_keys"]), ","); got != "LONG" {
		t.Fatalf("secret_keys %q", got)
	}
	envMap, _ := spec["env"].(map[string]any)
	if envMap["LONG"] != plainLong || envMap["STAY"] != plainStay {
		t.Fatal("container env changed")
	}
	assertPreviewLines(t, "secret deploy", env, raw, []string{"value " + catalog.SecretPreview(plainLong)}, []string{plainLong})
}

// sealFailStore makes the second seal of MakeEnvKeysSecret fail with the
// error the handler's sealer would return when the secrets key is missing.
type sealFailStore struct {
	store.Store
}

func (f sealFailStore) MakeEnvKeysSecret(ctx context.Context, projectID uuid.UUID, name string, keys []string, seal store.EnvSealer, actor uuid.UUID, at time.Time) (store.EnvSet, []string, error) {
	calls := 0
	failing := func(key, plain string) (store.EnvSecret, error) {
		calls++
		if calls == 2 {
			return store.EnvSecret{}, sealFailure{errSecretsKey}
		}
		return seal(key, plain)
	}
	return f.Store.MakeEnvKeysSecret(ctx, projectID, name, keys, failing, actor, at)
}

// previewFailStore lets MakeEnvKeysSecret commit and then fails the
// material read that withPreviews makes for the response.
type previewFailStore struct {
	store.Store
}

func (f previewFailStore) ListEnvMaterial(context.Context, uuid.UUID, string) ([]store.EnvMaterial, error) {
	return nil, errors.New("material read failed")
}

// TestEnvKeysSecretAuditBeforePreview pins the audit order: a failure after
// the commit still leaves one key_secret row per changed key.
func TestEnvKeysSecretAuditBeforePreview(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "A="+plainLong+"\nB="+plainShort+"\nC="+plainStay+"\n", false)
	w.srv.Store = previewFailStore{Store: w.mem}

	status, env, raw := markSecret(t, w, tok, project, "svc", "A", "B")
	mustHTTP(t, status, env, http.StatusInternalServerError, "error", "internal error")
	if strings.Contains(raw, plainLong) || strings.Contains(raw, plainShort) {
		t.Fatalf("error body held a value %s", raw)
	}
	rows := map[string]int{}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == audit.ActionEnvSetKeySecret {
			key, _ := detailMap(t, row.Detail)["key"].(string)
			rows[key]++
		}
	}
	if len(rows) != 2 || rows["A"] != 1 || rows["B"] != 1 {
		t.Fatalf("key_secret rows %#v", rows)
	}
	set, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range set.Keys {
		if key.IsSecret != (key.Key != "C") {
			t.Fatalf("key %s secret=%v", key.Key, key.IsSecret)
		}
	}
}

func TestEnvKeysSecretSealFailure(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnvFlag(t, w, tok, project, "svc", "A="+plainLong+"\nB="+plainShort+"\n", false)
	snap := envSnap(t, w, sc.project.ID, "svc")
	w.srv.Store = sealFailStore{Store: w.mem}

	status, env, raw := markSecret(t, w, tok, project, "svc", "A", "B")
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	for _, v := range []string{plainLong, plainShort, "nonce", "ciphertext"} {
		if strings.Contains(raw, v) {
			t.Fatalf("seal error body held %q: %s", v, raw)
		}
	}
	if got := envSnap(t, w, sc.project.ID, "svc"); got != snap {
		t.Fatalf("seal failure changed the set %s -> %s", snap, got)
	}
	if n := countAction(w.mem.AllAudits(), audit.ActionEnvSetKeySecret); n != 0 {
		t.Fatalf("seal failure wrote %d key_secret rows", n)
	}
}
