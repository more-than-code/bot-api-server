package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const inviteNotFoundBody = `{"code":"not_found","msg":"not found","payload":null}`

type inviteFix struct {
	t      *testing.T
	mem    *memstore.Mem
	srv    *Server
	http   *httptest.Server
	client *http.Client
	now    time.Time
	logs   *bytes.Buffer
}

func newInviteFix(t *testing.T) *inviteFix {
	t.Helper()
	mem := memstore.New()
	f := &inviteFix{
		t:    t,
		mem:  mem,
		now:  time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC),
		logs: &bytes.Buffer{},
	}
	clk := func() time.Time { return f.now }
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	f.srv = &Server{
		Store:         mem,
		Auth:          auth.New(mem, config.Config{}, clk),
		Audit:         audit.Writer{Store: mem, Log: log, Now: clk},
		ConsoleOrigin: "http://console.test",
		Log:           log,
		Now:           clk,
	}
	f.http = httptest.NewServer(f.srv.Handler())
	f.client = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(f.http.Close)
	return f
}

func (f *inviteFix) user(email, name string) store.User {
	f.t.Helper()
	u, err := f.mem.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: email, Email: email, Name: name, At: f.now,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

func (f *inviteFix) session(userID uuid.UUID, kind string) string {
	f.t.Helper()
	plain, hash, err := secret.NewToken()
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.mem.CreateSession(context.Background(), userID, hash, kind, f.now.Add(30*24*time.Hour), f.now); err != nil {
		f.t.Fatal(err)
	}
	return plain
}

func (f *inviteFix) project(owner store.User, name, slug string) store.Project {
	f.t.Helper()
	p, err := f.mem.CreateProject(context.Background(), owner.ID, name, slug, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *inviteFix) do(token, method, path, body string) (int, []byte) {
	f.t.Helper()
	var rdr io.Reader
	if body != "" || method == http.MethodPost {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.http.URL+path, rdr)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return res.StatusCode, raw
}

func decodeInviteEnv(t *testing.T, raw []byte) (string, string, json.RawMessage) {
	t.Helper()
	var env struct {
		Code    string          `json:"code"`
		Msg     string          `json:"msg"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("json: %v body %s", err, raw)
	}
	return env.Code, env.Msg, env.Payload
}

type inviteView struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	RevokedAt *time.Time `json:"revoked_at"`
	Token     string     `json:"token"`
	URL       string     `json:"url"`
}

func decodeInvite(t *testing.T, raw []byte) inviteView {
	t.Helper()
	code, msg, payload := decodeInviteEnv(t, raw)
	if code != "ok" || msg != "ok" {
		t.Fatalf("envelope %s %s body %s", code, msg, raw)
	}
	var item inviteView
	if err := json.Unmarshal(payload, &item); err != nil {
		t.Fatalf("payload: %v body %s", err, raw)
	}
	return item
}

func decodeInviteList(t *testing.T, raw []byte) []inviteView {
	t.Helper()
	code, _, payload := decodeInviteEnv(t, raw)
	if code != "ok" {
		t.Fatalf("list %s", raw)
	}
	var body struct {
		Items []inviteView `json:"items"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("list payload: %v", err)
	}
	return body.Items
}

func TestInviteCreateShowsTokenOnce(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	tok := f.session(owner.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	path := "/v1/projects/" + p.ID.String() + "/invites"

	status, raw := f.do(tok, http.MethodPost, path, `{"role":"viewer"}`)
	if status != http.StatusCreated {
		t.Fatalf("create %d %s", status, raw)
	}
	first := decodeInvite(t, raw)
	if first.Role != "viewer" || first.MaxUses != 1 || first.Uses != 0 || first.RevokedAt != nil {
		t.Fatalf("invite %#v", first)
	}
	if first.CreatedBy != owner.ID.String() {
		t.Fatalf("created_by %s", first.CreatedBy)
	}
	wantExp := f.now.Add(604800 * time.Second)
	if !first.ExpiresAt.Equal(wantExp) {
		t.Fatalf("expires %s want %s", first.ExpiresAt, wantExp)
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(first.Token)
	if err != nil || len(first.Token) != 43 || len(rawToken) != 32 {
		t.Fatalf("token %q", first.Token)
	}
	if first.URL != "http://console.test/invite/"+first.Token {
		t.Fatalf("url %s", first.URL)
	}
	if strings.Count(string(raw), first.Token) != 2 {
		t.Fatalf("token should appear in token and url only: %s", raw)
	}

	f.now = f.now.Add(time.Second)
	f.srv.ConsoleOrigin = "http://console.test/"
	status, raw = f.do(tok, http.MethodPost, path, `{"role":"admin","expires_in_sec":3600,"max_uses":50}`)
	if status != http.StatusCreated {
		t.Fatalf("second create %d %s", status, raw)
	}
	second := decodeInvite(t, raw)
	if second.Token == first.Token || second.Role != "admin" || second.MaxUses != 50 {
		t.Fatalf("second %#v", second)
	}
	if second.URL != "http://console.test/invite/"+second.Token {
		t.Fatalf("trimmed url %s", second.URL)
	}
	if !second.ExpiresAt.Equal(f.now.Add(3600 * time.Second)) {
		t.Fatalf("explicit expiry %s", second.ExpiresAt)
	}
	if strings.Contains(string(raw), first.Token) {
		t.Fatal("second response contains the first token")
	}

	status, listRaw := f.do(tok, http.MethodGet, path, "")
	if status != http.StatusOK {
		t.Fatalf("list %d %s", status, listRaw)
	}
	if strings.Contains(string(listRaw), first.Token) || strings.Contains(string(listRaw), second.Token) || strings.Contains(string(listRaw), "/invite/") {
		t.Fatalf("list contains a token: %s", listRaw)
	}
	items := decodeInviteList(t, listRaw)
	if len(items) != 2 || items[0].ID != second.ID || items[1].ID != first.ID {
		t.Fatalf("order %#v", items)
	}
	for _, item := range items {
		if item.Token != "" || item.URL != "" {
			t.Fatalf("list item has a secret %#v", item)
		}
	}
}

func TestInviteCreateValidation(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	tok := f.session(owner.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	path := "/v1/projects/" + p.ID.String() + "/invites"
	cases := []struct {
		body string
		msg  string
	}{
		{`{"role":"owner"}`, "invalid role"},
		{`{"role":"member"}`, "invalid role"},
		{`{}`, "invalid role"},
		{`{"role":"viewer","expires_in_sec":3599}`, "invalid expires_in_sec"},
		{`{"role":"viewer","expires_in_sec":2592001}`, "invalid expires_in_sec"},
		{`{"role":"viewer","max_uses":0}`, "invalid max_uses"},
		{`{"role":"viewer","max_uses":51}`, "invalid max_uses"},
		{`{"role":"viewer","extra":1}`, "invalid json"},
	}
	for _, tc := range cases {
		status, raw := f.do(tok, http.MethodPost, path, tc.body)
		code, msg, _ := decodeInviteEnv(t, raw)
		if status != http.StatusBadRequest || code != "bad_request" || msg != tc.msg {
			t.Fatalf("%s: %d %s", tc.body, status, raw)
		}
	}
	if items := f.list(tok, path); len(items) != 0 {
		t.Fatalf("rejected bodies created invites: %#v", items)
	}
	for _, body := range []string{
		`{"role":"viewer","expires_in_sec":3600}`,
		`{"role":"viewer","expires_in_sec":2592000}`,
		`{"role":"admin","max_uses":1}`,
		`{"role":"admin","max_uses":50}`,
	} {
		status, raw := f.do(tok, http.MethodPost, path, body)
		if status != http.StatusCreated {
			t.Fatalf("%s: %d %s", body, status, raw)
		}
	}
}

func TestInviteAdminAuthz(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	admin := f.user("admin@example.com", "Admin")
	viewer := f.user("viewer@example.com", "Viewer")
	outsider := f.user("out@example.com", "Out")
	p := f.project(owner, "Lab", "lab")
	if _, err := f.mem.AddMember(context.Background(), p.ID, admin.ID, "admin", owner.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.AddMember(context.Background(), p.ID, viewer.ID, "viewer", owner.ID, f.now); err != nil {
		t.Fatal(err)
	}
	ownerTok := f.session(owner.ID, store.KindConsole)
	adminTok := f.session(admin.ID, store.KindConsole)
	viewerTok := f.session(viewer.ID, store.KindConsole)
	outTok := f.session(outsider.ID, store.KindConsole)
	path := "/v1/projects/" + p.ID.String() + "/invites"

	status, raw := f.do(ownerTok, http.MethodPost, path, `{"role":"viewer"}`)
	if status != http.StatusCreated {
		t.Fatalf("owner create %d %s", status, raw)
	}
	created := decodeInvite(t, raw)
	del := path + "/" + created.ID

	status, raw = f.do(adminTok, http.MethodPost, path, `{"role":"admin"}`)
	if status != http.StatusCreated {
		t.Fatalf("admin create %d %s", status, raw)
	}

	for _, call := range []struct{ method, url string }{
		{http.MethodPost, path},
		{http.MethodGet, path},
		{http.MethodDelete, del},
	} {
		body := ""
		if call.method == http.MethodPost {
			body = `{"role":"viewer"}`
		}
		status, raw = f.do(viewerTok, call.method, call.url, body)
		code, _, _ := decodeInviteEnv(t, raw)
		if status != http.StatusForbidden || code != "forbidden" || string(raw) != `{"code":"forbidden","msg":"forbidden","payload":null}` {
			t.Fatalf("viewer %s %s: %d %s", call.method, call.url, status, raw)
		}
		status, raw = f.do(outTok, call.method, call.url, body)
		code, _, _ = decodeInviteEnv(t, raw)
		if status != http.StatusNotFound || code != "not_found" || string(raw) != inviteNotFoundBody {
			t.Fatalf("outsider %s %s: %d %s", call.method, call.url, status, raw)
		}
	}
	items := f.list(ownerTok, path)
	for _, item := range items {
		if item.ID == created.ID && item.RevokedAt != nil {
			t.Fatal("denied revoke changed revoked_at")
		}
	}
}

func TestInviteRevokeOtherProject(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	tok := f.session(owner.ID, store.KindConsole)
	a := f.project(owner, "A", "a")
	b := f.project(owner, "B", "b")
	status, raw := f.do(tok, http.MethodPost, "/v1/projects/"+b.ID.String()+"/invites", `{"role":"viewer"}`)
	if status != http.StatusCreated {
		t.Fatalf("create %d %s", status, raw)
	}
	other := decodeInvite(t, raw)
	status, raw = f.do(tok, http.MethodDelete, "/v1/projects/"+a.ID.String()+"/invites/"+other.ID, "")
	if status != http.StatusNotFound || string(raw) != inviteNotFoundBody {
		t.Fatalf("cross revoke %d %s", status, raw)
	}
	items := f.list(tok, "/v1/projects/"+b.ID.String()+"/invites")
	if len(items) != 1 || items[0].ID != other.ID || items[0].RevokedAt != nil {
		t.Fatalf("other invite changed: %#v", items)
	}

	status, raw = f.do(tok, http.MethodPost, "/v1/projects/"+a.ID.String()+"/invites", `{"role":"admin"}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	mine := decodeInvite(t, raw)
	del := "/v1/projects/" + a.ID.String() + "/invites/" + mine.ID
	status, raw = f.do(tok, http.MethodDelete, del, "")
	if status != http.StatusOK || string(raw) != `{"code":"ok","msg":"ok","payload":null}` {
		t.Fatalf("revoke %d %s", status, raw)
	}
	revokedAt := f.now
	f.now = f.now.Add(time.Minute)
	status, raw = f.do(tok, http.MethodDelete, del, "")
	if status != http.StatusOK {
		t.Fatalf("second revoke %d %s", status, raw)
	}
	items = f.list(tok, "/v1/projects/"+a.ID.String()+"/invites")
	if len(items) != 1 || items[0].RevokedAt == nil || !items[0].RevokedAt.Equal(revokedAt) {
		t.Fatalf("idempotent revoke %#v want %s", items, revokedAt)
	}
}

func TestInviteLookupReadOnly(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer","max_uses":2}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	before := len(f.mem.AllAudits())
	for i := 0; i < 2; i++ {
		status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", `{"token":"`+created.Token+`"}`)
		if status != http.StatusOK {
			t.Fatalf("lookup %d %s", status, raw)
		}
		var got struct {
			ProjectID     string `json:"project_id"`
			ProjectName   string `json:"project_name"`
			Role          string `json:"role"`
			AlreadyMember bool   `json:"already_member"`
		}
		_, _, payload := decodeInviteEnv(t, raw)
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.ProjectID != p.ID.String() || got.ProjectName != "Lab" || got.Role != "viewer" || got.AlreadyMember {
			t.Fatalf("lookup %#v", got)
		}
		if strings.Contains(string(raw), created.Token) {
			t.Fatal("lookup returned the token")
		}
	}
	if len(f.mem.AllAudits()) != before {
		t.Fatal("lookup wrote an audit row")
	}
	items := f.list(ownerTok, "/v1/projects/"+p.ID.String()+"/invites")
	if len(items) != 1 || items[0].Uses != 0 {
		t.Fatalf("uses changed: %#v", items)
	}
	if _, err := f.mem.Role(context.Background(), p.ID, guest.ID); err == nil {
		t.Fatal("lookup added a member")
	}
}

func TestInviteUnusableNotFound(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	joiner := f.user("joiner@example.com", "Joiner")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	joinerTok := f.session(joiner.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	base := "/v1/projects/" + p.ID.String() + "/invites"

	status, raw := f.do(ownerTok, http.MethodPost, base, `{"role":"viewer","expires_in_sec":3600}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	short := decodeInvite(t, raw)
	f.now = f.now.Add(3600*time.Second + time.Second)

	status, raw = f.do(ownerTok, http.MethodPost, base, `{"role":"viewer"}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	revoked := decodeInvite(t, raw)
	status, raw = f.do(ownerTok, http.MethodDelete, base+"/"+revoked.ID, "")
	if status != http.StatusOK {
		t.Fatal(string(raw))
	}

	status, raw = f.do(ownerTok, http.MethodPost, base, `{"role":"admin","max_uses":1}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	used := decodeInvite(t, raw)
	status, raw = f.do(joinerTok, http.MethodPost, "/v1/invites/accept", `{"token":"`+used.Token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("consume %d %s", status, raw)
	}

	probes := []string{
		`{"token":"nope"}`,
		`{"token":""}`,
		`{"token":"abc="}`,
		`{"token":"` + short.Token + `"}`,
		`{"token":"` + revoked.Token + `"}`,
		`{"token":"` + used.Token + `"}`,
	}
	for _, body := range probes {
		for _, path := range []string{"/v1/invites/lookup", "/v1/invites/accept"} {
			status, raw = f.do(guestTok, http.MethodPost, path, body)
			if status != http.StatusNotFound || string(raw) != inviteNotFoundBody {
				t.Fatalf("%s %s: %d %s", path, body, status, raw)
			}
		}
	}
	for _, path := range []string{"/v1/invites/lookup", "/v1/invites/accept"} {
		status, raw = f.do(ownerTok, http.MethodPost, path, `{"token":"`+used.Token+`"}`)
		if status != http.StatusNotFound || string(raw) != inviteNotFoundBody {
			t.Fatalf("member %s used-up: %d %s", path, status, raw)
		}
	}
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", `{`)
	code, msg, _ := decodeInviteEnv(t, raw)
	if status != http.StatusBadRequest || code != "bad_request" || msg != "invalid json" || string(raw) == inviteNotFoundBody {
		t.Fatalf("bad json %d %s", status, raw)
	}
	items := f.list(ownerTok, base)
	for _, item := range items {
		if item.ID == used.ID && item.Uses != 1 {
			t.Fatalf("used invite uses = %d", item.Uses)
		}
		if item.ID == short.ID && item.Uses != 0 {
			t.Fatal("expired invite consumed a use")
		}
		if item.ID == revoked.ID && item.Uses != 0 {
			t.Fatal("revoked invite consumed a use")
		}
	}
}

func TestInviteAcceptAddsMember(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"admin","max_uses":1}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/accept", `{"token":"`+created.Token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("accept %d %s", status, raw)
	}
	var got struct {
		ProjectID string `json:"project_id"`
		Role      string `json:"role"`
	}
	_, _, payload := decodeInviteEnv(t, raw)
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != p.ID.String() || got.Role != "admin" || strings.Contains(string(raw), created.Token) {
		t.Fatalf("accept %#v body %s", got, raw)
	}
	role, err := f.mem.Role(context.Background(), p.ID, guest.ID)
	if err != nil || role != "admin" {
		t.Fatalf("role %s %v", role, err)
	}
	items := f.list(ownerTok, "/v1/projects/"+p.ID.String()+"/invites")
	if len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("uses %#v", items)
	}
}

func TestInviteAcceptKeepsExistingRole(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer","max_uses":1}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	status, raw = f.do(ownerTok, http.MethodPost, "/v1/invites/lookup", `{"token":"`+created.Token+`"}`)
	if status != http.StatusOK {
		t.Fatal(string(raw))
	}
	var look struct {
		Role          string `json:"role"`
		AlreadyMember bool   `json:"already_member"`
	}
	_, _, payload := decodeInviteEnv(t, raw)
	if err := json.Unmarshal(payload, &look); err != nil {
		t.Fatal(err)
	}
	if look.Role != "viewer" || !look.AlreadyMember {
		t.Fatalf("lookup %#v", look)
	}
	before := 0
	for _, row := range f.mem.AllAudits() {
		if row.Action == audit.ActionInviteAccept {
			before++
		}
	}
	status, raw = f.do(ownerTok, http.MethodPost, "/v1/invites/accept", `{"token":"`+created.Token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("accept %d %s", status, raw)
	}
	var got struct {
		Role string `json:"role"`
	}
	_, _, payload = decodeInviteEnv(t, raw)
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Role != "owner" {
		t.Fatalf("role %s", got.Role)
	}
	accepts := 0
	for _, row := range f.mem.AllAudits() {
		if row.Action == audit.ActionInviteAccept {
			accepts++
		}
	}
	if accepts != before+1 {
		t.Fatalf("accept audits %d", accepts)
	}
	role, err := f.mem.Role(context.Background(), p.ID, owner.ID)
	if err != nil || role != "owner" {
		t.Fatalf("owner role %s %v", role, err)
	}
	items := f.list(ownerTok, "/v1/projects/"+p.ID.String()+"/invites")
	if len(items) != 1 || items[0].Uses != 0 {
		t.Fatalf("uses %#v", items)
	}
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/accept", `{"token":"`+created.Token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("guest %d %s", status, raw)
	}
	_, _, payload = decodeInviteEnv(t, raw)
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Role != "viewer" {
		t.Fatalf("guest role %s", got.Role)
	}
	role, err = f.mem.Role(context.Background(), p.ID, owner.ID)
	if err != nil || role != "owner" {
		t.Fatalf("owner role after guest %s", role)
	}
	items = f.list(ownerTok, "/v1/projects/"+p.ID.String()+"/invites")
	if len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("uses after guest %#v", items)
	}
}

func TestInviteConsoleSessionRequired(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	console := f.session(guest.ID, store.KindConsole)
	delegated := f.session(guest.ID, store.KindDelegated)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer"}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	body := `{"token":"` + created.Token + `"}`
	const unauth = `{"code":"unauthorized","msg":"unauthorized","payload":null}`
	for _, path := range []string{"/v1/invites/lookup", "/v1/invites/accept"} {
		for i := 0; i < 30; i++ {
			status, raw = f.do(delegated, http.MethodPost, path, body)
			if status != http.StatusUnauthorized || string(raw) != unauth {
				t.Fatalf("%s delegated %d %s", path, status, raw)
			}
		}
	}
	if _, err := f.mem.Role(context.Background(), p.ID, guest.ID); err == nil {
		t.Fatal("delegated accept added a member")
	}
	status, raw = f.do(console, http.MethodPost, "/v1/invites/lookup", body)
	if status != http.StatusOK {
		t.Fatalf("console lookup %d %s", status, raw)
	}
	status, raw = f.do(console, http.MethodPost, "/v1/invites/accept", body)
	if status != http.StatusOK {
		t.Fatalf("console accept %d %s", status, raw)
	}
	role, err := f.mem.Role(context.Background(), p.ID, guest.ID)
	if err != nil || role != "viewer" {
		t.Fatalf("console accept role %s %v", role, err)
	}
}

func TestInviteRateLimitUser(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer","max_uses":50}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	body := `{"token":"` + created.Token + `"}`
	for i := 0; i < 29; i++ {
		status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", body)
		if status != http.StatusOK {
			t.Fatalf("lookup %d: %d %s", i, status, raw)
		}
	}
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/accept", body)
	if status != http.StatusOK {
		t.Fatalf("accept %d %s", status, raw)
	}
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", body)
	if status != http.StatusTooManyRequests || string(raw) != `{"code":"rate_limited","msg":"rate limited","payload":null}` {
		t.Fatalf("user cap %d %s", status, raw)
	}
	f.now = f.now.Add(time.Minute)
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", body)
	if status != http.StatusOK {
		t.Fatalf("after window %d %s", status, raw)
	}
	items := f.list(ownerTok, "/v1/projects/"+p.ID.String()+"/invites")
	if len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("uses %#v", items)
	}
}

func TestInviteRateLimitIP(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	ownerTok := f.session(owner.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer","max_uses":50}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	body := `{"token":"` + created.Token + `"}`
	var tokens []string
	for i := 0; i < 3; i++ {
		u := f.user("u"+string(rune('a'+i))+"@example.com", "U")
		tokens = append(tokens, f.session(u.ID, store.KindConsole))
	}
	for i := 0; i < 2; i++ {
		for n := 0; n < 30; n++ {
			status, raw = f.do(tokens[i], http.MethodPost, "/v1/invites/lookup", body)
			if status != http.StatusOK {
				t.Fatalf("user %d req %d: %d %s", i, n, status, raw)
			}
		}
	}
	status, raw = f.do(tokens[2], http.MethodPost, "/v1/invites/lookup", body)
	if status != http.StatusTooManyRequests || string(raw) != `{"code":"rate_limited","msg":"rate limited","payload":null}` {
		t.Fatalf("ip cap %d %s", status, raw)
	}
	f.now = f.now.Add(time.Minute)
	status, raw = f.do(tokens[2], http.MethodPost, "/v1/invites/lookup", body)
	if status != http.StatusOK {
		t.Fatalf("ip window %d %s", status, raw)
	}
}

func TestInviteAuditOmitsToken(t *testing.T) {
	f := newInviteFix(t)
	owner := f.user("owner@example.com", "Owner")
	guest := f.user("guest@example.com", "Guest")
	ownerTok := f.session(owner.ID, store.KindConsole)
	guestTok := f.session(guest.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	status, raw := f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"viewer","max_uses":2,"expires_in_sec":3600}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	created := decodeInvite(t, raw)
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/lookup", `{"token":"`+created.Token+`"}`)
	if status != http.StatusOK {
		t.Fatal(string(raw))
	}
	status, raw = f.do(ownerTok, http.MethodDelete, "/v1/projects/"+p.ID.String()+"/invites/"+created.ID, "")
	if status != http.StatusOK {
		t.Fatal(string(raw))
	}
	// A second invite is accepted so invite.accept is present alongside revoke.
	status, raw = f.do(ownerTok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/invites", `{"role":"admin","max_uses":1}`)
	if status != http.StatusCreated {
		t.Fatal(string(raw))
	}
	joined := decodeInvite(t, raw)
	status, raw = f.do(guestTok, http.MethodPost, "/v1/invites/accept", `{"token":"`+joined.Token+`"}`)
	if status != http.StatusOK {
		t.Fatal(string(raw))
	}

	var sawCreate, sawRevoke, sawAccept bool
	hexes := []string{hex.EncodeToString(secret.Hash(created.Token)), hex.EncodeToString(secret.Hash(joined.Token))}
	for _, row := range f.mem.AllAudits() {
		text := string(row.Detail)
		if strings.Contains(text, created.Token) || strings.Contains(text, joined.Token) {
			t.Fatalf("audit detail contains a token: %s %s", row.Action, text)
		}
		for _, h := range hexes {
			if strings.Contains(strings.ToLower(text), h) {
				t.Fatalf("audit detail contains a hash: %s", text)
			}
		}
		var detail map[string]any
		if err := json.Unmarshal(row.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		switch row.Action {
		case audit.ActionInviteCreate:
			sawCreate = true
			if detail["role"] != "viewer" && detail["role"] != "admin" {
				t.Fatalf("create detail %s", text)
			}
			id, _ := detail["invite_id"].(string)
			if id == "" || detail["max_uses"] == nil || detail["expires_at"] == nil {
				t.Fatalf("create detail %s", text)
			}
			if _, ok := detail["token"]; ok {
				t.Fatal("create detail has token")
			}
		case audit.ActionInviteRevoke:
			sawRevoke = true
			if detail["invite_id"] != created.ID {
				t.Fatalf("revoke detail %s", text)
			}
		case audit.ActionInviteAccept:
			sawAccept = true
			if detail["invite_id"] != joined.ID || detail["user_id"] != guest.ID.String() {
				t.Fatalf("accept detail %s", text)
			}
		}
	}
	if !sawCreate || !sawRevoke || !sawAccept {
		t.Fatalf("audit actions create=%v revoke=%v accept=%v", sawCreate, sawRevoke, sawAccept)
	}
	logged := f.logs.String()
	if strings.Contains(logged, created.Token) || strings.Contains(logged, joined.Token) {
		t.Fatalf("log contains a token: %s", logged)
	}
	for _, h := range hexes {
		if strings.Contains(strings.ToLower(logged), h) {
			t.Fatalf("log contains a hash: %s", logged)
		}
	}
}

func TestInviteEmptyOriginMintsNothing(t *testing.T) {
	f := newInviteFix(t)
	f.srv.ConsoleOrigin = ""
	owner := f.user("owner@example.com", "Owner")
	tok := f.session(owner.ID, store.KindConsole)
	p := f.project(owner, "Lab", "lab")
	path := "/v1/projects/" + p.ID.String() + "/invites"
	status, raw := f.do(tok, http.MethodPost, path, `{"role":"viewer"}`)
	code, msg, _ := decodeInviteEnv(t, raw)
	if status != http.StatusInternalServerError || code != "error" || msg != "internal error" {
		t.Fatalf("empty origin %d %s", status, raw)
	}
	if !strings.Contains(f.logs.String(), "console origin is not configured") {
		t.Fatalf("log %s", f.logs.String())
	}
	items := f.list(tok, path)
	if len(items) != 0 {
		t.Fatalf("minted %#v", items)
	}
}

func (f *inviteFix) list(token, path string) []inviteView {
	f.t.Helper()
	status, raw := f.do(token, http.MethodGet, path, "")
	if status != http.StatusOK {
		f.t.Fatalf("list %d %s", status, raw)
	}
	return decodeInviteList(f.t, raw)
}
