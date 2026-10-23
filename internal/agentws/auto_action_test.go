package agentws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func autoDigest(c byte) string {
	return "sha256:" + strings.Repeat(string(c), 64)
}

func autoEntry(t *testing.T, st *memstore.Mem, projectID, actor uuid.UUID, name, spec string, at time.Time) store.CatalogEntry {
	t.Helper()
	img, err := catalog.BuildImage(name, []byte(spec), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := st.CreateCatalogEntry(context.Background(), projectID, store.CatalogWrite{
		Name: name, Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image, Actor: actor, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func autoPolicy(onUnhealthy string) string {
	return `{"kind":"service","image":"redis","healthcheck":{"test":["redis-cli","ping"]},"health_policy":{"on_unhealthy":"` + onUnhealthy + `"}}`
}

func autoFrame(id, project, entry, action, result string, digest any, at time.Time) map[string]any {
	return map[string]any{
		"v": 1, "type": "auto_action", "id": id, "t": at.Format(time.RFC3339),
		"project": project, "entry": entry, "container": project + "-" + entry,
		"action": action, "reason": "unhealthy for 47s", "result": result, "digest": digest,
	}
}

// expectQuiet sends a ping and requires pong as the next frame, so nothing
// was written in reply to the frame before it.
func expectQuiet(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	writeMsg(t, conn, map[string]any{"v": 1, "type": "ping"})
	if got := readMsg(t, conn); got["type"] != "pong" {
		t.Fatalf("expected no reply, got %#v", got)
	}
}

func expectAck(t *testing.T, conn *websocket.Conn, id string) {
	t.Helper()
	got := readMsg(t, conn)
	if got["type"] != "auto_action_ack" || got["id"] != id || got["v"] != float64(1) || len(got) != 3 {
		t.Fatalf("ack %#v", got)
	}
}

func autoAudits(t *testing.T, st *memstore.Mem, projectID uuid.UUID) []store.AuditEntry {
	t.Helper()
	items, _, err := st.ListAudit(context.Background(), projectID, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := []store.AuditEntry{}
	for _, item := range items {
		if strings.HasPrefix(item.Action, "catalog.auto_") {
			out = append(out, item)
		}
	}
	return out
}

// lockedBuf is a log sink safe for the hub goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type autoClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *autoClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *autoClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func TestAutoActionIngest(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	logBuf := &lockedBuf{}
	log := slog.New(slog.NewTextHandler(logBuf, nil))
	clock := &autoClock{at: time.Now().UTC().Truncate(time.Second)}
	now := clock.now
	hub := New(st, audit.Writer{Store: st, Log: log, Now: now}, log, now)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "sub", Email: "a@b.c", Name: "A", At: now()})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name, slug string) store.Project {
		p, err := st.CreateProject(ctx, user.ID, name, slug, now())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	project, other, viewer, deployer := mk("P", "p"), mk("Q", "q"), mk("M", "m"), mk("D", "d")
	web := autoEntry(t, st, project.ID, user.ID, "web", autoPolicy("restart"), now())
	roll := autoEntry(t, st, project.ID, user.ID, "roll", autoPolicy("rollback"), now())
	plain := autoEntry(t, st, project.ID, user.ID, "plain", `{"kind":"service","image":"redis","healthcheck":{"test":["redis-cli","ping"]}}`, now())
	job := autoEntry(t, st, project.ID, user.ID, "batch", `{"kind":"job","image":"redis"}`, now())
	fresh := autoEntry(t, st, project.ID, user.ID, "fresh", autoPolicy("restart"), now())
	autoEntry(t, st, other.ID, user.ID, "web", autoPolicy("restart"), now())
	autoEntry(t, st, viewer.ID, user.ID, "web", autoPolicy("restart"), now())
	shared := autoEntry(t, st, deployer.ID, user.ID, "web", autoPolicy("restart"), now())

	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, now().Add(time.Hour), now()); err != nil {
		t.Fatal(err)
	}
	enrollConn := dial(t, url, "")
	writeMsg(t, enrollConn, map[string]any{
		"v": 1, "type": "enroll", "join_token": joinPlain,
		"hostname": "pi", "agent_version": "0.1.0", "os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, enrollConn)
	hostID, err := uuid.Parse(enrolled["host_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	credID := enrolled["credential_id"].(string)
	credential := enrolled["credential"].(string)
	if _, _, err := st.PutHostShare(ctx, hostID, viewer.ID, "metrics", user.ID, now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.PutHostShare(ctx, hostID, deployer.ID, "deploy", user.ID, now()); err != nil {
		t.Fatal(err)
	}

	// User deploys: the spec_hash and digest fallbacks, and the "deployed" rule.
	lastHash := strings.Repeat("a", 64)
	firstDigest := autoDigest('1')
	seed := func(entryID uuid.UUID, outcome string) {
		began, err := st.BeginImageOp(ctx, entryID, hostID, lastHash, user.ID, "console", now().Add(-2*time.Hour), now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.FinishImageDeploy(ctx, began.ID, outcome, &firstDigest, nil, now().Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []uuid.UUID{web.ID, roll.ID, plain.ID, job.ID, shared.ID} {
		seed(id, "succeeded")
	}
	seed(fresh.ID, "failed")

	hello := func(policy bool) *websocket.Conn {
		conn := dial(t, url, credential)
		programs := map[string]any{
			"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc",
			"images": true, "docker": true, "healthcheck": true,
		}
		if policy {
			programs["health_policy"] = true
		}
		writeMsg(t, conn, map[string]any{
			"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
			"agent_version": "0.2.6", "os": "linux", "arch": "arm64", "services": []any{}, "programs": programs,
		})
		if got := readMsg(t, conn); got["type"] != "hello_ok" {
			t.Fatalf("hello %#v", got)
		}
		return conn
	}
	rows := func(entryID uuid.UUID) []store.ImageDeploy {
		items, err := st.ListImageDeploys(ctx, entryID, hostID)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	frameAt := now().Add(-5 * time.Minute)

	// An agent that did not advertise health_policy gets no ack and nothing is stored.
	old := hello(false)
	writeMsg(t, old, autoFrame(uuid.New().String(), "p", "web", "restart", "ok", autoDigest('2'), frameAt))
	expectQuiet(t, old)
	if len(rows(web.ID)) != 1 || len(autoAudits(t, st, project.ID)) != 0 {
		t.Fatal("ungated auto_action was stored")
	}
	old.Close(websocket.StatusNormalClosure, "")

	conn := hello(true)
	// Each frame advances the clock by a second, so the per-connection bucket
	// (burst 10, 1 a second) never throttles this test.
	sendAuto := func(f map[string]any) {
		clock.add(time.Second)
		writeMsg(t, conn, f)
	}
	restartID := uuid.New().String()
	sendAuto(autoFrame(restartID, "p", "web", "restart", "ok", autoDigest('2'), frameAt))
	expectAck(t, conn, restartID)
	got := rows(web.ID)
	if len(got) != 2 {
		t.Fatalf("rows %d", len(got))
	}
	row := got[0]
	serverAt := now()
	if row.Outcome != "auto_restarted" || row.Via != "agent" || row.By != nil || row.Digest == nil || *row.Digest != autoDigest('2') ||
		row.SpecHash != lastHash || !row.StartedAt.Equal(serverAt) || row.FinishedAt == nil || !row.FinishedAt.Equal(serverAt) || row.ExitCode != nil {
		t.Fatalf("restart row %+v (want server time %s)", row, serverAt)
	}
	raw, err := json.Marshal(row)
	if err != nil || !strings.Contains(string(raw), `"by":null`) || !strings.Contains(string(raw), `"via":"agent"`) {
		t.Fatalf("row json %s %v", raw, err)
	}
	audits := autoAudits(t, st, project.ID)
	if len(audits) != 1 {
		t.Fatalf("audits %d", len(audits))
	}
	a := audits[0]
	if a.Action != "catalog.auto_restart" || a.Via != "agent" || a.ActorUserID != nil || a.Decision != "allowed" ||
		a.HostID == nil || *a.HostID != hostID || a.Result == nil || *a.Result != "ok" || a.ErrorCode != nil {
		t.Fatalf("audit %+v", a)
	}
	var detail map[string]any
	if err := json.Unmarshal(a.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["entry"] != "web" || detail["host"] != "pi" || detail["container"] != "p-web" || detail["reason"] != "unhealthy for 47s" ||
		detail["result"] != "ok" || detail["t"] != frameAt.Format(time.RFC3339) {
		t.Fatalf("detail %#v", detail)
	}

	// Replay: acknowledged, not stored twice.
	sendAuto(autoFrame(restartID, "p", "web", "restart", "ok", autoDigest('2'), frameAt))
	expectAck(t, conn, restartID)
	if len(rows(web.ID)) != 2 || len(autoAudits(t, st, project.ID)) != 1 {
		t.Fatal("replayed auto_action stored twice")
	}

	// rollback on a rollback entry; a null digest falls back to the last stored digest.
	clock.add(time.Second)
	rollID := uuid.New().String()
	sendAuto(autoFrame(rollID, "p", "roll", "rollback", "ok", nil, frameAt))
	expectAck(t, conn, rollID)
	if got := rows(roll.ID); len(got) != 2 || got[0].Outcome != "auto_rolled_back" || got[0].Digest == nil || *got[0].Digest != firstDigest {
		t.Fatalf("rollback row %+v", got[0])
	}
	// gave_up needs any policy other than none.
	clock.add(time.Second)
	gaveID := uuid.New().String()
	sendAuto(autoFrame(gaveID, "p", "roll", "gave_up", "ok", nil, frameAt))
	expectAck(t, conn, gaveID)
	if got := rows(roll.ID); len(got) != 3 || got[0].Outcome != "auto_gave_up" {
		t.Fatalf("gave_up row %+v", got[0])
	}
	// An error result is auto_failed with a null digest, whatever the action.
	clock.add(time.Second)
	failID := uuid.New().String()
	sendAuto(autoFrame(failID, "p", "web", "rollback", "error", autoDigest('3'), frameAt))
	expectAck(t, conn, failID)
	got = rows(web.ID)
	if len(got) != 3 || got[0].Outcome != "auto_failed" || got[0].Digest != nil {
		t.Fatalf("failed row %+v", got[0])
	}
	var failedAudit, gaveAudit bool
	for _, item := range autoAudits(t, st, project.ID) {
		if item.Action == "catalog.auto_rollback" && item.ErrorCode != nil && *item.ErrorCode == "error" {
			failedAudit = true
		}
		if item.Action == "catalog.auto_gave_up" {
			gaveAudit = true
		}
	}
	if !failedAudit || !gaveAudit {
		t.Fatal("auto_failed or gave_up audit missing")
	}
	// RollbackDigests stays user deploys only.
	if digests, err := st.RollbackDigests(ctx, web.ID, hostID); err != nil || len(digests) != 1 || digests[0] != firstDigest {
		t.Fatalf("rollback digests %v %v", digests, err)
	}

	// A deploy-level share counts; spec_hash comes from its last row.
	sharedID := uuid.New().String()
	sendAuto(autoFrame(sharedID, "d", "web", "restart", "ok", nil, frameAt))
	expectAck(t, conn, sharedID)
	if sharedRows := rows(shared.ID); len(sharedRows) != 2 || sharedRows[0].SpecHash != lastHash || sharedRows[0].Digest == nil {
		t.Fatalf("shared rows %+v", sharedRows)
	}
	if len(autoAudits(t, st, deployer.ID)) != 1 {
		t.Fatal("shared project audit missing")
	}

	// Frames that fail validation or authority are acknowledged and dropped.
	counts := func() map[uuid.UUID]int {
		out := map[uuid.UUID]int{}
		for _, e := range []store.CatalogEntry{web, roll, plain, job, fresh, shared} {
			out[e.ID] = len(rows(e.ID))
		}
		return out
	}
	before := counts()
	auditsBefore := len(autoAudits(t, st, project.ID))
	invalid := []map[string]any{
		autoFrame(uuid.New().String(), "p", "nope", "restart", "ok", nil, frameAt),
		autoFrame(uuid.New().String(), "q", "web", "restart", "ok", nil, frameAt),
		autoFrame(uuid.New().String(), "m", "web", "restart", "ok", nil, frameAt),
		autoFrame(uuid.New().String(), "zz", "web", "restart", "ok", nil, frameAt),
		autoFrame(uuid.New().String(), "p", "web", "stop", "ok", nil, frameAt),
		autoFrame(uuid.New().String(), "p", "web", "restart", "maybe", nil, frameAt),
		autoFrame(uuid.New().String(), "p", "web", "restart", "ok", "sha256:short", frameAt),
		autoFrame(uuid.New().String(), "p", "Web!", "restart", "ok", nil, frameAt),
		// authority (rev 2)
		autoFrame(uuid.New().String(), "p", "web", "rollback", "ok", nil, frameAt),     // policy is restart
		autoFrame(uuid.New().String(), "p", "roll", "restart", "ok", nil, frameAt),     // policy is rollback
		autoFrame(uuid.New().String(), "p", "plain", "restart", "ok", nil, frameAt),    // no policy
		autoFrame(uuid.New().String(), "p", "plain", "gave_up", "ok", nil, frameAt),    // gave_up needs a policy
		autoFrame(uuid.New().String(), "p", "plain", "restart", "error", nil, frameAt), // auto_failed needs a policy
		autoFrame(uuid.New().String(), "p", "batch", "gave_up", "ok", nil, frameAt),    // a job
		autoFrame(uuid.New().String(), "p", "fresh", "restart", "ok", nil, frameAt),    // never deployed here
	}
	wrongContainer := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	wrongContainer["container"] = "q-web"
	prefixed := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	prefixed["container"] = "deploybot-p-web"
	long := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	long["reason"] = strings.Repeat("x", 201)
	ctl := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	ctl["reason"] = "unhealthy\nfor 1s"
	extra := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	extra["by"] = user.ID.String()
	badT := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	badT["t"] = "yesterday"
	invalid = append(invalid, wrongContainer, prefixed, long, ctl, extra, badT)
	for i, f := range invalid {
		sendAuto(f)
		expectAck(t, conn, f["id"].(string))
		after := counts()
		for id, n := range before {
			if after[id] != n {
				t.Fatalf("invalid frame %d stored a row", i)
			}
		}
	}
	for _, p := range []uuid.UUID{other.ID, viewer.ID} {
		if len(autoAudits(t, st, p)) != 0 {
			t.Fatal("unrelated project received an audit row")
		}
	}
	if len(autoAudits(t, st, project.ID)) != auditsBefore {
		t.Fatal("invalid frame wrote an audit row")
	}
	// No usable id: nothing to acknowledge.
	sendAuto(autoFrame("not-a-uuid", "p", "web", "restart", "ok", nil, frameAt))
	expectQuiet(t, conn)
	// A 200-byte reason is accepted.
	edge := autoFrame(uuid.New().String(), "p", "web", "restart", "ok", nil, frameAt)
	edge["reason"] = strings.Repeat("x", 200)
	sendAuto(edge)
	expectAck(t, conn, edge["id"].(string))

	// Rate: 20 stored agent rows per (entry, host) per rolling hour. web already
	// has 3 (restart, auto_failed, edge) this hour. History lists at most 20
	// automatic rows, so the 21st is checked through the audit count.
	agentRows := func() int {
		n := 0
		for _, r := range rows(web.ID) {
			if r.Via == "agent" {
				n++
			}
		}
		return n
	}
	for agentRows() < 20 {
		clock.add(time.Second)
		id := uuid.New().String()
		sendAuto(autoFrame(id, "p", "web", "restart", "ok", nil, frameAt))
		expectAck(t, conn, id)
	}
	auditsAt20 := len(autoAudits(t, st, project.ID))
	over := uuid.New().String()
	sendAuto(autoFrame(over, "p", "web", "restart", "ok", nil, frameAt))
	expectAck(t, conn, over)
	over2 := uuid.New().String()
	sendAuto(autoFrame(over2, "p", "web", "restart", "ok", nil, frameAt))
	expectAck(t, conn, over2)
	if agentRows() != 20 || len(autoAudits(t, st, project.ID)) != auditsAt20 {
		t.Fatal("the 21st or 22nd frame within an hour was stored")
	}
	if n := strings.Count(logBuf.String(), "reason=rate"); n != 1 {
		t.Fatalf("cap warn lines %d over two over-cap frames:\n%s", n, logBuf.String())
	}
	// Another entry on the same host is not capped by web's count.
	clock.add(time.Second)
	otherEntry := uuid.New().String()
	sendAuto(autoFrame(otherEntry, "p", "roll", "rollback", "ok", nil, frameAt))
	expectAck(t, conn, otherEntry)
	if len(rows(roll.ID)) != 4 {
		t.Fatal("cap on one entry blocked another")
	}
	// An hour later the window has moved.
	clock.add(time.Hour)
	later := uuid.New().String()
	sendAuto(autoFrame(later, "p", "web", "restart", "ok", nil, frameAt))
	expectAck(t, conn, later)
	if got := rows(web.ID); len(autoAudits(t, st, project.ID)) != auditsAt20+2 || !got[0].FinishedAt.Equal(now()) {
		t.Fatal("frame after the window was not stored")
	}
}
