package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	actOwnerViewer   = "owner_viewer"
	actOwnerAdmin    = "owner_admin"
	actOwnerOwner    = "owner_owner"
	actMetricsViewer = "metrics_viewer"
	actMetricsAdmin  = "metrics_admin"
	actDeployViewer  = "deploy_viewer"
	actDeployAdmin   = "deploy_admin"
	actNone          = "none"
)

// shareActors is every §4 column that has a phase-1 route.
// owner_admin and owner_owner are both admin+: a check for only one of those
// role strings fails one of them. metrics_admin matches metrics_viewer on
// every cell except leaving the share.
var shareActors = []string{
	actOwnerViewer, actOwnerAdmin, actOwnerOwner,
	actMetricsViewer, actMetricsAdmin,
	actDeployViewer, actDeployAdmin, actNone,
}

func cellWant(ownerViewer, ownerAdmin, metrics, deployViewer, deployAdmin, none int) map[string]int {
	return map[string]int{
		actOwnerViewer:   ownerViewer,
		actOwnerAdmin:    ownerAdmin,
		actOwnerOwner:    ownerAdmin,
		actMetricsViewer: metrics,
		actMetricsAdmin:  metrics,
		actDeployViewer:  deployViewer,
		actDeployAdmin:   deployAdmin,
		actNone:          none,
	}
}

type shareFixture struct {
	w                     *world
	sc                    scene
	home, metrics, deploy store.Project
	ownerSvc, shareSvc    store.Service
	tok                   map[string]string
}

func newShareFixture(t *testing.T) *shareFixture {
	t.Helper()
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	metricsViewer := w.user("metrics-viewer@ex.com", "MetricsViewer")
	metricsAdmin := w.user("metrics-admin@ex.com", "MetricsAdmin")
	deployViewer := w.user("deploy-viewer@ex.com", "DeployViewer")
	deployOwner := w.user("deploy-owner@ex.com", "DeployOwner")
	deployAdmin := w.user("deploy-admin@ex.com", "DeployAdmin")
	outsider := w.user("outsider@ex.com", "Outsider")
	sc := w.scene(owner, admin, viewer, spare, extra)
	metrics, err := w.mem.CreateProject(ctx, metricsViewer.ID, "Metrics", "metrics", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, metrics.ID, metricsAdmin.ID, "admin", metricsViewer.ID, w.now); err != nil {
		t.Fatal(err)
	}
	deploy, err := w.mem.CreateProject(ctx, deployOwner.ID, "Deploy", "deploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployAdmin.ID, "admin", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployViewer.ID, "viewer", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, metrics.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	shareSvc := w.mem.PutDeclared(sc.host.ID, "web", "process", []int{8080}, w.now)
	w.mem.SetServiceProject(shareSvc.ID, deploy.ID)
	samples := []store.Sample{
		procSample(w.now, 11, "api"),
		procSample(w.now, 22, "web"),
		procSample(w.now, 33, ""),
	}
	if _, err := w.mem.InsertBatch(ctx, sc.host.ID, uuid.New(), samples, w.now); err != nil {
		t.Fatal(err)
	}
	return &shareFixture{
		w: w, sc: sc, home: sc.project, metrics: metrics, deploy: deploy,
		ownerSvc: sc.svc, shareSvc: shareSvc,
		tok: map[string]string{
			actOwnerViewer:   w.token(viewer.ID),
			actOwnerAdmin:    w.token(admin.ID),
			actOwnerOwner:    w.token(owner.ID),
			actMetricsViewer: w.token(metricsViewer.ID),
			actMetricsAdmin:  w.token(metricsAdmin.ID),
			actDeployViewer:  w.token(deployViewer.ID),
			actDeployAdmin:   w.token(deployAdmin.ID),
			actNone:          w.token(outsider.ID),
		},
	}
}

func (fx *shareFixture) do(actor, method, path, body string) (int, envelope) {
	return fx.w.do(fx.tok[actor], method, path, body)
}

func (fx *shareFixture) projectID(actor string) string {
	switch actor {
	case actMetricsViewer, actMetricsAdmin:
		return fx.metrics.ID.String()
	case actDeployViewer, actDeployAdmin:
		return fx.deploy.ID.String()
	default:
		return fx.home.ID.String()
	}
}

func (fx *shareFixture) hostPath(suffix string) string {
	return "/v1/hosts/" + fx.sc.host.ID.String() + suffix
}

func (fx *shareFixture) servicePath(svc store.Service, suffix string) string {
	return "/v1/services/" + svc.ID.String() + suffix
}

// TestSharePermissionMatrix covers every phase-1 cell of spec §4 on the real
// mux and memstore. Phase 2 logs and deploy have no routes. Revoke 200 is
// TestShareRevoke, because a successful revoke kills the shared host.
func TestSharePermissionMatrix(t *testing.T) {
	fx := newShareFixture(t)
	answerTasks(fx.w.hello(fx.sc))
	const (
		ok   = http.StatusOK
		no   = http.StatusForbidden
		miss = http.StatusNotFound
	)
	health := `{"checks":[{"protocol":"http","port":8080,"path":"/"}]}`
	probe := `{"protocol":"http","port":8080,"path":"/"}`
	cells := []struct {
		name  string
		want  map[string]int
		call  func(actor string) (int, envelope)
		check func(t *testing.T, actor string, env envelope)
	}{
		{
			name: "see host in project list and status",
			want: cellWant(ok, ok, ok, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, "/v1/projects/"+fx.projectID(actor)+"/hosts", "")
			},
			check: func(t *testing.T, actor string, env envelope) {
				assertListedHost(t, fx, actor, env)
				code, got := fx.do(actor, http.MethodGet, fx.hostPath(""), "")
				if code != http.StatusOK {
					t.Fatalf("GET host %d %s", code, got.Code)
				}
				assertGotHost(t, fx, actor, got)
			},
		},
		{
			name: "host metrics",
			want: cellWant(ok, ok, ok, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.hostPath("/metrics?m=cpu"), "")
			},
		},
		{
			name: "processes list",
			want: cellWant(ok, ok, ok, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.hostPath("/processes"), "")
			},
			check: func(t *testing.T, actor string, env envelope) {
				assertProcessPIDs(t, fx, actor, env)
			},
		},
		{
			name: "snapshot",
			want: cellWant(ok, ok, ok, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodPost, fx.hostPath("/snapshot"), "")
			},
		},
		{
			name: "services list filtered",
			want: cellWant(ok, ok, no, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.hostPath("/services"), "")
			},
			check: func(t *testing.T, actor string, env envelope) {
				assertServiceNames(t, fx, actor, env)
			},
		},
		{
			name: "get host",
			want: cellWant(ok, ok, ok, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.hostPath(""), "")
			},
			check: func(t *testing.T, actor string, env envelope) {
				assertGotHost(t, fx, actor, env)
			},
		},
		{
			name: "get share-project service",
			want: cellWant(ok, ok, no, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.servicePath(fx.shareSvc, ""), "")
			},
		},
		{
			name: "get owner-project service",
			want: cellWant(ok, ok, no, no, no, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.servicePath(fx.ownerSvc, ""), "")
			},
		},
		{
			name: "probe own service",
			want: cellWant(ok, ok, no, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodPost, fx.servicePath(fx.shareSvc, "/probe"), probe)
			},
		},
		{
			name: "probe other service",
			want: cellWant(ok, ok, no, no, no, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodPost, fx.servicePath(fx.ownerSvc, "/probe"), probe)
			},
		},
		{
			name: "health history own service",
			want: cellWant(ok, ok, no, ok, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.servicePath(fx.shareSvc, "/health"), "")
			},
		},
		{
			name: "health history other service",
			want: cellWant(ok, ok, no, no, no, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.servicePath(fx.ownerSvc, "/health"), "")
			},
		},
		{
			name: "edit health checks own service",
			want: cellWant(no, ok, no, no, ok, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodPut, fx.servicePath(fx.shareSvc, "/health-checks"), health)
			},
		},
		{
			name: "edit health checks other service",
			want: cellWant(no, ok, no, no, no, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodPut, fx.servicePath(fx.ownerSvc, "/health-checks"), health)
			},
		},
		{
			name: "manage shares",
			want: cellWant(no, ok, no, no, no, miss),
			call: func(actor string) (int, envelope) {
				return fx.do(actor, http.MethodGet, fx.hostPath("/shares"), "")
			},
			check: func(t *testing.T, actor string, env envelope) {
				ids := map[string]bool{}
				for _, item := range listItems(t, env) {
					ids[item["project_id"].(string)] = true
				}
				if !ids[fx.metrics.ID.String()] || !ids[fx.deploy.ID.String()] {
					t.Fatalf("%s shares %#v", actor, ids)
				}
			},
		},
	}
	for _, cell := range cells {
		for _, actor := range shareActors {
			t.Run(cell.name+"/"+actor, func(t *testing.T) {
				status, env := cell.call(actor)
				assertHTTP(t, status, env, cell.want[actor])
				if cell.want[actor] == http.StatusOK && cell.check != nil {
					cell.check(t, actor, env)
				}
			})
		}
	}
}

func TestShareRevoke(t *testing.T) {
	fx := newShareFixture(t)
	cases := []struct {
		actor string
		want  int
	}{
		{actOwnerViewer, http.StatusForbidden},
		{actOwnerAdmin, http.StatusOK},
		{actOwnerOwner, http.StatusOK},
		{actMetricsViewer, http.StatusForbidden},
		{actMetricsAdmin, http.StatusForbidden},
		{actDeployViewer, http.StatusForbidden},
		{actDeployAdmin, http.StatusForbidden},
		{actNone, http.StatusNotFound},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.actor, func(t *testing.T) {
			host := enrollHost(t, fx.w, fx.home, fx.sc.project.CreatedBy, "revoke-"+tc.actor)
			switch tc.actor {
			case actMetricsViewer, actMetricsAdmin:
				if _, _, err := fx.w.mem.PutHostShare(ctx, host.ID, fx.metrics.ID, "metrics", fx.sc.project.CreatedBy, fx.w.now); err != nil {
					t.Fatal(err)
				}
			case actDeployViewer, actDeployAdmin:
				if _, _, err := fx.w.mem.PutHostShare(ctx, host.ID, fx.deploy.ID, "deploy", fx.sc.project.CreatedBy, fx.w.now); err != nil {
					t.Fatal(err)
				}
			}
			status, env := fx.do(tc.actor, http.MethodDelete, "/v1/hosts/"+host.ID.String()+"/credential", "")
			assertHTTP(t, status, env, tc.want)
			got, err := fx.w.mem.GetHost(ctx, host.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == http.StatusOK {
				if got.RevokedAt == nil {
					t.Fatal("credential still live")
				}
			} else if got.RevokedAt != nil {
				t.Fatal("denied revoke revoked the credential")
			}
		})
	}
}

func TestShareLeave(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	metricsOwner := w.user("metrics-owner@ex.com", "MetricsOwner")
	metricsViewer := w.user("metrics-viewer@ex.com", "MetricsViewer")
	metricsAdmin := w.user("metrics-admin@ex.com", "MetricsAdmin")
	deployOwner := w.user("deploy-owner@ex.com", "DeployOwner")
	deployViewer := w.user("deploy-viewer@ex.com", "DeployViewer")
	deployAdmin := w.user("deploy-admin@ex.com", "DeployAdmin")
	outsider := w.user("out@ex.com", "Out")
	metrics, err := w.mem.CreateProject(ctx, metricsOwner.ID, "Metrics", "metrics", w.now)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := w.mem.CreateProject(ctx, deployOwner.ID, "Deploy", "deploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, add := range []struct {
		project store.Project
		user    store.User
		role    string
		by      uuid.UUID
	}{
		{metrics, metricsViewer, "viewer", metricsOwner.ID},
		{metrics, metricsAdmin, "admin", metricsOwner.ID},
		{deploy, deployViewer, "viewer", deployOwner.ID},
		{deploy, deployAdmin, "admin", deployOwner.ID},
	} {
		if _, err := w.mem.AddMember(ctx, add.project.ID, add.user.ID, add.role, add.by, w.now); err != nil {
			t.Fatal(err)
		}
	}
	hostM := enrollHost(t, w, sc.project, owner.ID, "metrics-host")
	hostD := enrollHost(t, w, sc.project, owner.ID, "deploy-host")
	if _, _, err := w.mem.PutHostShare(ctx, hostM.ID, metrics.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, hostD.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	tok := map[string]string{
		"metrics_viewer": w.token(metricsViewer.ID),
		"metrics_admin":  w.token(metricsAdmin.ID),
		"deploy_viewer":  w.token(deployViewer.ID),
		"deploy_admin":   w.token(deployAdmin.ID),
		"owner_viewer":   w.token(viewer.ID),
		"none":           w.token(outsider.ID),
	}
	type leave struct {
		name string
		host store.Host
		want int
	}
	// Viewer attempts run first so the share is still there for the admin.
	steps := []leave{
		{"metrics_viewer", hostM, http.StatusForbidden},
		{"owner_viewer", hostM, http.StatusForbidden},
		{"none", hostM, http.StatusNotFound},
		{"metrics_admin", hostM, http.StatusOK},
		{"deploy_viewer", hostD, http.StatusForbidden},
		{"deploy_admin", hostD, http.StatusOK},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			path := "/v1/hosts/" + step.host.ID.String() + "/shares/"
			if step.name == "deploy_viewer" || step.name == "deploy_admin" {
				path += deploy.ID.String()
			} else if step.name == "none" {
				path += metrics.ID.String()
			} else {
				path += metrics.ID.String()
			}
			status, env := w.do(tok[step.name], http.MethodDelete, path, "")
			assertHTTP(t, status, env, step.want)
		})
	}
	if status, env := w.do(tok["metrics_viewer"], http.MethodGet, "/v1/hosts/"+hostM.ID.String(), ""); status != http.StatusNotFound {
		t.Fatalf("metrics host after leave: %d %s", status, env.Code)
	}
	if status, env := w.do(tok["deploy_viewer"], http.MethodGet, "/v1/hosts/"+hostD.ID.String(), ""); status != http.StatusNotFound {
		t.Fatalf("deploy host after leave: %d %s", status, env.Code)
	}
}

func TestOwnerAdminUnsharesForeignProject(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	foreignOwner := w.user("foreign@ex.com", "Foreign")
	foreign, err := w.mem.CreateProject(ctx, foreignOwner.ID, "Foreign", "foreign", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.Role(ctx, foreign.ID, admin.ID); err == nil {
		t.Fatal("owner admin is a member of the target")
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, foreign.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	status, env := w.do(w.token(admin.ID), http.MethodDelete, "/v1/hosts/"+sc.host.ID.String()+"/shares/"+foreign.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	shares, err := w.mem.ListHostShares(ctx, sc.host.ID)
	if err != nil || len(shares) != 0 {
		t.Fatalf("shares left: %v %+v", err, shares)
	}
}

func TestOwnerWinsOverShare(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	both := w.user("both@ex.com", "Both")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	if _, err := w.mem.AddMember(ctx, sc.project.ID, both.ID, "viewer", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	deployOwner := w.user("deploy-owner@ex.com", "DeployOwner")
	deploy, err := w.mem.CreateProject(ctx, deployOwner.ID, "Deploy", "deploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, both.ID, "admin", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	shareSvc := w.mem.PutDeclared(sc.host.ID, "web", "process", []int{8080}, w.now)
	w.mem.SetServiceProject(shareSvc.ID, deploy.ID)
	tok := w.token(both.ID)
	status, env := w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	host := objectPayload(t, env)
	_, levelPresent := host["share_level"]
	if host["relation"] != "owner" || !levelPresent || host["share_level"] != nil {
		t.Fatalf("relation %#v share_level %#v present %v", host["relation"], host["share_level"], levelPresent)
	}
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String()+"/services", "")
	assertHTTP(t, status, env, http.StatusOK)
	names := map[string]bool{}
	for _, item := range listItems(t, env) {
		names[item["name"].(string)] = true
	}
	if !names["api"] || !names["web"] {
		t.Fatalf("services %#v", names)
	}
	// Listing the sharing project is still "shared": relation is project-relative.
	status, env = w.do(tok, http.MethodGet, "/v1/projects/"+deploy.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	listed := findItem(t, listItems(t, env), "id", sc.host.ID.String())
	if listed["relation"] != "shared" || listed["share_level"] != "deploy" {
		t.Fatalf("project list %#v", listed)
	}
	status, env = w.do(tok, http.MethodDelete, "/v1/hosts/"+sc.host.ID.String()+"/shares/"+deploy.ID.String()+"?reassign=owner", "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	if objectPayload(t, env)["relation"] != "owner" {
		t.Fatal("still an owner viewer after leaving the share")
	}
}

func TestHostListOrdersOwnedThenShared(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	homeOwner := w.user("home@ex.com", "Home")
	otherOwner := w.user("other@ex.com", "Other")
	thirdOwner := w.user("third@ex.com", "Third")
	home, err := w.mem.CreateProject(ctx, homeOwner.ID, "Home", "home", w.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.mem.CreateProject(ctx, otherOwner.ID, "Other", "other", w.now)
	if err != nil {
		t.Fatal(err)
	}
	third, err := w.mem.CreateProject(ctx, thirdOwner.ID, "Third", "third", w.now)
	if err != nil {
		t.Fatal(err)
	}
	aOther := enrollHost(t, w, other, otherOwner.ID, "a-other")
	zOther := enrollHost(t, w, other, otherOwner.ID, "z-other")
	mHome := enrollHost(t, w, home, homeOwner.ID, "m-home")
	aHome := enrollHost(t, w, home, homeOwner.ID, "a-home")
	cShared := enrollHost(t, w, third, thirdOwner.ID, "c-shared")
	if _, _, err := w.mem.PutHostShare(ctx, mHome.ID, other.ID, "metrics", homeOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, cShared.ID, other.ID, "deploy", thirdOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	tok := w.token(otherOwner.ID)
	status, env := w.do(tok, http.MethodGet, "/v1/projects/"+other.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	items := listItems(t, env)
	want := []struct {
		id, relation string
		level        any
	}{
		{aOther.ID.String(), "owner", nil},
		{zOther.ID.String(), "owner", nil},
		{cShared.ID.String(), "shared", "deploy"},
		{mHome.ID.String(), "shared", "metrics"},
	}
	if len(items) != len(want) {
		t.Fatalf("len %d", len(items))
	}
	for i, exp := range want {
		if items[i]["id"] != exp.id || items[i]["relation"] != exp.relation || items[i]["share_level"] != exp.level {
			t.Fatalf("item %d %#v", i, items[i])
		}
		if items[i]["project_id"] == other.ID.String() && exp.relation == "shared" {
			t.Fatalf("shared host kept the listing project id: %#v", items[i]["project_id"])
		}
	}
	homeTok := w.token(homeOwner.ID)
	status, env = w.do(homeTok, http.MethodGet, "/v1/projects/"+home.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	homeItems := listItems(t, env)
	if len(homeItems) != 2 || homeItems[0]["id"] != aHome.ID.String() || homeItems[1]["id"] != mHome.ID.String() {
		t.Fatalf("home list %#v", namesOf(homeItems))
	}
	if _, present := homeItems[0]["share_level"]; homeItems[0]["relation"] != "owner" || !present || homeItems[0]["share_level"] != nil {
		t.Fatalf("owned row %#v", homeItems[0])
	}
}

func TestShareCRUDAuditAndUnshare(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	guestOwner := w.user("guest@ex.com", "Guest")
	secretOwner := w.user("secret@ex.com", "Secret")
	guest, err := w.mem.CreateProject(ctx, guestOwner.ID, "Guest", "guest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := w.mem.CreateProject(ctx, secretOwner.ID, "Secret", "secret", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, guest.ID, owner.ID, "viewer", guestOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, guest.ID, admin.ID, "viewer", guestOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	ownerTok := w.token(owner.ID)
	adminTok := w.token(admin.ID)
	viewerTok := w.token(viewer.ID)
	outsiderTok := w.token(secretOwner.ID)
	guestTok := w.token(guestOwner.ID)
	sharePath := "/v1/hosts/" + sc.host.ID.String() + "/shares/" + guest.ID.String()
	body := `{"level":"deploy"}`

	status, env := w.do(outsiderTok, http.MethodPut, sharePath, body)
	assertHTTP(t, status, env, http.StatusNotFound)
	status, env = w.do(viewerTok, http.MethodPut, sharePath, body)
	assertHTTP(t, status, env, http.StatusForbidden)
	status, env = w.do(ownerTok, http.MethodPut, "/v1/hosts/"+sc.host.ID.String()+"/shares/"+secret.ID.String(), body)
	assertHTTP(t, status, env, http.StatusNotFound)
	secretMsg := env.Msg
	status, env = w.do(ownerTok, http.MethodPut, "/v1/hosts/"+sc.host.ID.String()+"/shares/"+uuid.New().String(), body)
	assertHTTP(t, status, env, http.StatusNotFound)
	if env.Msg != secretMsg {
		t.Fatalf("enumeration msgs %q and %q", secretMsg, env.Msg)
	}
	status, env = w.do(ownerTok, http.MethodPut, "/v1/hosts/"+sc.host.ID.String()+"/shares/"+sc.project.ID.String(), body)
	assertHTTP(t, status, env, http.StatusBadRequest)
	if env.Msg != "cannot share with the owning project" {
		t.Fatalf("owner share msg %q", env.Msg)
	}
	status, env = w.do(ownerTok, http.MethodPut, sharePath, `{"level":"admin"}`)
	assertHTTP(t, status, env, http.StatusBadRequest)
	if env.Msg != "invalid level" {
		t.Fatalf("level msg %q", env.Msg)
	}

	status, env = w.do(ownerTok, http.MethodPut, sharePath, body)
	assertHTTP(t, status, env, http.StatusOK)
	created := objectPayload(t, env)
	if created["level"] != "deploy" || created["project_id"] != guest.ID.String() || created["project_name"] != "Guest" || created["created_by"] != owner.ID.String() {
		t.Fatalf("created %#v", created)
	}
	status, env = w.do(guestTok, http.MethodPut, sharePath, `{"level":"metrics"}`)
	assertHTTP(t, status, env, http.StatusForbidden)
	status, env = w.do(adminTok, http.MethodPut, sharePath, `{"level":"metrics"}`)
	assertHTTP(t, status, env, http.StatusOK)
	updated := objectPayload(t, env)
	if updated["level"] != "metrics" || updated["created_by"] != created["created_by"] || updated["created_at"] != created["created_at"] {
		t.Fatalf("update kept creator? created %#v updated %#v", created, updated)
	}
	status, env = w.do(ownerTok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String()+"/shares", "")
	assertHTTP(t, status, env, http.StatusOK)
	if _, ok := env.Payload.(map[string]any)["next_cursor"]; ok {
		t.Fatal("share list is paginated")
	}
	items := listItems(t, env)
	if len(items) != 1 || items[0]["project_id"] != guest.ID.String() || items[0]["level"] != "metrics" {
		t.Fatalf("items %#v", items)
	}
	status, env = w.do(viewerTok, http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	if findItem(t, listItems(t, env), "id", sc.host.ID.String())["relation"] != "owner" {
		t.Fatal("owner list relation")
	}
	status, env = w.do(guestTok, http.MethodGet, "/v1/projects/"+guest.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	listed := findItem(t, listItems(t, env), "id", sc.host.ID.String())
	if listed["relation"] != "shared" || listed["share_level"] != "metrics" || listed["project_id"] != sc.project.ID.String() {
		t.Fatalf("shared list %#v", listed)
	}

	status, env = w.do(ownerTok, http.MethodDelete, sharePath+"?reassign=nope", "")
	assertHTTP(t, status, env, http.StatusBadRequest)
	if env.Msg != "invalid reassign" {
		t.Fatalf("reassign msg %q", env.Msg)
	}
	w.mem.SetServiceProject(sc.svc.ID, guest.ID)
	status, env = w.do(ownerTok, http.MethodDelete, sharePath, "")
	assertHTTP(t, status, env, http.StatusConflict)
	status, env = w.do(ownerTok, http.MethodGet, "/v1/services/"+sc.svc.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	if objectPayload(t, env)["project_id"] != guest.ID.String() {
		t.Fatalf("service moved on 409: %#v", objectPayload(t, env)["project_id"])
	}
	status, env = w.do(ownerTok, http.MethodDelete, sharePath+"?reassign=owner", "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(ownerTok, http.MethodGet, "/v1/services/"+sc.svc.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	if objectPayload(t, env)["project_id"] != sc.project.ID.String() {
		t.Fatalf("reassign project %#v", objectPayload(t, env)["project_id"])
	}
	status, env = w.do(guestTok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	assertHTTP(t, status, env, http.StatusNotFound)

	status, env = w.do(ownerTok, http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/audit", "")
	assertHTTP(t, status, env, http.StatusOK)
	got := map[string]map[string]any{}
	for _, item := range listItems(t, env) {
		if item["decision"] != audit.DecisionAllowed {
			continue
		}
		action, _ := item["action"].(string)
		detail, _ := item["detail"].(map[string]any)
		if action == audit.ActionHostShare || action == audit.ActionHostShareUpdate || action == audit.ActionHostUnshare {
			got[action] = detail
		}
	}
	for _, action := range []string{audit.ActionHostShare, audit.ActionHostShareUpdate, audit.ActionHostUnshare} {
		detail := got[action]
		if detail["project_id"] != guest.ID.String() || detail["project_name"] != "Guest" || detail["level"] == nil {
			t.Fatalf("%s detail %#v", action, detail)
		}
	}
	if got[audit.ActionHostShare]["level"] != "deploy" || got[audit.ActionHostShareUpdate]["level"] != "metrics" || got[audit.ActionHostUnshare]["level"] != "metrics" {
		t.Fatalf("levels %#v", got)
	}
	if got[audit.ActionHostUnshare]["reassign"] != "owner" {
		t.Fatalf("unshare detail %#v", got[audit.ActionHostUnshare])
	}
}

func TestProjectDeleteCascadesShares(t *testing.T) {
	t.Run("sharing project", func(t *testing.T) {
		w := newWorld(t)
		ctx := context.Background()
		owner := w.user("owner@ex.com", "Owner")
		admin := w.user("admin@ex.com", "Admin")
		viewer := w.user("viewer@ex.com", "Viewer")
		spare := w.user("spare@ex.com", "Spare")
		extra := w.user("extra@ex.com", "Extra")
		sc := w.scene(owner, admin, viewer, spare, extra)
		guestOwner := w.user("guest@ex.com", "Guest")
		guest, err := w.mem.CreateProject(ctx, guestOwner.ID, "Guest", "guest", w.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.mem.AddMember(ctx, guest.ID, owner.ID, "viewer", guestOwner.ID, w.now); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, guest.ID, "deploy", owner.ID, w.now); err != nil {
			t.Fatal(err)
		}
		w.mem.SetServiceProject(sc.svc.ID, guest.ID)
		status, env := w.do(w.token(guestOwner.ID), http.MethodDelete, "/v1/projects/"+guest.ID.String(), "")
		assertHTTP(t, status, env, http.StatusOK)
		shares, err := w.mem.ListHostShares(ctx, sc.host.ID)
		if err != nil || len(shares) != 0 {
			t.Fatalf("shares: %v %+v", err, shares)
		}
		svc, err := w.mem.GetService(ctx, sc.svc.ID, w.now)
		if err != nil || svc.ProjectID != sc.project.ID {
			t.Fatalf("service project %s err %v", svc.ProjectID, err)
		}
		host, err := w.mem.GetHost(ctx, sc.host.ID)
		if err != nil || host.RevokedAt != nil {
			t.Fatalf("owning host revoked: %v", host.RevokedAt)
		}
		if status, env := w.do(w.token(guestOwner.ID), http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), ""); status != http.StatusNotFound {
			t.Fatalf("former share member: %d %s", status, env.Code)
		}
	})

	t.Run("owning project", func(t *testing.T) {
		w := newWorld(t)
		ctx := context.Background()
		owner := w.user("owner@ex.com", "Owner")
		admin := w.user("admin@ex.com", "Admin")
		viewer := w.user("viewer@ex.com", "Viewer")
		spare := w.user("spare@ex.com", "Spare")
		extra := w.user("extra@ex.com", "Extra")
		sc := w.scene(owner, admin, viewer, spare, extra)
		guestOwner := w.user("guest@ex.com", "Guest")
		guest, err := w.mem.CreateProject(ctx, guestOwner.ID, "Guest", "guest", w.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, guest.ID, "metrics", owner.ID, w.now); err != nil {
			t.Fatal(err)
		}
		shareSvc := w.mem.PutDeclared(sc.host.ID, "web", "process", []int{8080}, w.now)
		w.mem.SetServiceProject(shareSvc.ID, guest.ID)
		guestTok := w.token(guestOwner.ID)
		if status, env := w.do(guestTok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), ""); status != http.StatusOK {
			t.Fatalf("before delete %d %s", status, env.Code)
		}
		status, env := w.do(w.token(owner.ID), http.MethodDelete, "/v1/projects/"+sc.project.ID.String(), "")
		assertHTTP(t, status, env, http.StatusOK)
		host, err := w.mem.GetHost(ctx, sc.host.ID)
		if err != nil || host.RevokedAt == nil {
			t.Fatalf("credential not revoked: %v", err)
		}
		shares, err := w.mem.ListHostShares(ctx, sc.host.ID)
		if err != nil || len(shares) != 0 {
			t.Fatalf("shares: %v %+v", err, shares)
		}
		svc, err := w.mem.GetService(ctx, shareSvc.ID, w.now)
		if err != nil || svc.ProjectID != guest.ID {
			t.Fatalf("guest service project %s err %v", svc.ProjectID, err)
		}
		if status, env := w.do(guestTok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), ""); status != http.StatusNotFound {
			t.Fatalf("share member after owner delete: %d %s", status, env.Code)
		}
	})
}

func assertHTTP(t *testing.T, status int, env envelope, want int) {
	t.Helper()
	wantCode := map[int]string{
		http.StatusOK:         "ok",
		http.StatusBadRequest: "bad_request",
		http.StatusForbidden:  "forbidden",
		http.StatusNotFound:   "not_found",
		http.StatusConflict:   "conflict",
	}[want]
	if status != want || env.Code != wantCode {
		t.Fatalf("status %d code %s msg %s, want %d %s", status, env.Code, env.Msg, want, wantCode)
	}
}

func assertListedHost(t *testing.T, fx *shareFixture, actor string, env envelope) {
	t.Helper()
	item := findItem(t, listItems(t, env), "id", fx.sc.host.ID.String())
	assertRelation(t, fx, actor, item)
	if item["status"] == "" {
		t.Fatal("empty status")
	}
}

func assertGotHost(t *testing.T, fx *shareFixture, actor string, env envelope) {
	t.Helper()
	item := objectPayload(t, env)
	assertRelation(t, fx, actor, item)
	if item["project_id"] != fx.home.ID.String() {
		t.Fatalf("project_id %#v", item["project_id"])
	}
	if item["status"] == "" {
		t.Fatal("empty status")
	}
}

func assertRelation(t *testing.T, fx *shareFixture, actor string, item map[string]any) {
	t.Helper()
	switch actor {
	case actOwnerViewer, actOwnerAdmin, actOwnerOwner:
		_, present := item["share_level"]
		if item["relation"] != "owner" || !present || item["share_level"] != nil {
			t.Fatalf("%s relation %#v level %#v present %v", actor, item["relation"], item["share_level"], present)
		}
	case actMetricsViewer, actMetricsAdmin:
		if item["relation"] != "shared" || item["share_level"] != "metrics" {
			t.Fatalf("%s relation %#v level %#v", actor, item["relation"], item["share_level"])
		}
	case actDeployViewer, actDeployAdmin:
		if item["relation"] != "shared" || item["share_level"] != "deploy" {
			t.Fatalf("%s relation %#v level %#v", actor, item["relation"], item["share_level"])
		}
	default:
		t.Fatalf("no relation for %s", actor)
	}
	if actor != actOwnerViewer && actor != actOwnerAdmin && actor != actOwnerOwner && item["project_id"] != fx.home.ID.String() {
		t.Fatalf("owning project_id %#v", item["project_id"])
	}
}

func assertServiceNames(t *testing.T, fx *shareFixture, actor string, env envelope) {
	t.Helper()
	got := map[string]string{}
	for _, item := range listItems(t, env) {
		got[item["name"].(string)] = item["project_id"].(string)
	}
	switch actor {
	case actOwnerViewer, actOwnerAdmin, actOwnerOwner:
		if len(got) != 2 || got["api"] != fx.home.ID.String() || got["web"] != fx.deploy.ID.String() {
			t.Fatalf("%s services %#v", actor, got)
		}
	case actDeployViewer, actDeployAdmin:
		if len(got) != 1 || got["web"] != fx.deploy.ID.String() {
			t.Fatalf("%s services %#v", actor, got)
		}
	default:
		t.Fatalf("%s should not see services", actor)
	}
}

func assertProcessPIDs(t *testing.T, fx *shareFixture, actor string, env envelope) {
	t.Helper()
	got := map[int]any{}
	payload := objectPayload(t, env)
	items, _ := payload["items"].([]any)
	for _, raw := range items {
		item := raw.(map[string]any)
		got[int(item["pid"].(float64))] = item["service_id"]
	}
	// Full sample. service_id is the owner service, the deploy-share
	// service, or null when the process matches no service.
	want := map[int]any{
		11: fx.ownerSvc.ID.String(),
		22: fx.shareSvc.ID.String(),
		33: nil,
	}
	if len(got) != len(want) {
		t.Fatalf("%s pids %#v", actor, got)
	}
	for pid, svc := range want {
		if got[pid] != svc {
			t.Fatalf("%s pid %d service_id %#v, want %#v", actor, pid, got[pid], svc)
		}
	}
}

func listItems(t *testing.T, env envelope) []map[string]any {
	t.Helper()
	payload := objectPayload(t, env)
	raw, _ := payload["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("item %T", item)
		}
		out = append(out, m)
	}
	return out
}

func objectPayload(t *testing.T, env envelope) map[string]any {
	t.Helper()
	m, ok := env.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload %T", env.Payload)
	}
	return m
}

func findItem(t *testing.T, items []map[string]any, key, value string) map[string]any {
	t.Helper()
	for _, item := range items {
		if item[key] == value {
			return item
		}
	}
	t.Fatalf("no item %s=%s in %d", key, value, len(items))
	return nil
}

func namesOf(items []map[string]any) []string {
	out := make([]string, len(items))
	for i, item := range items {
		name, _ := item["name"].(string)
		id, _ := item["id"].(string)
		out[i] = name + ":" + id
	}
	return out
}

func procSample(at time.Time, pid int, service string) store.Sample {
	tags := map[string]string{
		"pid": strconv.Itoa(pid), "process_name": "p", "user": "root", "cmdline": "p",
	}
	if service != "" {
		tags["service"] = service
	}
	return store.Sample{
		M:      "process",
		T:      at,
		Tags:   tags,
		Floats: map[string]float64{"cpu_usage": 1, "memory_usage": 1},
		Ints:   map[string]int64{"memory_rss": 1, "num_threads": 1},
	}
}

func enrollHost(t *testing.T, w *world, project store.Project, ownerID uuid.UUID, name string) store.Host {
	t.Helper()
	ctx := context.Background()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.CreateJoinToken(ctx, project.ID, hash, nil, ownerID, w.now.Add(time.Hour), w.now); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := w.mem.ConsumeJoinToken(ctx, hash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, uuid.New(), credHash, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if host.Name != name {
		t.Fatalf("name %s", host.Name)
	}
	return host
}

func TestSeveralShares(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	mixed := w.user("mixed@ex.com", "Mixed")
	both := w.user("both@ex.com", "Both")
	home, err := w.mem.CreateProject(ctx, owner.ID, "Home", "home", w.now)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := w.mem.CreateProject(ctx, mixed.ID, "Metrics", "metrics", w.now)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := w.mem.CreateProject(ctx, owner.ID, "Deploy", "deploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	deploy2, err := w.mem.CreateProject(ctx, both.ID, "Deploy2", "deploy2", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, mixed.ID, "viewer", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, both.ID, "admin", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	host := enrollHost(t, w, home, owner.ID, "pi")
	if _, _, err := w.mem.PutHostShare(ctx, host.ID, metrics.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, host.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, host.ID, deploy2.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	api := w.mem.PutDeclared(host.ID, "api", "process", nil, w.now)
	met := w.mem.PutDeclared(host.ID, "met", "process", nil, w.now)
	web := w.mem.PutDeclared(host.ID, "web", "process", nil, w.now)
	web2 := w.mem.PutDeclared(host.ID, "web2", "process", nil, w.now)
	w.mem.SetServiceProject(met.ID, metrics.ID)
	w.mem.SetServiceProject(web.ID, deploy.ID)
	w.mem.SetServiceProject(web2.ID, deploy2.ID)

	mixedTok := w.token(mixed.ID)
	status, env := w.do(mixedTok, http.MethodGet, "/v1/hosts/"+host.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	got := objectPayload(t, env)
	if got["relation"] != "shared" || got["share_level"] != "deploy" {
		t.Fatalf("highest share %#v %#v", got["relation"], got["share_level"])
	}
	status, env = w.do(mixedTok, http.MethodGet, "/v1/hosts/"+host.ID.String()+"/metrics?m=cpu", "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(mixedTok, http.MethodGet, "/v1/hosts/"+host.ID.String()+"/services", "")
	assertHTTP(t, status, env, http.StatusOK)
	if names := serviceNameSet(t, env); len(names) != 1 || !names["web"] {
		t.Fatalf("mixed services %#v", names)
	}
	status, env = w.do(mixedTok, http.MethodGet, "/v1/services/"+web.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(mixedTok, http.MethodGet, "/v1/services/"+met.ID.String(), "")
	assertHTTP(t, status, env, http.StatusForbidden)
	status, env = w.do(mixedTok, http.MethodGet, "/v1/services/"+api.ID.String(), "")
	assertHTTP(t, status, env, http.StatusForbidden)

	bothTok := w.token(both.ID)
	status, env = w.do(bothTok, http.MethodGet, "/v1/hosts/"+host.ID.String()+"/services", "")
	assertHTTP(t, status, env, http.StatusOK)
	names := serviceNameSet(t, env)
	if len(names) != 2 || !names["web"] || !names["web2"] {
		t.Fatalf("two deploy services %#v", names)
	}
	status, env = w.do(bothTok, http.MethodGet, "/v1/services/"+web.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(bothTok, http.MethodGet, "/v1/services/"+web2.ID.String(), "")
	assertHTTP(t, status, env, http.StatusOK)
	status, env = w.do(bothTok, http.MethodGet, "/v1/services/"+api.ID.String(), "")
	assertHTTP(t, status, env, http.StatusForbidden)
	status, env = w.do(bothTok, http.MethodGet, "/v1/hosts/"+host.ID.String()+"/metrics?m=cpu", "")
	assertHTTP(t, status, env, http.StatusOK)
}

func TestHostListCursorResume(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	homeOwner := w.user("home@ex.com", "Home")
	boardOwner := w.user("board@ex.com", "Board")
	home, err := w.mem.CreateProject(ctx, homeOwner.ID, "Home", "home", w.now)
	if err != nil {
		t.Fatal(err)
	}
	board, err := w.mem.CreateProject(ctx, boardOwner.ID, "Board", "board", w.now)
	if err != nil {
		t.Fatal(err)
	}
	a := enrollHost(t, w, home, homeOwner.ID, "a-owned")
	b := enrollHost(t, w, home, homeOwner.ID, "b-owned")
	c := enrollHost(t, w, board, boardOwner.ID, "c-shared")
	z := enrollHost(t, w, board, boardOwner.ID, "z-shared")
	if _, _, err := w.mem.PutHostShare(ctx, c.ID, home.ID, "deploy", boardOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, z.ID, home.ID, "metrics", boardOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	boardTok := w.token(boardOwner.ID)
	status, env := w.do(boardTok, http.MethodGet, "/v1/projects/"+board.ID.String()+"/hosts", "")
	assertHTTP(t, status, env, http.StatusOK)
	for i, item := range listItems(t, env) {
		if item["relation"] != "owner" || item["share_level"] != nil {
			t.Fatalf("owning row %d %#v", i, item)
		}
	}
	tok := w.token(homeOwner.ID)
	path := "/v1/projects/" + home.ID.String() + "/hosts?limit=1"
	want := []string{a.ID.String(), b.ID.String(), c.ID.String(), z.ID.String()}
	var got []string
	for page := 0; page < len(want)+1; page++ {
		status, env = w.do(tok, http.MethodGet, path, "")
		assertHTTP(t, status, env, http.StatusOK)
		items := listItems(t, env)
		if len(items) == 0 {
			if _, ok := nextCursor(t, env); ok {
				t.Fatal("empty page has a cursor")
			}
			break
		}
		if len(items) != 1 {
			t.Fatalf("page %d len %d", page, len(items))
		}
		got = append(got, items[0]["id"].(string))
		cur, ok := nextCursor(t, env)
		if !ok {
			break
		}
		if items[0]["id"] == c.ID.String() {
			if _, err := w.mem.DeleteHostShare(ctx, c.ID, home.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		path = "/v1/projects/" + home.ID.String() + "/hosts?limit=1&cursor=" + cur
	}
	if len(got) != len(want) {
		t.Fatalf("resumed %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v want %v", got, want)
		}
	}
	old := encodeCursor(&store.Cursor{At: w.now, ID: a.ID.String()})
	if old == nil {
		t.Fatal("encode")
	}
	status, env = w.do(tok, http.MethodGet, "/v1/projects/"+home.ID.String()+"/hosts?cursor="+*old, "")
	assertHTTP(t, status, env, http.StatusBadRequest)
	if env.Msg != "invalid cursor" {
		t.Fatalf("old cursor msg %q", env.Msg)
	}
}

func TestHostCursorCodec(t *testing.T) {
	id := uuid.New().String()
	old := encodeCursor(&store.Cursor{At: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), ID: id})
	if _, err := decodeHostCursor(*old); err == nil {
		t.Fatal("time cursor decoded as a host cursor")
	}
	rank := 0
	next := encodeCursor(&store.Cursor{Rank: &rank, Name: "a-owned", ID: id})
	got, err := decodeHostCursor(*next)
	if err != nil || got.Rank == nil || *got.Rank != 0 || got.Name != "a-owned" || got.ID != id {
		t.Fatalf("%+v %v", got, err)
	}
	partial, err := json.Marshal(map[string]any{"rel_rank": 0, "id": id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHostCursor(base64.RawURLEncoding.EncodeToString(partial)); err == nil {
		t.Fatal("partial cursor decoded")
	}
}

func nextCursor(t *testing.T, env envelope) (string, bool) {
	t.Helper()
	raw, ok := objectPayload(t, env)["next_cursor"]
	if !ok || raw == nil {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		t.Fatalf("cursor %#v", raw)
	}
	return s, true
}

func serviceNameSet(t *testing.T, env envelope) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, item := range listItems(t, env) {
		out[item["name"].(string)] = true
	}
	return out
}
