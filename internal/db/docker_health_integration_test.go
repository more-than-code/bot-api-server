package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// TestDockerHealthQuery is the v1.11 services health query. It is skipped
// unless DEPLOYBOT_TEST_DATABASE_URL names the deploybot_test database.
func TestDockerHealthQuery(t *testing.T) {
	d, ctx := openPresenceDB(t)
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := uuid.New().String()[:8]
	user := mustSvcUser(t, d, ctx, "dh-"+tag, at)
	project := mustSvcProject(t, d, ctx, user.ID, "DH", "dh-"+tag, at)
	host := enrollHostDB(t, d, ctx, project.ID, user.ID, "dh-"+tag, at)

	freshDocker := insertLiveService(t, d, ctx, host.ID, project.ID, "fresh-docker", "container", "discovered", nil, nil, nil, at)
	checkWins := insertLiveService(t, d, ctx, host.ID, project.ID, "check-wins", "container", "discovered", nil, nil, nil, at)
	dockerOnly := insertLiveService(t, d, ctx, host.ID, project.ID, "docker-stale", "container", "discovered", nil, nil, nil, at)
	unhealthy := insertLiveService(t, d, ctx, host.ID, project.ID, "unhealthy", "container", "discovered", nil, nil, nil, at)
	edge := insertLiveService(t, d, ctx, host.ID, project.ID, "edge", "container", "discovered", nil, nil, nil, at)
	up := insertLiveService(t, d, ctx, host.ID, project.ID, "sort-up", "container", "discovered", nil, nil, nil, at)
	down := insertLiveService(t, d, ctx, host.ID, project.ID, "sort-down", "container", "discovered", nil, nil, nil, at)

	checkID := uuid.New()
	insertHealth(t, d, ctx, host.ID, freshDocker, "docker", "success", at.Add(-time.Minute), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, freshDocker, "http", "fail", at.Add(-30*time.Second), &checkID, intPtr(80), floatPtr(9))
	insertHealth(t, d, ctx, host.ID, checkWins, "docker", "success", at.Add(-store.HealthStale-time.Second), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, checkWins, "http", "success", at.Add(-20*time.Second), &checkID, intPtr(80), floatPtr(4.5))
	insertHealth(t, d, ctx, host.ID, dockerOnly, "docker", "success", at.Add(-store.HealthStale-time.Second), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, unhealthy, "docker", "unhealthy", at.Add(-time.Minute), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, edge, "docker", "success", at.Add(-store.HealthStale), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, up, "docker", "success", at.Add(-time.Minute), nil, nil, nil)
	insertHealth(t, d, ctx, host.ID, down, "", "fail", at.Add(-time.Minute), &checkID, intPtr(80), floatPtr(1))

	assertQueriedHealth(t, d, ctx, project.ID, freshDocker, at, "up", "docker", true)
	assertQueriedHealth(t, d, ctx, project.ID, checkWins, at, "up", "check", false)
	assertQueriedHealth(t, d, ctx, project.ID, dockerOnly, at, "unknown", "", true)
	assertQueriedHealth(t, d, ctx, project.ID, unhealthy, at, "down", "docker", true)
	assertQueriedHealth(t, d, ctx, project.ID, edge, at, "up", "docker", true)

	rows, err := d.HealthHistory(ctx, unhealthy, at.Add(-time.Hour), at.Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Protocol != "docker" || rows[0].Result != "unhealthy" || rows[0].CheckID != nil || rows[0].Port != nil || rows[0].HTTPStatus != nil || rows[0].LatencyMS != nil {
		t.Fatalf("history %+v %v", rows, err)
	}

	page, err := d.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, at)
	if err != nil {
		t.Fatal(err)
	}
	var upAt, downAt int
	for i, item := range page.Items {
		if item.ID == up {
			upAt = i
		}
		if item.ID == down {
			downAt = i
		}
	}
	if upAt >= downAt {
		t.Fatalf("status sort put docker up at %d and check down at %d", upAt, downAt)
	}
}

func assertQueriedHealth(t *testing.T, d *DB, ctx context.Context, project, service uuid.UUID, at time.Time, status, source string, latNil bool) {
	t.Helper()
	listed, err := d.ListServices(ctx, serviceHost(t, d, ctx, service), nil, at)
	if err != nil {
		t.Fatal(err)
	}
	var fromList store.Service
	found := false
	for _, item := range listed {
		if item.ID == service {
			fromList = item
			found = true
		}
	}
	if !found {
		t.Fatal("list missed the service")
	}
	got, err := d.GetService(ctx, service, at)
	if err != nil {
		t.Fatal(err)
	}
	page, err := d.ListProjectServices(ctx, project, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at)
	if err != nil {
		t.Fatal(err)
	}
	var fromPage store.Health
	found = false
	for _, item := range page.Items {
		if item.ID == service {
			fromPage = item.Health
			found = true
		}
	}
	if !found {
		t.Fatal("project list missed the service")
	}
	check := func(name string, h store.Health) {
		t.Helper()
		if h.Status != status {
			t.Fatalf("%s %s status %s", name, service, h.Status)
		}
		if source == "" {
			if h.Source != nil || h.LastCheckedAt != nil || h.LatencyMS != nil {
				t.Fatalf("%s %s unexpected row %+v", name, service, h)
			}
			return
		}
		if h.Source == nil || *h.Source != source || h.LastCheckedAt == nil {
			t.Fatalf("%s %s source %+v", name, service, h)
		}
		if latNil {
			if h.LatencyMS != nil {
				t.Fatalf("%s %s latency %v", name, service, *h.LatencyMS)
			}
			return
		}
		if h.LatencyMS == nil || *h.LatencyMS != 4.5 {
			t.Fatalf("%s %s latency %#v", name, service, h.LatencyMS)
		}
	}
	check("list", fromList.Health)
	check("get", got.Health)
	check("project", fromPage)
}

func serviceHost(t *testing.T, d *DB, ctx context.Context, service uuid.UUID) uuid.UUID {
	t.Helper()
	var host string
	if err := d.pool.QueryRow(ctx, `SELECT host_id::text FROM app.services WHERE id = $1::uuid`, service.String()).Scan(&host); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func insertHealth(t *testing.T, d *DB, ctx context.Context, host, service uuid.UUID, protocol, result string, at time.Time, check *uuid.UUID, port *int, latency *float64) {
	t.Helper()
	var checkArg any
	if check != nil {
		checkArg = check.String()
	}
	var portArg any
	if port != nil {
		portArg = int32(*port)
	}
	var proto any
	if protocol != "" {
		proto = protocol
	}
	if _, err := d.pool.Exec(ctx, `
INSERT INTO metrics.health_results (
    time, host_id, service_id, check_id, protocol, port, result, http_status, latency_ms
) VALUES (
    $1, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, NULL, $8
)`, at, host.String(), service.String(), checkArg, proto, portArg, result, latency); err != nil {
		t.Fatalf("health insert: %v", err)
	}
}

func intPtr(n int) *int { return &n }

func floatPtr(v float64) *float64 { return &v }
