package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestDockerHealthMemstore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	mem := New()
	user := mustUser(t, mem, "dh@ex.com", now)
	project := makeProject(t, mem, user.ID, "DH", "dh", now)
	host := enrollMem(t, mem, project.ID, user.ID, "dh-host", now)
	api := discoverService(t, mem, host.ID, "api", "container", nil, nil, now)
	discoverService(t, mem, host.ID, "down", "container", nil, nil, now)

	lat := 4.5
	put := func(service, protocol, result string, at time.Time, withLat bool) {
		t.Helper()
		sample := store.Sample{
			M:    "health",
			T:    at,
			Tags: map[string]string{"service": service, "protocol": protocol},
			Strs: map[string]string{"result": result},
		}
		if protocol == "docker" {
			sample.Nulls = map[string]bool{"http_status": true, "latency_ms": true}
		} else {
			sample.Tags["check_id"] = "11111111-1111-1111-1111-111111111111"
			sample.Tags["port"] = "80"
			sample.Ints = map[string]int64{"http_status": 200}
			if withLat {
				sample.Floats = map[string]float64{"latency_ms": lat}
			}
		}
		if _, err := mem.InsertBatch(ctx, host.ID, uuid.New(), []store.Sample{sample}, at); err != nil {
			t.Fatal(err)
		}
	}
	put("api", "http", "fail", now.Add(-30*time.Second), true)
	put("api", "docker", "success", now.Add(-time.Minute), false)
	put("down", "http", "fail", now.Add(-time.Minute), true)

	got, err := mem.GetService(ctx, api.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Health.Status != "up" || got.Health.Source == nil || *got.Health.Source != "docker" || got.Health.LatencyMS != nil {
		t.Fatalf("api health %+v", got.Health)
	}
	rows, err := mem.HealthHistory(ctx, api.ID, now.Add(-time.Hour), now.Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("history %d", len(rows))
	}
	var sawDocker bool
	for _, row := range rows {
		if row.Protocol != "docker" {
			if row.CheckID == nil || row.Port == nil || *row.Port != 80 || row.LatencyMS == nil {
				t.Fatalf("check row %+v", row)
			}
			continue
		}
		sawDocker = true
		if row.Result != "success" || row.CheckID != nil || row.Port != nil || row.HTTPStatus != nil || row.LatencyMS != nil {
			t.Fatalf("docker row %+v", row)
		}
	}
	if !sawDocker {
		t.Fatal("history omitted the docker row")
	}

	page, err := mem.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 10}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Name != "api" || page.Items[0].Health.Status != "up" || page.Items[1].Name != "down" || page.Items[1].Health.Status != "down" {
		t.Fatalf("sort %+v", page.Items)
	}
	if page.Items[1].Health.Source == nil || *page.Items[1].Health.Source != "check" {
		t.Fatalf("check source %+v", page.Items[1].Health)
	}
}
