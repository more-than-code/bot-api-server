package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestLatestProcessesCapsAndSorts(t *testing.T) {
	ctx := context.Background()
	mem := New()
	host := uuid.New()
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	samples := make([]store.Sample, 201)
	for i := range samples {
		pid := i + 1
		samples[i] = store.Sample{
			M: "process", T: at,
			Tags: map[string]string{
				"pid": strconvItoa(pid), "process_name": "p", "user": "u", "cmdline": "c",
			},
			Floats: map[string]float64{"cpu_usage": float64(pid)},
			Ints:   map[string]int64{"memory_rss": int64(300 - pid)},
		}
	}
	if _, err := mem.InsertBatch(ctx, host, uuid.New(), samples, at); err != nil {
		t.Fatal(err)
	}
	_, items, err := mem.LatestProcesses(ctx, host, at.Add(-time.Minute), "cpu", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 200 || items[0].CPUUsage != 201 {
		t.Fatalf("cpu cap %+v len %d", items[0], len(items))
	}
	for i := 1; i < len(items); i++ {
		if items[i].CPUUsage > items[i-1].CPUUsage {
			t.Fatal("cpu order")
		}
	}
	_, memItems, err := mem.LatestProcesses(ctx, host, at.Add(-time.Minute), "memory", 1)
	if err != nil || len(memItems) != 1 || memItems[0].PID != 1 {
		t.Fatalf("memory limit %+v %v", memItems, err)
	}
}

func TestHealthHistoryCaps(t *testing.T) {
	ctx := context.Background()
	mem := New()
	host := uuid.New()
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	svc := mem.PutDeclared(host, "api", "process", []int{80}, at)
	samples := make([]store.Sample, 1001)
	for i := range samples {
		samples[i] = store.Sample{
			M: "health", T: at.Add(time.Duration(i) * time.Second),
			Tags:   map[string]string{"service": "api", "check_id": uuid.New().String()},
			Strs:   map[string]string{"result": "success"},
			Nulls:  map[string]bool{"http_status": true},
			Floats: map[string]float64{},
			Ints:   map[string]int64{},
		}
	}
	if _, err := mem.InsertBatch(ctx, host, uuid.New(), samples, at); err != nil {
		t.Fatal(err)
	}
	items, err := mem.HealthHistory(ctx, svc.ID, at.Add(-time.Second), at.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1000 {
		t.Fatalf("health rows %d", len(items))
	}
}

func TestDeleteOldBatches(t *testing.T) {
	ctx := context.Background()
	mem := New()
	host := uuid.New()
	batch := uuid.New()
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	ok, err := mem.InsertBatch(ctx, host, batch, nil, at)
	if err != nil || !ok {
		t.Fatalf("insert %v %v", ok, err)
	}
	if err := mem.DeleteOldBatches(ctx, at); err != nil {
		t.Fatal(err)
	}
	ok, err = mem.InsertBatch(ctx, host, batch, nil, at)
	if err != nil || ok {
		t.Fatal("cutoff equal to received_at deleted the row")
	}
	if err := mem.DeleteOldBatches(ctx, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ok, err = mem.InsertBatch(ctx, host, batch, nil, at)
	if err != nil || !ok {
		t.Fatalf("reinsert after delete %v %v", ok, err)
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
