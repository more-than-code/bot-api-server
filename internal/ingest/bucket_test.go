package ingest

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestBucketCPUAndNegativeDelta(t *testing.T) {
	from := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	to := from.Add(20 * time.Second)
	host := uuid.New()
	samples := []store.Sample{
		{HostID: host, M: "cpu", T: from.Add(time.Second), Floats: map[string]float64{"usage_idle": 80}},
		{HostID: host, M: "cpu", T: from.Add(2 * time.Second), Floats: map[string]float64{"usage_idle": 60}},
		{HostID: host, M: "diskio", T: from.Add(time.Second), Tags: map[string]string{"name": "sda"}, Ints: map[string]int64{"read_bytes": 1000}},
		{HostID: host, M: "diskio", T: from.Add(11 * time.Second), Tags: map[string]string{"name": "sda"}, Ints: map[string]int64{"read_bytes": 500}},
	}
	cpu, err := Bucket("cpu", from, to, 10, samples[:2])
	if err != nil || len(cpu) != 1 || cpu[0].Name != "usage_percent" || cpu[0].Unit != "%" {
		t.Fatalf("cpu series: %v %#v", err, cpu)
	}
	if cpu[0].Points[0].V == nil || *cpu[0].Points[0].V != 30 {
		t.Fatalf("usage = %#v", cpu[0].Points[0].V)
	}
	io, err := Bucket("diskio", from, to, 10, samples[2:])
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range io[0].Points {
		if p.V != nil {
			t.Fatalf("negative delta was kept: %v", *p.V)
		}
	}
}

func TestChooseStep(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	step, err := ChooseStep(from, from.Add(time.Hour), 0)
	if err != nil || step != MinStep {
		t.Fatalf("default hour: %d %v", step, err)
	}
	step, err = ChooseStep(from, from.Add(2*time.Hour), 0)
	if err != nil || step != 15 {
		t.Fatalf("default two hours: %d %v", step, err)
	}
	if _, err := ChooseStep(from, from.Add(time.Hour), 9); err == nil {
		t.Fatal("step 9 was accepted")
	}
	if _, err := ChooseStep(from, from.Add(time.Hour), 3601); err == nil {
		t.Fatal("step 3601 was accepted")
	}
	step, err = ChooseStep(from, from.Add(MaxSpan), 0)
	if err != nil || step != MaxStep {
		t.Fatalf("31-day default: %d %v", step, err)
	}
	if _, err := ChooseStep(from, from.Add(MaxSpan+time.Second), 0); err == nil {
		t.Fatal("span over 31 days was accepted")
	}
}

func TestRateSumPerInterface(t *testing.T) {
	from := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	to := from.Add(10 * time.Second)
	sample := func(iface string, at time.Time, recv int64) store.Sample {
		return store.Sample{
			M: "net", T: at, Tags: map[string]string{"interface": iface},
			Ints: map[string]int64{"bytes_recv": recv, "bytes_sent": 0},
		}
	}
	samples := []store.Sample{
		sample("eth0", from.Add(time.Second), 0),
		sample("eth0", from.Add(5*time.Second), 400),
		sample("eth1", from.Add(time.Second), 0),
		sample("eth1", from.Add(5*time.Second), 200),
		sample("eth2", from.Add(time.Second), 500),
		sample("eth2", from.Add(5*time.Second), 100),
	}
	series, err := Bucket("net", from, to, 10, samples)
	if err != nil {
		t.Fatal(err)
	}
	if series[0].Name != "rx_bps" || series[0].Points[0].V == nil || *series[0].Points[0].V != 150 {
		t.Fatalf("rx %#v", series[0].Points)
	}
}

func TestNullBucketsAndRootDisk(t *testing.T) {
	from := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	cpu := []store.Sample{{
		M: "cpu", T: from.Add(time.Second), Floats: map[string]float64{"usage_idle": 50},
	}}
	series, err := Bucket("cpu", from, from.Add(30*time.Second), 10, cpu)
	if err != nil {
		t.Fatal(err)
	}
	if len(series[0].Points) != 3 || series[0].Points[0].V == nil || *series[0].Points[0].V != 50 {
		t.Fatalf("first bucket %#v", series[0].Points)
	}
	if series[0].Points[1].V != nil || series[0].Points[2].V != nil {
		t.Fatal("gap buckets were not null")
	}
	disk := []store.Sample{
		{M: "disk", T: from.Add(time.Second), Tags: map[string]string{"path": "/", "fstype": "ext4"}, Floats: map[string]float64{"used_percent": 10}},
		{M: "disk", T: from.Add(time.Second), Tags: map[string]string{"path": "/var", "fstype": "ext4"}, Floats: map[string]float64{"used_percent": 90}},
	}
	series, err = Bucket("disk", from, from.Add(10*time.Second), 10, disk)
	if err != nil || series[0].Points[0].V == nil || *series[0].Points[0].V != 10 {
		t.Fatalf("disk path filter %#v %v", series, err)
	}
}

func TestBucketHardLimit(t *testing.T) {
	from := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	series, err := Bucket("cpu", from, from.Add(10000*time.Second), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(series[0].Points) != MaxBuckets {
		t.Fatalf("buckets %d", len(series[0].Points))
	}
}
