package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceBefore(t *testing.T) {
	low := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	high := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	if bytes.Compare(low[:], high[:]) >= 0 {
		t.Fatal("fixture ids are out of order")
	}
	base := ServiceOrder{ID: low, NameKey: "m", Host: "h", Kind: "process", StatusRank: 2, LastSeen: time.Unix(10, 0)}
	other := base
	other.ID = high

	assertOrder := func(a, b ServiceOrder, key, dir string, wantA bool) {
		t.Helper()
		if got := ServiceBefore(a, b, key, dir); got != wantA {
			t.Fatalf("before %s %s = %v, want %v", key, dir, got, wantA)
		}
		if got := ServiceBefore(b, a, key, dir); got != !wantA {
			t.Fatalf("reverse %s %s = %v", key, dir, got)
		}
	}

	assertOrder(base, other, "name", "asc", true)
	assertOrder(base, other, "name", "desc", true)
	assertOrder(base, other, "bogus", "asc", true)

	named := base
	named.NameKey = "a"
	later := other
	later.NameKey = "z"
	assertOrder(named, later, "name", "asc", true)
	assertOrder(named, later, "name", "desc", false)

	nullName := base
	nullName.NameNull = true
	assertOrder(nullName, other, "name", "asc", false)
	assertOrder(nullName, other, "name", "desc", false)
	nullHost := base
	nullHost.HostNull = true
	assertOrder(nullHost, other, "host", "asc", false)
	assertOrder(nullHost, other, "host", "desc", false)
	nullKind := base
	nullKind.KindNull = true
	assertOrder(nullKind, other, "kind", "desc", false)
	nullTime := base
	nullTime.LastNull = true
	assertOrder(nullTime, other, "last_seen", "asc", false)
	assertOrder(nullTime, other, "last_seen", "desc", false)

	up := base
	up.StatusRank = HealthRank("up")
	down := other
	down.StatusRank = HealthRank("down")
	assertOrder(up, down, "status", "asc", true)
	assertOrder(up, down, "status", "desc", false)

	unknownLow := base
	unknownLow.StatusRank = HealthRank("unknown")
	unknownLow.NameKey = "a"
	unknownHigh := other
	unknownHigh.StatusRank = HealthRank("unknown")
	unknownHigh.NameKey = "z"
	assertOrder(unknownLow, unknownHigh, "status", "asc", true)
	assertOrder(unknownLow, unknownHigh, "status", "desc", false)

	same := base
	same.StatusRank = 2
	sameName := other
	sameName.StatusRank = 2
	sameName.NameKey = base.NameKey
	assertOrder(same, sameName, "status", "asc", true)
	assertOrder(same, sameName, "status", "desc", true)

	early := base
	early.LastSeen = time.Unix(1, 0)
	late := other
	late.LastSeen = time.Unix(2, 0)
	assertOrder(early, late, "last_seen", "asc", true)
	assertOrder(early, late, "last_seen", "desc", false)

	hostA := base
	hostA.Host = "a"
	hostZ := other
	hostZ.Host = "z"
	assertOrder(hostA, hostZ, "host", "asc", true)
	assertOrder(hostA, hostZ, "host", "desc", false)
}

func TestHealthRank(t *testing.T) {
	if HealthRank("up") != 0 || HealthRank("down") != 1 || HealthRank("unknown") != 2 || HealthRank("other") != 2 {
		t.Fatalf("ranks %d %d %d", HealthRank("up"), HealthRank("down"), HealthRank("unknown"))
	}
}
