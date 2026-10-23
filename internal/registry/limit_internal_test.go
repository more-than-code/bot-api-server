package registry

import (
	"testing"
	"time"
)

func TestLimiterRefusalDoesNotExtendWindow(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if ok, _ := l.Allow("u", now); !ok {
		t.Fatal("first hit refused")
	}
	for i := 1; i <= 50; i++ {
		if ok, _ := l.Allow("u", now.Add(time.Duration(i)*time.Second)); ok {
			t.Fatal("over limit allowed")
		}
	}
	if ok, _ := l.Allow("u", now.Add(time.Minute+time.Second)); !ok {
		t.Fatal("refused calls extended the window")
	}
}

func TestLimiterSweepDropsIdleKeys(t *testing.T) {
	l := NewLimiter(5, time.Minute)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	l.Allow("idle", now)
	l.Allow("busy", now.Add(2*time.Minute))
	l.Allow("busy", now.Add(3*time.Minute+30*time.Second))
	if _, ok := l.hits["idle"]; ok {
		t.Fatal("idle key kept")
	}
	if len(l.hits["busy"]) != 1 {
		t.Fatalf("busy hits %d", len(l.hits["busy"]))
	}
}
