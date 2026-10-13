package ingest

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSeenCapsPerHost(t *testing.T) {
	start := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	now := start
	s := NewSeen(func() time.Time { return now })
	host := uuid.New()
	other := uuid.New()
	var first, second uuid.UUID
	for i := 0; i < seenCap; i++ {
		id := uuid.New()
		if i == 0 {
			first = id
		}
		if i == 1 {
			second = id
		}
		now = now.Add(time.Millisecond)
		s.Add(host, id)
	}
	if len(s.hosts[host]) != seenCap {
		t.Fatalf("len %d", len(s.hosts[host]))
	}
	if !s.Has(host, first) || !s.Has(host, second) {
		t.Fatal("filled keys missing")
	}
	s.Add(host, first)
	extra := uuid.New()
	now = now.Add(time.Millisecond)
	s.Add(host, extra)
	if len(s.hosts[host]) != seenCap {
		t.Fatalf("after drop len %d", len(s.hosts[host]))
	}
	if !s.Has(host, first) || !s.Has(host, extra) {
		t.Fatal("refreshed key or new key was dropped")
	}
	if s.Has(host, second) {
		t.Fatal("oldest remaining key was kept")
	}
	kept := uuid.New()
	s.Add(other, kept)
	if !s.Has(other, kept) || len(s.hosts[host]) != seenCap {
		t.Fatal("other host changed this host's cap")
	}
}
