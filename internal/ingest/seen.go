package ingest

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	seenTTL = 24 * time.Hour
	seenCap = 50000
)

// Seen remembers batch ids per host for 24 hours so a replay is acked
// without a second insert. The database unique key is the durable copy.
// Each host keeps at most seenCap keys; the oldest expiry is dropped first.
type Seen struct {
	mu        sync.Mutex
	hosts     map[uuid.UUID]map[uuid.UUID]time.Time
	now       func() time.Time
	nextPrune time.Time
}

func NewSeen(now func() time.Time) *Seen {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Seen{hosts: map[uuid.UUID]map[uuid.UUID]time.Time{}, now: now}
}

// Has reports whether this host already committed batch.
func (s *Seen) Has(host, batch uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	exp, ok := s.hosts[host][batch]
	return ok && s.now().Before(exp)
}

// Add marks the batch seen for 24 hours from now.
func (s *Seen) Add(host, batch uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	rows := s.hosts[host]
	if rows == nil {
		rows = map[uuid.UUID]time.Time{}
		s.hosts[host] = rows
	}
	if _, ok := rows[batch]; !ok && len(rows) >= seenCap {
		dropOldest(rows)
	}
	exp := s.now().Add(seenTTL)
	rows[batch] = exp
	if s.nextPrune.IsZero() || exp.Before(s.nextPrune) {
		s.nextPrune = exp
	}
}

func dropOldest(rows map[uuid.UUID]time.Time) {
	var oldest uuid.UUID
	var at time.Time
	first := true
	for id, exp := range rows {
		if first || exp.Before(at) {
			oldest = id
			at = exp
			first = false
		}
	}
	if !first {
		delete(rows, oldest)
	}
}

func (s *Seen) prune() {
	now := s.now()
	if !s.nextPrune.IsZero() && now.Before(s.nextPrune) {
		return
	}
	next := now.Add(seenTTL)
	for host, rows := range s.hosts {
		for id, exp := range rows {
			if !now.Before(exp) {
				delete(rows, id)
				continue
			}
			if exp.Before(next) {
				next = exp
			}
		}
		if len(rows) == 0 {
			delete(s.hosts, host)
		}
	}
	s.nextPrune = next
}
