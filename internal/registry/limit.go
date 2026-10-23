package registry

import (
	"sync"
	"time"
)

// Limiter is a sliding window per key: at most limit hits per window.
// A refused call is not counted.
type Limiter struct {
	limit  int
	window time.Duration

	mu        sync.Mutex
	hits      map[string][]time.Time
	lastSweep time.Time
}

// NewLimiter returns a limiter for limit hits per window.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// Allow counts one hit for key at now. When the window is full it returns
// false and how long until the oldest hit leaves the window.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	kept := freshHits(l.hits[key], now, l.window)
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false, kept[0].Add(l.window).Sub(now)
	}
	l.hits[key] = append(kept, now)
	return true, 0
}

func (l *Limiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = now
	for key, hits := range l.hits {
		if kept := freshHits(hits, now, l.window); len(kept) == 0 {
			delete(l.hits, key)
		} else {
			l.hits[key] = kept
		}
	}
}

func freshHits(hits []time.Time, now time.Time, window time.Duration) []time.Time {
	cut := now.Add(-window)
	kept := make([]time.Time, 0, len(hits)+1)
	for _, at := range hits {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	return kept
}

// Cache keeps successful lookups for ttl. It holds at most max entries;
// when full after dropping expired entries, a new result is not stored.
type Cache struct {
	ttl time.Duration
	max int

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	value   any
	expires time.Time
}

// NewCache returns a cache with ttl and at most max entries.
func NewCache(ttl time.Duration, max int) *Cache {
	return &Cache{ttl: ttl, max: max, entries: map[string]cacheEntry{}}
}

// Get returns the value for key when it has not expired.
func (c *Cache) Get(key string, now time.Time) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.expires) {
		return nil, false
	}
	return e.value, true
}

// Put stores value for key until now + ttl.
func (c *Cache) Put(key string, value any, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.max {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return
		}
	}
	c.entries[key] = cacheEntry{value: value, expires: now.Add(c.ttl)}
}
