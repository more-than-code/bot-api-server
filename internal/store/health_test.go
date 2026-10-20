package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSelectHealthPrecedence(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	newer := now.Add(-30 * time.Second)
	edge := now.Add(-HealthStale)
	stale := now.Add(-HealthStale - time.Second)
	checkID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	lat := 4.5
	check := func(at time.Time, result string) HealthPoint {
		return HealthPoint{T: at, Protocol: "http", Result: result, CheckID: &checkID, LatencyMS: &lat, Port: intPtr(80)}
	}
	docker := func(at time.Time, result string) HealthPoint {
		return HealthPoint{T: at, Protocol: "docker", Result: result, LatencyMS: &lat}
	}
	none := func(at time.Time, result string) HealthPoint {
		return HealthPoint{T: at, Result: result, LatencyMS: &lat}
	}

	cases := []struct {
		name   string
		points []HealthPoint
		status string
		source string
		latNil bool
	}{
		{"docker fresh beats newer check", []HealthPoint{check(newer, "fail"), docker(fresh, "success")}, "up", "docker", true},
		{"docker fresh alone", []HealthPoint{docker(fresh, "success")}, "up", "docker", true},
		{"docker edge is fresh", []HealthPoint{docker(edge, "unhealthy"), check(stale, "success")}, "down", "docker", true},
		{"stale docker falls through to check", []HealthPoint{docker(stale, "success"), check(fresh, "success")}, "up", "check", false},
		{"stale docker alone", []HealthPoint{docker(stale, "success")}, "unknown", "", true},
		{"check fresh", []HealthPoint{check(fresh, "success")}, "up", "check", false},
		{"null protocol is a check", []HealthPoint{none(fresh, "fail"), docker(stale, "success")}, "down", "check", false},
		{"both stale keeps the check", []HealthPoint{docker(stale, "success"), check(stale, "success")}, "unknown", "check", false},
		{"none", nil, "unknown", "", true},
	}
	for _, tc := range cases {
		got := DeriveHealth(SelectHealth(tc.points, now), now)
		if got.Status != tc.status {
			t.Fatalf("%s status %s", tc.name, got.Status)
		}
		if tc.source == "" {
			if got.Source != nil || got.LastCheckedAt != nil {
				t.Fatalf("%s source %#v at %v", tc.name, got.Source, got.LastCheckedAt)
			}
		} else if got.Source == nil || *got.Source != tc.source || got.LastCheckedAt == nil {
			t.Fatalf("%s source %#v", tc.name, got.Source)
		}
		if tc.latNil {
			if got.LatencyMS != nil {
				t.Fatalf("%s latency %v", tc.name, *got.LatencyMS)
			}
		} else if got.LatencyMS == nil || *got.LatencyMS != lat {
			t.Fatalf("%s latency %#v", tc.name, got.LatencyMS)
		}
	}
}

func intPtr(n int) *int { return &n }
