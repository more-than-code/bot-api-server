package store

import "time"

const HealthStale = 2 * time.Minute

// DeriveHealth maps the chosen probe to the Service.health object.
// Unknown when there is no chosen row, or the chosen row is older than 2 minutes.
// A stale non-docker row still reports last_checked_at and source "check".
// Docker latency is always null. Source is null only when there is no row.
func DeriveHealth(latest *HealthPoint, now time.Time) Health {
	if latest == nil {
		return Health{Status: "unknown"}
	}
	source := "check"
	latency := latest.LatencyMS
	if latest.Protocol == "docker" {
		source = "docker"
		latency = nil
	}
	h := Health{
		Status:        "unknown",
		LastCheckedAt: &latest.T,
		LatencyMS:     latency,
		Source:        &source,
	}
	if now.Sub(latest.T) > HealthStale {
		return h
	}
	if latest.Result == "success" {
		h.Status = "up"
	} else {
		h.Status = "down"
	}
	return h
}

// SelectHealth picks the row Service.health is derived from.
// A docker row at most HealthStale old wins, even when a check is newer.
// Otherwise the latest non-docker row wins, at any age. A stale docker row
// is not a fallback. An empty protocol counts as non-docker.
func SelectHealth(points []HealthPoint, now time.Time) *HealthPoint {
	var docker, check *HealthPoint
	for i := range points {
		p := points[i]
		if p.Protocol == "docker" {
			if now.Sub(p.T) > HealthStale {
				continue
			}
			if docker == nil || p.T.After(docker.T) {
				cp := p
				docker = &cp
			}
			continue
		}
		if check == nil || p.T.After(check.T) {
			cp := p
			check = &cp
		}
	}
	if docker != nil {
		return docker
	}
	return check
}

// HealthRank orders health.status for the project services list.
// Ascending is up, then down, then unknown.
func HealthRank(status string) int {
	switch status {
	case "up":
		return 0
	case "down":
		return 1
	default:
		return 2
	}
}
