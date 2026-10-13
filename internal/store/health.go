package store

import "time"

const HealthStale = 2 * time.Minute

// DeriveHealth maps the latest probe to the Service.health object.
// Unknown when there is no sample or the latest sample is older than 2 minutes.
func DeriveHealth(latest *HealthPoint, now time.Time) Health {
	if latest == nil {
		return Health{Status: "unknown"}
	}
	h := Health{
		Status:        "unknown",
		LastCheckedAt: &latest.T,
		LatencyMS:     floatPtr(latest.LatencyMS),
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

func floatPtr(v float64) *float64 {
	return &v
}
