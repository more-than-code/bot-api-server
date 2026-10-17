package store

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// HealthCheckInputs copies stored checks into the input shape the hashes use.
// Ids are dropped. Path strings are copied.
func HealthCheckInputs(checks []HealthCheck) []HealthCheckInput {
	out := make([]HealthCheckInput, len(checks))
	for i, c := range checks {
		item := HealthCheckInput{
			Protocol: c.Protocol, Port: c.Port, IntervalSec: c.IntervalSec,
			ExpectStatusMin: c.ExpectStatusMin, ExpectStatusMax: c.ExpectStatusMax, Enabled: c.Enabled,
		}
		if c.Path != nil {
			p := *c.Path
			item.Path = &p
		}
		out[i] = item
	}
	return out
}

// HealthRequestHash binds an idempotency row to this service and this
// normalized check list, in request order. The idempotency key is not hashed.
func HealthRequestHash(serviceID uuid.UUID, checks []HealthCheckInput) []byte {
	raw := `{"checks":[` + joinCheckCanon(checks) + `],"service_id":` + quoteJSON(serviceID.String()) + `}`
	sum := sha256.Sum256([]byte(raw))
	return append([]byte(nil), sum[:]...)
}

// HealthSetHash is the check set at issue time. Checks are sorted so a
// memstore map walk cannot change the hash between issue and confirm.
// Protocol, port, path, interval, expect, and enabled all count. Ids do not.
func HealthSetHash(checks []HealthCheckInput) []byte {
	sorted := append([]HealthCheckInput(nil), checks...)
	sort.SliceStable(sorted, func(i, j int) bool { return healthCheckLess(sorted[i], sorted[j]) })
	raw := `{"checks":[` + joinCheckCanon(sorted) + `]}`
	sum := sha256.Sum256([]byte(raw))
	return append([]byte(nil), sum[:]...)
}

func joinCheckCanon(checks []HealthCheckInput) string {
	parts := make([]string, len(checks))
	for i, c := range checks {
		parts[i] = checkCanon(c)
	}
	return strings.Join(parts, ",")
}

func checkCanon(c HealthCheckInput) string {
	path := "null"
	if c.Path != nil {
		path = quoteJSON(*c.Path)
	}
	enabled := "false"
	if c.Enabled {
		enabled = "true"
	}
	return `{"enabled":` + enabled +
		`,"expect_status_max":` + strconv.Itoa(c.ExpectStatusMax) +
		`,"expect_status_min":` + strconv.Itoa(c.ExpectStatusMin) +
		`,"interval_sec":` + strconv.Itoa(c.IntervalSec) +
		`,"path":` + path +
		`,"port":` + strconv.Itoa(c.Port) +
		`,"protocol":` + quoteJSON(c.Protocol) + `}`
}

func healthCheckLess(a, b HealthCheckInput) bool {
	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if pathLess(a.Path, b.Path) {
		return true
	}
	if pathLess(b.Path, a.Path) {
		return false
	}
	if a.IntervalSec != b.IntervalSec {
		return a.IntervalSec < b.IntervalSec
	}
	if a.ExpectStatusMin != b.ExpectStatusMin {
		return a.ExpectStatusMin < b.ExpectStatusMin
	}
	if a.ExpectStatusMax != b.ExpectStatusMax {
		return a.ExpectStatusMax < b.ExpectStatusMax
	}
	return !a.Enabled && b.Enabled
}

func pathLess(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b != nil
	}
	return *a < *b
}

func quoteJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
