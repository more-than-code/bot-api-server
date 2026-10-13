package db

import (
	"os"
	"strings"
	"testing"
)

func TestChartSQLAggregates(t *testing.T) {
	body, err := os.ReadFile("chart.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, needle := range []string{
		"time_bucket(make_interval(secs => $3), time)",
		"chartBucketLimit = 500",
		"LIMIT %d",
		"last_v >= first_v",
		"(last_v - first_v)::float8 / dt",
		"path = '/'",
		"cpu = 'cpu-total'",
		"interface <> 'lo'",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("chart SQL missing %s", needle)
		}
	}
	if strings.Contains(text, "LoadMetric") {
		t.Fatal("QueryChart must not load raw samples")
	}
}
