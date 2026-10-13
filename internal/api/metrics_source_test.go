package api

import (
	"os"
	"strings"
	"testing"
)

func TestMetricsHandlerSources(t *testing.T) {
	body, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	metrics := fnText(t, text, "handleMetrics")
	if !strings.Contains(metrics, "QueryChart") || strings.Contains(metrics, "LoadMetric") {
		t.Fatal("handleMetrics must call QueryChart and must not load raw samples")
	}
	proc := fnText(t, text, "handleProcesses")
	if !strings.Contains(proc, "LatestProcesses") || strings.Contains(proc, "sort.") {
		t.Fatal("handleProcesses must pass sort and limit to the store")
	}
	health := fnText(t, text, "handleHealthHistory")
	if !strings.Contains(health, ", 1000)") {
		t.Fatal("health history must cap at 1000")
	}
}

func fnText(t *testing.T, file, name string) string {
	t.Helper()
	start := strings.Index(file, "func (s *Server) "+name)
	if start < 0 {
		t.Fatalf("missing %s", name)
	}
	rest := file[start+1:]
	next := strings.Index(rest, "\nfunc ")
	if next < 0 {
		return file[start:]
	}
	return file[start : start+1+next]
}
