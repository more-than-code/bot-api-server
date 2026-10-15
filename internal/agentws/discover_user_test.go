package agentws

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
)

func TestDiscoveredUser(t *testing.T) {
	h := New(memstore.New(), audit.Writer{}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	raw := json.RawMessage(`[
		{"name":"api","kind":"process","ports":[80],"user":"www-data"},
		{"name":"blank","kind":"process","user":null},
		{"name":"missing","kind":"process"},
		{"name":"noisy","kind":"process","user":"a\nb"},
		{"name":"typed","kind":"process","user":1}
	]`)
	items, presence, report := h.discoveredReport(raw)
	if !report || !presence || len(items) != 5 {
		t.Fatalf("discovered %d services", len(items))
	}
	got := map[string]*string{}
	for _, item := range items {
		got[item.Name] = item.OwnerUser
	}
	if got["api"] == nil || *got["api"] != "www-data" {
		t.Fatalf("api user %#v", got["api"])
	}
	if _, ok := got["blank"]; !ok || got["blank"] != nil {
		t.Fatal("null user dropped the service or kept a value")
	}
	if got["missing"] != nil {
		t.Fatal("missing user kept a value")
	}
	if got["noisy"] == nil || *got["noisy"] != "a\nb" {
		t.Fatalf("control user %#v", got["noisy"])
	}
	if _, ok := got["typed"]; !ok || got["typed"] != nil {
		t.Fatal("non-string user dropped the service or kept a value")
	}
}

func TestContainerNameDropped(t *testing.T) {
	h := New(memstore.New(), audit.Writer{}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	long := strings.Repeat("a", 129)
	raw := json.RawMessage(`[
		{"name":"keep","kind":"container","container_name":"web"},
		{"name":"nilname","kind":"container"},
		{"name":"empty","kind":"container","container_name":""},
		{"name":"long","kind":"container","container_name":"` + long + `"},
		{"name":"ctrl","kind":"container","container_name":"a\nb"},
		{"name":"assigned","kind":"container","container_name":"password=hunter22"}
	]`)
	items, _, report := h.discoveredReport(raw)
	if !report {
		t.Fatal("report dropped")
	}
	names := map[string]*string{}
	for _, item := range items {
		names[item.Name] = item.ContainerName
	}
	if names["keep"] == nil || *names["keep"] != "web" {
		t.Fatalf("keep %#v", names["keep"])
	}
	if _, ok := names["nilname"]; !ok || names["nilname"] != nil {
		t.Fatal("missing container_name dropped the service or kept a value")
	}
	if _, ok := names["empty"]; ok {
		t.Fatal("empty container_name was stored")
	}
	if _, ok := names["long"]; ok {
		t.Fatal("long container_name was stored")
	}
	if _, ok := names["ctrl"]; ok {
		t.Fatal("control character in container_name was stored")
	}
	if names["assigned"] == nil || *names["assigned"] != "password=[REDACTED]" || strings.Contains(*names["assigned"], "hunter22") {
		t.Fatalf("assignment %#v", names["assigned"])
	}
}
