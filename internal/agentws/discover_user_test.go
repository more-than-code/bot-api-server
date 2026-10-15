package agentws

import (
	"encoding/json"
	"io"
	"log/slog"
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
