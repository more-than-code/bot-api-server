package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestImageEntryEnsuresFiles(t *testing.T) {
	bare := CatalogEntry{
		ID: uuid.New(), ProjectID: uuid.New(), Name: "web", Kind: "image",
		ImageRaw: json.RawMessage(`{"image":"nginx","kind":"service"}`),
		SpecHash: "abc", CommandDisplay: "nginx", CreatedBy: uuid.New(),
	}
	raw, err := json.Marshal(bare)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	spec, _ := got["spec"].(map[string]any)
	files, ok := spec["files"].([]any)
	if !ok || len(files) != 0 || !strings.Contains(string(raw), `"files":[]`) {
		t.Fatalf("missing files %#v", spec)
	}
	kept := CatalogEntry{
		ID: bare.ID, ProjectID: bare.ProjectID, Name: "web", Kind: "image",
		ImageRaw:       json.RawMessage(`{"files":[{"file":"a.conf","target":"/config/a.conf"}],"image":"nginx"}`),
		SpecHash:       bare.SpecHash,
		CommandDisplay: "nginx", CreatedBy: bare.CreatedBy,
	}
	raw, err = json.Marshal(kept)
	if err != nil || !strings.Contains(string(raw), `"file":"a.conf"`) || strings.Contains(string(raw), `"files":[]`) {
		t.Fatalf("rewrote a spec that already had files %s %v", raw, err)
	}
	prog := CatalogEntry{ID: uuid.New(), ProjectID: bare.ProjectID, Name: "job", Kind: "program", CreatedBy: bare.CreatedBy}
	raw, err = json.Marshal(prog)
	if err != nil || strings.Contains(string(raw), `"files"`) {
		t.Fatalf("program gained files %s %v", raw, err)
	}
}

func TestPlaceDiscoveredUnitName(t *testing.T) {
	hostProject := uuid.New()
	lookup := func(string, string, string) (uuid.UUID, bool) { return uuid.Nil, false }
	huge := strings.Repeat("a", 80)
	item := Discovered{
		Name: "kept", Kind: "systemd", SystemdUnit: &huge,
		Owner: &DiscoveredOwner{Kind: "program", Project: "missing", Entry: "nope"},
	}
	name, source, project, catalog := PlaceDiscovered(item, hostProject, lookup)
	if name != "kept" || source != "discovered" || project != hostProject || catalog != nil {
		t.Fatalf("huge unit %s %s %s %v", name, source, project, catalog)
	}
	good := "deploybot-ok.service"
	item.SystemdUnit = &good
	name, source, project, catalog = PlaceDiscovered(item, hostProject, lookup)
	if name != good || source != "discovered" || project != hostProject || catalog != nil {
		t.Fatalf("unit name %s %s %s %v", name, source, project, catalog)
	}
	home := uuid.New()
	item.Owner.Project = "app"
	item.Owner.Entry = "web"
	name, source, project, catalog = PlaceDiscovered(item, hostProject, func(slug, entry, kind string) (uuid.UUID, bool) {
		if slug == "app" && entry == "web" && kind == "program" {
			return home, true
		}
		return uuid.Nil, false
	})
	if name != "web" || source != "owned" || project != home || catalog == nil || *catalog != "web" {
		t.Fatalf("owned %s %s %s %v", name, source, project, catalog)
	}
	item.Owner.Entry = "absent"
	name, source, _, catalog = PlaceDiscovered(item, hostProject, func(slug, entry, kind string) (uuid.UUID, bool) {
		return home, slug == "app" && entry == "web" && kind == "program"
	})
	if name != good || source != "discovered" || catalog != nil {
		t.Fatalf("wrong entry %s %s %v", name, source, catalog)
	}
}
