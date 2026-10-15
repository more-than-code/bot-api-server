package store

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPlaceDiscoveredUnitName(t *testing.T) {
	hostProject := uuid.New()
	lookup := func(string, string) (uuid.UUID, bool) { return uuid.Nil, false }
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
	name, source, project, catalog = PlaceDiscovered(item, hostProject, func(slug, entry string) (uuid.UUID, bool) {
		if slug == "app" && entry == "web" {
			return home, true
		}
		return uuid.Nil, false
	})
	if name != "web" || source != "owned" || project != home || catalog == nil || *catalog != "web" {
		t.Fatalf("owned %s %s %s %v", name, source, project, catalog)
	}
	item.Owner.Entry = "absent"
	name, source, _, catalog = PlaceDiscovered(item, hostProject, func(slug, entry string) (uuid.UUID, bool) {
		return home, slug == "app" && entry == "web"
	})
	if name != good || source != "discovered" || catalog != nil {
		t.Fatalf("wrong entry %s %s %v", name, source, catalog)
	}
}
