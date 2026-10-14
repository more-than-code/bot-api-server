package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestAuthorizeHostMatrix is the §4 matrix at the authz function.
// HTTP coverage of the same cells is in the api package.
func TestAuthorizeHostMatrix(t *testing.T) {
	shareID := uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	otherID := uuid.MustParse("00000000-0000-4000-8000-0000000000c2")
	ownerViewer := Relation{Kind: RelOwner, OwnerRole: RoleViewer}
	ownerAdmin := Relation{Kind: RelOwner, OwnerRole: RoleAdmin}
	ownerOwner := Relation{Kind: RelOwner, OwnerRole: RoleOwner}
	metrics := shareRel(ShareMetrics, RoleAdmin, shareID)
	deployViewer := shareRel(ShareDeploy, RoleViewer, shareID)
	deployAdmin := shareRel(ShareDeploy, RoleAdmin, shareID)
	none := Relation{Kind: RelNone}

	ok := ""
	no := "forbidden"
	miss := "not_found"
	actors := []struct {
		name string
		rel  Relation
	}{
		{"owner_viewer", ownerViewer},
		{"owner_admin", ownerAdmin},
		{"owner_owner", ownerOwner},
		{"metrics", metrics},
		{"deploy_viewer", deployViewer},
		{"deploy_admin", deployAdmin},
		{"none", none},
	}
	// cap, service project, then one code per actor in the order above.
	// "ok" is allow. Phase 2 logs and deploy have no capabilities here.
	rows := []struct {
		cap     string
		service uuid.UUID
		want    []string
	}{
		{CapHostView, uuid.Nil, []string{ok, ok, ok, ok, ok, ok, miss}},
		{CapHostServices, uuid.Nil, []string{ok, ok, ok, no, ok, ok, miss}},
		{CapServiceRead, shareID, []string{ok, ok, ok, no, ok, ok, miss}},
		{CapServiceRead, otherID, []string{ok, ok, ok, no, no, no, miss}},
		{CapServiceWrite, shareID, []string{no, ok, ok, no, no, ok, miss}},
		{CapServiceWrite, otherID, []string{no, ok, ok, no, no, no, miss}},
		{CapHostAdmin, uuid.Nil, []string{no, ok, ok, no, no, no, miss}},
	}
	if len(rows) == 0 {
		t.Fatal("empty matrix")
	}
	for _, row := range rows {
		if len(row.want) != len(actors) {
			t.Fatalf("%s: %d wants", row.cap, len(row.want))
		}
		for i, actor := range actors {
			err := AuthorizeHost(actor.rel, row.cap, row.service)
			got := ""
			var denied *Denied
			if errors.As(err, &denied) {
				got = denied.Code
			} else if err != nil {
				t.Fatalf("%s/%s: %v", row.cap, actor.name, err)
			}
			if got != row.want[i] {
				t.Fatalf("%s/%s service %s: got %q, want %q", row.cap, actor.name, row.service, got, row.want[i])
			}
		}
	}
}

func TestAuthorizeUnshare(t *testing.T) {
	target := uuid.MustParse("00000000-0000-4000-8000-0000000000d3")
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000e4")
	ownerAdmin := Relation{Kind: RelOwner, OwnerRole: RoleAdmin}
	ownerViewer := Relation{Kind: RelOwner, OwnerRole: RoleViewer}
	metricsAdmin := shareRel(ShareMetrics, RoleAdmin, target)
	deployViewer := shareRel(ShareDeploy, RoleViewer, target)
	none := Relation{Kind: RelNone}

	cases := []struct {
		name   string
		rel    Relation
		target uuid.UUID
		role   string
		member bool
		want   string
	}{
		{"owner admin removes any share", ownerAdmin, other, "", false, ""},
		{"owner viewer cannot", ownerViewer, target, RoleViewer, true, "forbidden"},
		{"owner viewer who admins the share can leave", ownerViewer, target, RoleAdmin, true, ""},
		{"metrics admin leaves", metricsAdmin, target, RoleAdmin, true, ""},
		{"deploy viewer cannot leave", deployViewer, target, RoleViewer, true, "forbidden"},
		{"admin of a different project cannot", metricsAdmin, other, "", false, "forbidden"},
		{"none", none, target, RoleAdmin, true, "not_found"},
	}
	for _, tc := range cases {
		err := AuthorizeUnshare(tc.rel, tc.target, tc.role, tc.member)
		got := ""
		var denied *Denied
		if errors.As(err, &denied) {
			got = denied.Code
		} else if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRelateOwnerWins(t *testing.T) {
	shareID := uuid.New()
	otherID := uuid.New()
	shares := []Share{
		{ProjectID: shareID, Level: ShareDeploy, Role: RoleAdmin},
		{ProjectID: otherID, Level: ShareMetrics, Role: RoleViewer},
	}
	got := Relate(RoleViewer, shares)
	if got.Kind != RelOwner || got.OwnerRole != RoleViewer || len(got.Shares) != 0 {
		t.Fatalf("owner wins: %+v", got)
	}
	got = Relate("", shares)
	if got.Kind != RelShare || len(got.Shares) != 2 || got.Shares[0].ProjectID != shareID || got.Shares[1].ProjectID != otherID {
		t.Fatalf("shares: %+v", got)
	}
	if HighestShareLevel(got.Shares) != ShareDeploy {
		t.Fatalf("highest %s", HighestShareLevel(got.Shares))
	}
	got = Relate("", nil)
	if got.Kind != RelNone || len(got.Shares) != 0 {
		t.Fatal("none")
	}
	if HighestShareLevel(nil) != "" {
		t.Fatal("highest of none")
	}
}

func TestAuthorizeHostSeveralShares(t *testing.T) {
	metricsID := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	deployID := uuid.MustParse("00000000-0000-4000-8000-0000000000a2")
	otherID := uuid.MustParse("00000000-0000-4000-8000-0000000000a3")
	// Metrics is first so a check that keeps only Shares[0] fails the deploy cells.
	mixed := Relation{Kind: RelShare, Shares: []Share{
		{ProjectID: metricsID, Level: ShareMetrics, Role: RoleAdmin},
		{ProjectID: deployID, Level: ShareDeploy, Role: RoleViewer},
	}}
	two := Relation{Kind: RelShare, Shares: []Share{
		{ProjectID: metricsID, Level: ShareDeploy, Role: RoleViewer},
		{ProjectID: deployID, Level: ShareDeploy, Role: RoleAdmin},
	}}
	if got := codes(AuthorizeHost(mixed, CapHostView, uuid.Nil)); got != "" {
		t.Fatalf("mixed view %s", got)
	}
	if got := codes(AuthorizeHost(mixed, CapHostServices, uuid.Nil)); got != "" {
		t.Fatalf("mixed services %s", got)
	}
	if got := codes(AuthorizeHost(mixed, CapServiceRead, deployID)); got != "" {
		t.Fatalf("mixed read deploy %s", got)
	}
	if got := codes(AuthorizeHost(mixed, CapServiceRead, metricsID)); got != "forbidden" {
		t.Fatalf("mixed read metrics %s", got)
	}
	if got := codes(AuthorizeHost(mixed, CapServiceRead, otherID)); got != "forbidden" {
		t.Fatalf("mixed read other %s", got)
	}
	if got := codes(AuthorizeHost(mixed, CapServiceWrite, deployID)); got != "forbidden" {
		t.Fatalf("mixed write deploy viewer %s", got)
	}
	filter := ServiceProjectFilter(mixed)
	if len(filter) != 1 || filter[0] != deployID {
		t.Fatalf("mixed filter %v", filter)
	}
	if got := codes(AuthorizeHost(two, CapServiceRead, metricsID)); got != "" {
		t.Fatalf("two read first %s", got)
	}
	if got := codes(AuthorizeHost(two, CapServiceRead, deployID)); got != "" {
		t.Fatalf("two read second %s", got)
	}
	if got := codes(AuthorizeHost(two, CapServiceWrite, metricsID)); got != "forbidden" {
		t.Fatalf("two write viewer %s", got)
	}
	if got := codes(AuthorizeHost(two, CapServiceWrite, deployID)); got != "" {
		t.Fatalf("two write admin %s", got)
	}
	if got := codes(AuthorizeHost(two, CapServiceRead, otherID)); got != "forbidden" {
		t.Fatalf("two read other %s", got)
	}
	both := ServiceProjectFilter(two)
	if len(both) != 2 || both[0] != metricsID || both[1] != deployID {
		t.Fatalf("two filter %v", both)
	}
	if ServiceProjectFilter(Relation{Kind: RelOwner, OwnerRole: RoleViewer}) != nil {
		t.Fatal("owner filter")
	}
	if empty := ServiceProjectFilter(shareRel(ShareMetrics, RoleAdmin, metricsID)); len(empty) != 0 {
		t.Fatalf("metrics filter %v", empty)
	}
}

func shareRel(level, role string, project uuid.UUID) Relation {
	return Relation{Kind: RelShare, Shares: []Share{{ProjectID: project, Level: level, Role: role}}}
}

func codes(err error) string {
	if err == nil {
		return ""
	}
	var denied *Denied
	if errors.As(err, &denied) {
		return denied.Code
	}
	return err.Error()
}

func TestHostRelationRequiresLookup(t *testing.T) {
	_, err := HostRelation(context.Background(), uuid.Nil, uuid.New())
	var denied *Denied
	if !errors.As(err, &denied) || denied.Code != "unauthorized" {
		t.Fatalf("nil user: %v", err)
	}
	_, err = HostRelation(context.Background(), uuid.New(), uuid.New())
	if err == nil || errors.As(err, &denied) {
		t.Fatalf("missing lookup: %v", err)
	}
}
