package authz

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

const (
	RelOwner = "owner"
	RelShare = "share"
	RelNone  = "none"

	ShareMetrics = "metrics"
	ShareDeploy  = "deploy"

	// Host and service capabilities. AuthorizeHost is the check.
	// Project routes keep using Authorize.
	// CapHostView is any relation to the host. It covers seeing the host,
	// its status and metrics, the full process list, and host snapshot.
	CapHostView     = "host_view"
	CapHostServices = "host_services"
	CapServiceRead  = "service_read"
	// CapServiceWrite is the service edit capability in spec-shared-hosts §4:
	// an owner admin+, or a deploy-share admin for that service's own project.
	// Health-check replacement and PATCH display_name both use it.
	CapServiceWrite = "service_write"
	CapHostAdmin    = "host_admin"
)

// Share is one project this caller belongs to that the host is shared with.
type Share struct {
	ProjectID uuid.UUID
	Level     string
	Role      string
}

// Relation is one user's access to one host. Kind is owner, share, or none.
// Shares holds every share the caller belongs to. Owner wins when the user is
// also a member of the owning project: Shares is then empty.
type Relation struct {
	Kind      string
	OwnerRole string
	Shares    []Share
}

// Relate builds a relation. A non-empty owner role wins and drops every share.
func Relate(ownerRole string, shares []Share) Relation {
	if ownerRole != "" {
		return Relation{Kind: RelOwner, OwnerRole: ownerRole}
	}
	kept := make([]Share, 0, len(shares))
	for _, sh := range shares {
		if sh.ProjectID == uuid.Nil {
			continue
		}
		if sh.Level != ShareMetrics && sh.Level != ShareDeploy {
			continue
		}
		kept = append(kept, sh)
	}
	if len(kept) == 0 {
		return Relation{Kind: RelNone}
	}
	return Relation{Kind: RelShare, Shares: kept}
}

// HighestShareLevel is deploy when any share is deploy, otherwise metrics.
// An empty list returns "".
func HighestShareLevel(shares []Share) string {
	level := ""
	for _, sh := range shares {
		if sh.Level == ShareDeploy {
			return ShareDeploy
		}
		if sh.Level == ShareMetrics {
			level = ShareMetrics
		}
	}
	return level
}

// ServiceProjectFilter is the project set for the service list.
// Nil means every service on the host (an owner). A share returns the
// deploy-level project ids only. That slice is empty when none of the
// shares are deploy, and an empty slice matches no rows.
// The process list is not filtered: it uses CapHostView.
func ServiceProjectFilter(rel Relation) []uuid.UUID {
	if rel.Kind != RelShare {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(rel.Shares))
	for _, sh := range rel.Shares {
		if sh.Level == ShareDeploy && sh.ProjectID != uuid.Nil {
			ids = append(ids, sh.ProjectID)
		}
	}
	return ids
}

// HostLookup loads the relation for a user and a host.
type HostLookup func(ctx context.Context, userID, hostID uuid.UUID) (Relation, error)

type hostKey struct{}

// WithHostLookup stores the host relation lookup on the request context.
func WithHostLookup(ctx context.Context, lookup HostLookup) context.Context {
	return context.WithValue(ctx, hostKey{}, lookup)
}

// HostRelation returns the caller's relation to hostID.
// A nil user is unauthorized. A missing lookup is a programmer error.
func HostRelation(ctx context.Context, userID, hostID uuid.UUID) (Relation, error) {
	if userID == uuid.Nil {
		return Relation{}, &Denied{Code: "unauthorized"}
	}
	lookup, _ := ctx.Value(hostKey{}).(HostLookup)
	if lookup == nil {
		return Relation{}, errors.New("authz host lookup is not configured")
	}
	rel, err := lookup(ctx, userID, hostID)
	if err != nil {
		return Relation{}, err
	}
	if rel.Kind == "" {
		rel.Kind = RelNone
	}
	return rel, nil
}

// AuthorizeHost decides whether rel may use capability.
// serviceProjectID is the service's project for service_read and service_write.
// It is ignored for host-level capabilities. None is not_found. A relation
// that is too weak is forbidden.
func AuthorizeHost(rel Relation, capability string, serviceProjectID uuid.UUID) error {
	if rel.Kind != RelOwner && rel.Kind != RelShare {
		return &Denied{Code: "not_found"}
	}
	if !hostAllows(rel, capability, serviceProjectID) {
		return &Denied{Code: "forbidden"}
	}
	return nil
}

// AuthorizeUnshare decides whether rel may remove the share with targetProjectID.
// An owner admin may remove any share. An admin of that sharing project may
// remove it (leave the share), including when they are also an owner-project
// viewer. None is not_found.
func AuthorizeUnshare(rel Relation, targetProjectID uuid.UUID, targetRole string, targetMember bool) error {
	if rel.Kind != RelOwner && rel.Kind != RelShare {
		return &Denied{Code: "not_found"}
	}
	if rel.Kind == RelOwner && adminRole(rel.OwnerRole) {
		return nil
	}
	if targetMember && targetProjectID != uuid.Nil && adminRole(targetRole) {
		return nil
	}
	return &Denied{Code: "forbidden"}
}

func hostAllows(rel Relation, capability string, serviceProjectID uuid.UUID) bool {
	owner := rel.Kind == RelOwner
	share := rel.Kind == RelShare
	switch capability {
	case CapHostView:
		return owner || share
	case CapHostServices:
		return owner || hasLevel(rel, ShareDeploy)
	case CapServiceRead:
		_, ok := deployShare(rel, serviceProjectID)
		return owner || ok
	case CapServiceWrite:
		if owner {
			return adminRole(rel.OwnerRole)
		}
		sh, ok := deployShare(rel, serviceProjectID)
		return ok && adminRole(sh.Role)
	case CapHostAdmin:
		return owner && adminRole(rel.OwnerRole)
	default:
		return false
	}
}

// deployShare is the caller's deploy share for this service's project.
// A metrics share of that project, or no share of it, does not match.
func deployShare(rel Relation, projectID uuid.UUID) (Share, bool) {
	if rel.Kind != RelShare || projectID == uuid.Nil {
		return Share{}, false
	}
	for _, sh := range rel.Shares {
		if sh.ProjectID == projectID && sh.Level == ShareDeploy {
			return sh, true
		}
	}
	return Share{}, false
}

func hasLevel(rel Relation, level string) bool {
	if rel.Kind != RelShare {
		return false
	}
	for _, sh := range rel.Shares {
		if sh.Level == level {
			return true
		}
	}
	return false
}

func adminRole(role string) bool {
	return role == RoleOwner || role == RoleAdmin
}

// ProjectServiceVisible is the v1.3 project-services row rule.
// owned is true when projectID owns the host. shareLevel is that host's
// share with projectID, or "" when there is no share. Owning the host
// shows every service on it. A deploy share shows only services whose
// project is projectID. A metrics share shows none.
func ProjectServiceVisible(owned bool, shareLevel string, serviceProject, projectID uuid.UUID) bool {
	if projectID == uuid.Nil {
		return false
	}
	if owned {
		return true
	}
	return shareLevel == ShareDeploy && serviceProject == projectID
}

// ProjectHostReached reports whether a project services list may filter
// to this host. Metrics shares and hosts with no relation are not reached.
func ProjectHostReached(owned bool, shareLevel string) bool {
	return owned || shareLevel == ShareDeploy
}
