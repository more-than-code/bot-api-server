// Package authz is the one permission check for every authenticated request.
package authz

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

const (
	// CapSession is any signed-in user. It is not a project capability.
	// Project routes use the capabilities below, which follow design §2.
	CapSession      = "session"
	CapRead         = "read"
	CapProbe        = "probe"
	CapJoinToken    = "join_token"
	CapMembers      = "members"
	CapProjectWrite = "project_write"
	// CapCatalogEdit is catalog replace: owner or admin. Create, delete, and
	// permissions stay CapProjectWrite.
	CapCatalogEdit = "catalog_edit"
	// CapHealthWrite and CapAuditRead are phase-1 admin+ routes that §2 does
	// not name on their own. See NOTES.md.
	CapHealthWrite = "health_write"
	CapAuditRead   = "audit_read"

	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Lookup reports the caller's role in a project. member is false when the
// user is not a member or the project does not exist.
type Lookup func(ctx context.Context, userID, projectID uuid.UUID) (role string, member bool, err error)

type ctxKey struct{}

// WithLookup stores the role lookup on the request context.
func WithLookup(ctx context.Context, lookup Lookup) context.Context {
	return context.WithValue(ctx, ctxKey{}, lookup)
}

// Denied is an authorization failure. Code is "forbidden", "not_found", or
// "unauthorized".
type Denied struct {
	Code string
}

func (d *Denied) Error() string { return d.Code }

// Allows reports whether role may use capability. The zero role never may,
// except that CapSession does not consult a role.
func Allows(role, capability string) bool {
	switch capability {
	case CapSession:
		return role == RoleOwner || role == RoleAdmin || role == RoleViewer
	case CapRead, CapProbe:
		return role == RoleOwner || role == RoleAdmin || role == RoleViewer
	case CapJoinToken, CapMembers, CapHealthWrite, CapAuditRead, CapCatalogEdit:
		return role == RoleOwner || role == RoleAdmin
	case CapProjectWrite:
		return role == RoleOwner
	default:
		return false
	}
}

// AllCapabilities is every capability Authorize understands, for tests.
func AllCapabilities() []string {
	return []string{
		CapSession,
		CapRead,
		CapProbe,
		CapJoinToken,
		CapMembers,
		CapProjectWrite,
		CapCatalogEdit,
		CapHealthWrite,
		CapAuditRead,
	}
}

// Authorize decides whether userID may use capability in projectID.
// CapSession ignores projectID and succeeds for any non-nil user.
// A non-member gets not_found. A member whose role is too low gets forbidden.
func Authorize(ctx context.Context, userID, projectID uuid.UUID, capability string) error {
	if userID == uuid.Nil {
		return &Denied{Code: "unauthorized"}
	}
	if capability == CapSession {
		return nil
	}
	lookup, _ := ctx.Value(ctxKey{}).(Lookup)
	if lookup == nil {
		return errors.New("authz lookup is not configured")
	}
	role, member, err := lookup(ctx, userID, projectID)
	if err != nil {
		return err
	}
	if !member {
		return &Denied{Code: "not_found"}
	}
	if !Allows(role, capability) {
		return &Denied{Code: "forbidden"}
	}
	return nil
}
