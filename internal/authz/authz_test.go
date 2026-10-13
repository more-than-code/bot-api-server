package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// Expected grants are the phase-1 matrix. They are written out here so the
// test does not echo Allows back at itself.
func TestAuthorizeMatrix(t *testing.T) {
	const (
		session      = "session"
		read         = "read"
		probe        = "probe"
		joinToken    = "join_token"
		members      = "members"
		projectWrite = "project_write"
		healthWrite  = "health_write"
		auditRead    = "audit_read"
	)
	allowed := map[string]map[string]bool{
		RoleViewer: {
			session: true, read: true, probe: true,
			joinToken: false, members: false, projectWrite: false,
			healthWrite: false, auditRead: false,
		},
		RoleAdmin: {
			session: true, read: true, probe: true,
			joinToken: true, members: true, projectWrite: false,
			healthWrite: true, auditRead: true,
		},
		RoleOwner: {
			session: true, read: true, probe: true,
			joinToken: true, members: true, projectWrite: true,
			healthWrite: true, auditRead: true,
		},
	}
	caps := []string{session, read, probe, joinToken, members, projectWrite, healthWrite, auditRead}
	projectID := uuid.New()
	for _, role := range []string{RoleViewer, RoleAdmin, RoleOwner} {
		userID := uuid.New()
		ctx := WithLookup(context.Background(), func(context.Context, uuid.UUID, uuid.UUID) (string, bool, error) {
			return role, true, nil
		})
		for _, cap := range caps {
			err := Authorize(ctx, userID, projectID, cap)
			if allowed[role][cap] {
				if err != nil {
					t.Fatalf("%s %s: %v", role, cap, err)
				}
				continue
			}
			var denied *Denied
			if !errors.As(err, &denied) || denied.Code != "forbidden" {
				t.Fatalf("%s %s: got %v, want forbidden", role, cap, err)
			}
		}
	}
}

func TestAuthorizeNonMember(t *testing.T) {
	ctx := WithLookup(context.Background(), func(context.Context, uuid.UUID, uuid.UUID) (string, bool, error) {
		return "", false, nil
	})
	userID := uuid.New()
	for _, cap := range []string{"read", "probe", "join_token", "members", "project_write", "health_write", "audit_read", "nope"} {
		err := Authorize(ctx, userID, uuid.New(), cap)
		var denied *Denied
		if !errors.As(err, &denied) || denied.Code != "not_found" {
			t.Fatalf("%s: got %v, want not_found", cap, err)
		}
	}
	if err := Authorize(ctx, userID, uuid.Nil, CapSession); err != nil {
		t.Fatalf("session: %v", err)
	}
}

func TestAuthorizeAnonymousAndMemberUnknown(t *testing.T) {
	ctx := WithLookup(context.Background(), func(context.Context, uuid.UUID, uuid.UUID) (string, bool, error) {
		return RoleViewer, true, nil
	})
	err := Authorize(ctx, uuid.Nil, uuid.New(), CapRead)
	var denied *Denied
	if !errors.As(err, &denied) || denied.Code != "unauthorized" {
		t.Fatalf("anonymous: %v", err)
	}
	err = Authorize(ctx, uuid.New(), uuid.New(), "nope")
	if !errors.As(err, &denied) || denied.Code != "forbidden" {
		t.Fatalf("unknown cap: %v", err)
	}
}
