// Package audit writes append-only audit rows. It never records tokens.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	ActionSignIn            = "sign_in"
	ActionProjectCreate     = "project.create"
	ActionProjectRename     = "project.rename"
	ActionProjectDelete     = "project.delete"
	ActionProjectTransfer   = "project.transfer"
	ActionMemberAdd         = "member.add"
	ActionMemberUpdate      = "member.update"
	ActionMemberRemove      = "member.remove"
	ActionJoinCreate        = "join_token.create"
	ActionJoinRevoke        = "join_token.revoke"
	ActionInviteCreate      = "invite.create"
	ActionInviteRevoke      = "invite.revoke"
	ActionInviteAccept      = "invite.accept"
	ActionHostEnroll        = "host.enroll"
	ActionHostRevoke        = "host.revoke"
	ActionHostShare         = "host.share"
	ActionHostShareUpdate   = "host.share_update"
	ActionHostUnshare       = "host.unshare"
	ActionHealthChecks      = "health_checks.replace"
	ActionServiceRename     = "service.rename"
	ActionSnapshot          = "host.snapshot"
	ActionProbe             = "service.probe"
	ActionDeviceApprove     = "device.approve"
	ActionDeviceDeny        = "device.deny"
	ActionOAuthRegister     = "oauth.client_register"
	ActionOAuthAuthorize    = "oauth.authorize"
	ActionOAuthTokenRevoke  = "oauth.token_revoke"
	ActionOAuthRefreshReuse = "oauth.refresh_reuse"

	ViaConsole = "console"
	ViaMCP     = "mcp"
	ViaAgent   = "agent"
	ViaSystem  = "system"

	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
)

// Writer appends audit rows. A write failure is logged and not returned:
// the caller's HTTP result must not depend on the audit insert succeeding
// after the action has already committed. Callers that need the insert to
// be part of the action use the store directly inside the same transaction.
// Phase 1 records the audit after the action.
type Writer struct {
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
}

// Record inserts one audit row. Nil detail becomes an empty object.
func (w Writer) Record(ctx context.Context, row store.AuditRow) {
	if w.Store == nil {
		return
	}
	if row.At.IsZero() && w.Now != nil {
		row.At = w.Now()
	}
	if row.At.IsZero() {
		row.At = time.Now().UTC()
	}
	if row.Detail == nil {
		row.Detail = map[string]any{}
	}
	if err := w.Store.InsertAudit(ctx, row); err != nil {
		log := w.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("audit write failed", "action", row.Action)
	}
}
