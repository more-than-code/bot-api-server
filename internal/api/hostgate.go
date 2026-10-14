package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// gateHost loads the caller's host relation and authorizes capability.
// serviceProject is the service's project for service-scoped capabilities.
func (s *Server) gateHost(w http.ResponseWriter, r *http.Request, p principal, host store.Host, capability string, serviceProject *uuid.UUID, serviceID *uuid.UUID, action string) (authz.Relation, bool) {
	rel, err := authz.HostRelation(r.Context(), p.User.ID, host.ID)
	if err != nil {
		var denied *authz.Denied
		if errors.As(err, &denied) {
			s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), serviceID, action, err)
			return authz.Relation{}, false
		}
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return authz.Relation{}, false
		}
		s.fail(w, err)
		return authz.Relation{}, false
	}
	project := uuid.Nil
	if serviceProject != nil {
		project = *serviceProject
	}
	if err := authz.AuthorizeHost(rel, capability, project); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), serviceID, action, err)
		return authz.Relation{}, false
	}
	return rel, true
}

func withRelation(h store.Host, rel authz.Relation) store.Host {
	switch rel.Kind {
	case authz.RelOwner:
		h.Relation = "owner"
		h.ShareLevel = nil
	case authz.RelShare:
		h.Relation = "shared"
		level := authz.HighestShareLevel(rel.Shares)
		if level != "" {
			h.ShareLevel = &level
		}
	default:
		h.Relation = ""
		h.ShareLevel = nil
	}
	return h
}
