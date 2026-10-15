package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const maxServiceQueryLen = 100

func (s *Server) handleProjectServices(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	projectID, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, projectID, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(projectID), nil, nil, "", err)
		return
	}
	q, hash, offset, ok := s.projectServiceQuery(w, r)
	if !ok {
		return
	}
	page, err := s.Store.ListProjectServices(r.Context(), projectID, q, s.now())
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			writeCode(w, "bad_request", "invalid host_id")
			return
		}
		s.fail(w, err)
		return
	}
	for i := range page.Items {
		page.Items[i].HostStatus = s.hostStatus(store.Host{
			ID:        page.Items[i].HostID,
			AlwaysOn:  page.Items[i].HostAlwaysOn,
			RevokedAt: page.Items[i].HostRevokedAt,
		})
	}
	writeOK(w, http.StatusOK, map[string]any{
		"items":       nonNilSlice(page.Items),
		"next_cursor": servicePageCursor(offset, q.Limit, page.Total, hash, true),
		"prev_cursor": servicePageCursor(offset, q.Limit, page.Total, hash, false),
		"total":       page.Total,
	})
}

func (s *Server) projectServiceQuery(w http.ResponseWriter, r *http.Request) (store.ServiceListQuery, string, int, bool) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) > maxServiceQueryLen {
		writeCode(w, "bad_request", "invalid q")
		return store.ServiceListQuery{}, "", 0, false
	}
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "name"
	}
	switch sortKey {
	case "name", "host", "kind", "status", "last_seen":
	default:
		writeCode(w, "bad_request", "invalid sort")
		return store.ServiceListQuery{}, "", 0, false
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = "asc"
		if sortKey == "last_seen" {
			dir = "desc"
		}
	} else if dir != "asc" && dir != "desc" {
		writeCode(w, "bad_request", "invalid dir")
		return store.ServiceListQuery{}, "", 0, false
	}
	var hostID *uuid.UUID
	if raw := r.URL.Query().Get("host_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeCode(w, "bad_request", "invalid host_id")
			return store.ServiceListQuery{}, "", 0, false
		}
		hostID = &id
	}
	view := r.URL.Query().Get("view")
	switch view {
	case "", "all":
		view = "all"
	case "deploybot", "deploybot_and_discovered":
	default:
		writeCode(w, "bad_request", "invalid view")
		return store.ServiceListQuery{}, "", 0, false
	}
	limit, ok := s.limit(w, r)
	if !ok {
		return store.ServiceListQuery{}, "", 0, false
	}
	hostText := ""
	if hostID != nil {
		hostText = hostID.String()
	}
	hash := serviceQueryHash(q, hostText, sortKey, dir, view)
	offset, ok := s.serviceOffset(w, r, hash)
	if !ok {
		return store.ServiceListQuery{}, "", 0, false
	}
	return store.ServiceListQuery{
		Q: q, HostID: hostID, Sort: sortKey, Dir: dir, View: view, Limit: limit, Offset: offset,
	}, hash, offset, true
}

type serviceCursorWire struct {
	O int    `json:"o"`
	H string `json:"h"`
}

func serviceQueryHash(q, hostID, sortKey, dir, view string) string {
	raw, _ := json.Marshal([]string{q, hostID, sortKey, dir, view})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func (s *Server) serviceOffset(w http.ResponseWriter, r *http.Request, hash string) (int, bool) {
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		return 0, true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		writeCode(w, "bad_request", "invalid cursor")
		return 0, false
	}
	dec := json.NewDecoder(strings.NewReader(string(decoded)))
	dec.DisallowUnknownFields()
	var wire serviceCursorWire
	if err := dec.Decode(&wire); err != nil || dec.More() || wire.O < 0 || wire.H == "" {
		writeCode(w, "bad_request", "invalid cursor")
		return 0, false
	}
	if wire.H != hash {
		writeCode(w, "bad_request", "cursor does not match query")
		return 0, false
	}
	return wire.O, true
}

func servicePageCursor(offset, limit, total int, hash string, next bool) *string {
	var at int
	if next {
		at = offset + limit
		if at >= total {
			return nil
		}
	} else {
		if offset <= 0 {
			return nil
		}
		at = offset - limit
		if at < 0 {
			at = 0
		}
	}
	body, err := json.Marshal(serviceCursorWire{O: at, H: hash})
	if err != nil {
		return nil
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return &encoded
}
