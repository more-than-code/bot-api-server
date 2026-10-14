package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) PutOAuthClient(_ context.Context, c store.OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.oauthClients[c.ID]; ok {
		if c.Kind != store.ClientInternal || existing.Kind != store.ClientInternal {
			return store.ErrConflict
		}
		existing.Name = c.Name
		existing.AuthMethod = c.AuthMethod
		existing.SecretHash = cloneBytes(c.SecretHash)
		m.oauthClients[c.ID] = existing
		return nil
	}
	c.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	c.GrantTypes = append([]string(nil), c.GrantTypes...)
	c.ResponseTypes = append([]string(nil), c.ResponseTypes...)
	c.SecretHash = cloneBytes(c.SecretHash)
	m.oauthClients[c.ID] = c
	return nil
}

func (m *Mem) GetOAuthClient(_ context.Context, id string) (store.OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.oauthClients[id]
	if !ok {
		return store.OAuthClient{}, store.ErrNotFound
	}
	c.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	c.GrantTypes = append([]string(nil), c.GrantTypes...)
	c.ResponseTypes = append([]string(nil), c.ResponseTypes...)
	c.SecretHash = cloneBytes(c.SecretHash)
	return c, nil
}

func (m *Mem) TouchOAuthClient(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.oauthClients[id]
	if !ok {
		return store.ErrNotFound
	}
	c.LastUsedAt = &at
	m.oauthClients[id] = c
	return nil
}

func (m *Mem) DeleteStalePublicClients(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.oauthClients {
		if c.Kind != store.ClientPublic {
			continue
		}
		seen := c.CreatedAt
		if c.LastUsedAt != nil {
			seen = *c.LastUsedAt
		}
		if seen.Before(before) {
			m.deleteClientLocked(id)
		}
	}
	return nil
}

func (m *Mem) deleteClientLocked(id string) {
	delete(m.oauthClients, id)
	for gid, g := range m.oauthGrants {
		if g.ClientID == id {
			m.revokeFamilyLocked(gid, time.Now().UTC())
			delete(m.oauthGrants, gid)
		}
	}
	for rid, req := range m.oauthRequests {
		if req.ClientID == id {
			delete(m.oauthRequests, rid)
		}
	}
	for cid, code := range m.oauthCodes {
		if code.ClientID == id {
			delete(m.codeByHash, hashKey(code.hash))
			delete(m.oauthCodes, cid)
		}
	}
}

func (m *Mem) InsertOAuthRequest(_ context.Context, req store.OAuthRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.oauthClients[req.ClientID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := m.oauthRequests[req.ID]; ok {
		return store.ErrConflict
	}
	m.oauthRequests[req.ID] = req
	return nil
}

func (m *Mem) GetOAuthRequest(_ context.Context, id string) (store.OAuthRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.oauthRequests[id]
	if !ok {
		return store.OAuthRequest{}, store.ErrNotFound
	}
	return req, nil
}

func (m *Mem) ApproveOAuth(_ context.Context, in store.ApproveCode) (store.OAuthGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.oauthRequests[in.RequestID]
	if !ok || req.DecidedAt != nil || !in.At.Before(req.ExpiresAt) {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	client, ok := m.oauthClients[req.ClientID]
	if !ok {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	grant, ok := m.liveGrantLocked(in.UserID, req.ClientID, req.Resource)
	if !ok {
		grant = store.OAuthGrant{
			ID: uuid.New(), UserID: in.UserID, ClientID: req.ClientID, ClientName: client.Name,
			Resource: req.Resource, RedirectHost: in.RedirectHost, Kind: store.GrantKindOAuth, CreatedAt: in.At,
		}
		m.oauthGrants[grant.ID] = grant
	} else {
		grant.RedirectHost = in.RedirectHost
		at := in.At
		grant.LastUsedAt = &at
		m.oauthGrants[grant.ID] = grant
	}
	codeID := uuid.New()
	m.oauthCodes[codeID] = oauthCodeRec{store.OAuthCode{
		ID: codeID, Hash: cloneBytes(in.CodeHash), ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Challenge: req.Challenge, Resource: req.Resource, UserID: in.UserID, GrantID: grant.ID,
		CreatedAt: in.At, ExpiresAt: in.CodeExpires,
	}, cloneBytes(in.CodeHash)}
	m.codeByHash[hashKey(in.CodeHash)] = codeID
	at := in.At
	uid := in.UserID
	req.DecidedAt = &at
	req.Decision = "allow"
	req.UserID = &uid
	m.oauthRequests[req.ID] = req
	client.LastUsedAt = &at
	m.oauthClients[client.ID] = client
	return grant, nil
}

func (m *Mem) DenyOAuth(_ context.Context, requestID string, userID uuid.UUID, at time.Time) (store.OAuthRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.oauthRequests[requestID]
	if !ok || req.DecidedAt != nil || !at.Before(req.ExpiresAt) {
		return store.OAuthRequest{}, store.ErrNotFound
	}
	req.DecidedAt = &at
	req.Decision = "deny"
	uid := userID
	req.UserID = &uid
	m.oauthRequests[requestID] = req
	return req, nil
}

func (m *Mem) liveGrantLocked(userID uuid.UUID, clientID, resource string) (store.OAuthGrant, bool) {
	for _, g := range m.oauthGrants {
		if g.UserID == userID && g.ClientID == clientID && g.Resource == resource && g.RevokedAt == nil && g.Kind == store.GrantKindOAuth {
			if c, ok := m.oauthClients[g.ClientID]; ok {
				g.ClientName = c.Name
			}
			return g, true
		}
	}
	return store.OAuthGrant{}, false
}

func (m *Mem) FindLiveGrant(_ context.Context, userID uuid.UUID, clientID, resource string) (store.OAuthGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.liveGrantLocked(userID, clientID, resource)
	if !ok {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	return g, nil
}

func (m *Mem) ListUserGrants(_ context.Context, userID uuid.UUID) ([]store.OAuthGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OAuthGrant
	for _, g := range m.oauthGrants {
		if g.UserID == userID && g.RevokedAt == nil {
			if c, ok := m.oauthClients[g.ClientID]; ok {
				g.ClientName = c.Name
			}
			out = append(out, g)
		}
	}
	sortGrants(out)
	if out == nil {
		out = []store.OAuthGrant{}
	}
	return out, nil
}

func sortGrants(out []store.OAuthGrant) {
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && grantLess(out[j], out[j-1]) {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
}

func grantLess(a, b store.OAuthGrant) bool {
	if a.CreatedAt.Equal(b.CreatedAt) {
		return a.ID.String() > b.ID.String()
	}
	return a.CreatedAt.After(b.CreatedAt)
}

func (m *Mem) RevokeUserGrant(_ context.Context, userID, grantID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.oauthGrants[grantID]
	if !ok || g.UserID != userID || g.RevokedAt != nil {
		return store.ErrNotFound
	}
	m.revokeFamilyLocked(grantID, at)
	return nil
}

func (m *Mem) revokeFamilyLocked(grantID uuid.UUID, at time.Time) {
	g := m.oauthGrants[grantID]
	g.RevokedAt = &at
	m.oauthGrants[grantID] = g
	for id, rec := range m.sessions {
		if rec.GrantID != nil && *rec.GrantID == grantID && rec.ExpiresAt.After(at) {
			rec.ExpiresAt = at
			m.sessions[id] = rec
		}
	}
}

func (m *Mem) PeekOAuthCode(_ context.Context, hash []byte) (store.OAuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.codeLocked(hash)
	if !ok {
		return store.OAuthCode{}, store.ErrNotFound
	}
	return code.OAuthCode, nil
}

func (m *Mem) codeLocked(hash []byte) (oauthCodeRec, bool) {
	id, ok := m.codeByHash[hashKey(hash)]
	if !ok {
		secret.Equal(hash, dummyHash)
		return oauthCodeRec{}, false
	}
	rec := m.oauthCodes[id]
	if !secret.Equal(hash, rec.hash) {
		return oauthCodeRec{}, false
	}
	return rec, true
}

func (m *Mem) RedeemOAuthCode(_ context.Context, in store.RedeemCode) (store.Session, store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.codeLocked(in.Hash)
	if !ok {
		return store.Session{}, store.Session{}, store.ErrNotFound
	}
	if code.UsedAt != nil {
		m.revokeFamilyLocked(code.GrantID, in.At)
		return store.Session{}, store.Session{}, store.ErrReuse
	}
	if !in.At.Before(code.ExpiresAt) {
		return store.Session{}, store.Session{}, store.ErrExpired
	}
	if code.Resource != in.Resource {
		return store.Session{}, store.Session{}, store.ErrTarget
	}
	if code.ClientID != in.ClientID || code.RedirectURI != in.RedirectURI {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	at := in.At
	code.UsedAt = &at
	m.oauthCodes[code.ID] = code
	codeID := code.ID
	grantID := code.GrantID
	access := m.insertBoundLocked(store.BoundSession{
		UserID: code.UserID, TokenHash: in.AccessHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.AccessExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: code.ClientID, CodeID: &codeID,
	})
	refresh := m.insertBoundLocked(store.BoundSession{
		UserID: code.UserID, TokenHash: in.RefreshHash, Kind: store.KindMCPRefresh,
		ExpiresAt: in.RefreshExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: code.ClientID, CodeID: &codeID,
	})
	m.touchFamilyLocked(grantID, code.ClientID, in.At)
	return access, refresh, nil
}

func (m *Mem) touchFamilyLocked(grantID uuid.UUID, clientID string, at time.Time) {
	if g, ok := m.oauthGrants[grantID]; ok {
		g.LastUsedAt = &at
		m.oauthGrants[grantID] = g
	}
	if c, ok := m.oauthClients[clientID]; ok {
		c.LastUsedAt = &at
		m.oauthClients[clientID] = c
	}
}

func (m *Mem) RotateRefresh(_ context.Context, in store.RotateRefresh) (store.Session, store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessionByHash[hashKey(in.Hash)]
	if !ok {
		secret.Equal(in.Hash, dummyHash)
		return store.Session{}, store.Session{}, store.ErrNotFound
	}
	rec := m.sessions[id]
	if !secret.Equal(in.Hash, rec.hash) || rec.Kind != store.KindMCPRefresh || rec.ClientID != in.ClientID {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	user := m.users[rec.UserID]
	if user.DisabledAt != nil || rec.GrantID == nil {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	grant, ok := m.oauthGrants[*rec.GrantID]
	if !ok {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	if rec.RotatedAt != nil {
		m.revokeFamilyLocked(*rec.GrantID, in.At)
		return store.Session{UserID: rec.UserID, GrantID: rec.GrantID}, store.Session{}, store.ErrReuse
	}
	if !in.At.Before(rec.ExpiresAt) || grant.RevokedAt != nil {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	if in.ResourceSet && grant.Resource != in.Resource {
		return store.Session{}, store.Session{}, store.ErrTarget
	}
	at := in.At
	rec.RotatedAt = &at
	rec.ExpiresAt = at
	m.sessions[id] = rec
	grantID := *rec.GrantID
	access := m.insertBoundLocked(store.BoundSession{
		UserID: rec.UserID, TokenHash: in.AccessHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.AccessExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: rec.ClientID,
	})
	refresh := m.insertBoundLocked(store.BoundSession{
		UserID: rec.UserID, TokenHash: in.RefreshHash, Kind: store.KindMCPRefresh,
		ExpiresAt: in.RefreshExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: rec.ClientID,
	})
	m.touchFamilyLocked(grantID, rec.ClientID, in.At)
	return access, refresh, nil
}

func (m *Mem) IssueDelegated(_ context.Context, in store.IssueDelegated) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessionByHash[hashKey(in.SubjectHash)]
	if !ok {
		secret.Equal(in.SubjectHash, dummyHash)
		return store.Session{}, store.ErrUnauthorized
	}
	rec := m.sessions[id]
	user := m.users[rec.UserID]
	var revoked bool
	if rec.GrantID != nil {
		if g, found := m.oauthGrants[*rec.GrantID]; !found || g.RevokedAt != nil {
			revoked = true
		}
	}
	if !secret.Equal(in.SubjectHash, rec.hash) || rec.Kind != store.KindMCPAccess || rec.Audience != in.SubjectAudience ||
		!in.At.Before(rec.ExpiresAt) || rec.RotatedAt != nil || revoked || user.DisabledAt != nil || rec.GrantID == nil || rec.ClientID == "" {
		return store.Session{}, store.ErrUnauthorized
	}
	grantID := *rec.GrantID
	sess := m.insertBoundLocked(store.BoundSession{
		UserID: rec.UserID, TokenHash: in.TokenHash, Kind: store.KindDelegated,
		ExpiresAt: in.ExpiresAt, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: rec.ClientID,
	})
	m.touchFamilyLocked(grantID, rec.ClientID, in.At)
	return sess, nil
}

func (m *Mem) IssueDeviceAccess(_ context.Context, in store.IssueDevice) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[in.UserID]; !ok {
		return store.Session{}, store.ErrNotFound
	}
	m.ensureDeviceClientLocked(in.At)
	grantID := uuid.New()
	m.oauthGrants[grantID] = store.OAuthGrant{
		ID: grantID, UserID: in.UserID, ClientID: store.ClientDevice, ClientName: store.ClientDevice,
		Resource: in.Audience, Kind: store.GrantKindDevice, CreatedAt: in.At,
	}
	return m.insertBoundLocked(store.BoundSession{
		UserID: in.UserID, TokenHash: in.TokenHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.ExpiresAt, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: store.ClientDevice,
	}), nil
}

func (m *Mem) ensureDeviceClientLocked(at time.Time) {
	if _, ok := m.oauthClients[store.ClientDevice]; ok {
		return
	}
	m.oauthClients[store.ClientDevice] = store.OAuthClient{
		ID: store.ClientDevice, Name: store.ClientDevice, RedirectURIs: []string{},
		GrantTypes: []string{}, ResponseTypes: []string{"code"}, AuthMethod: "none",
		Kind: store.ClientInternal, CreatedAt: at,
	}
}

func (m *Mem) RevokeTokenFamily(_ context.Context, tokenHash []byte, at time.Time, allowClient string, confidential bool) (store.RevokeResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessionByHash[hashKey(tokenHash)]
	if !ok {
		secret.Equal(tokenHash, dummyHash)
		return store.RevokeResult{}, nil
	}
	rec := m.sessions[id]
	if !secret.Equal(tokenHash, rec.hash) {
		return store.RevokeResult{}, nil
	}
	res := store.RevokeResult{Found: true, UserID: rec.UserID, ClientID: rec.ClientID}
	if rec.Kind != store.KindMCPAccess && rec.Kind != store.KindMCPRefresh {
		return res, nil
	}
	if !confidential && rec.ClientID != allowClient {
		return res, nil
	}
	if rec.GrantID == nil {
		return res, nil
	}
	g, ok := m.oauthGrants[*rec.GrantID]
	if !ok || g.RevokedAt != nil {
		return res, nil
	}
	m.revokeFamilyLocked(*rec.GrantID, at)
	res.Revoked = true
	res.GrantID = *rec.GrantID
	return res, nil
}

func (m *Mem) CreateBoundSession(_ context.Context, in store.BoundSession) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[in.UserID]; !ok {
		return store.Session{}, store.ErrNotFound
	}
	return m.insertBoundLocked(in), nil
}

func (m *Mem) insertBoundLocked(in store.BoundSession) store.Session {
	sess := store.Session{
		ID: uuid.New(), UserID: in.UserID, Kind: in.Kind, CreatedAt: in.At, ExpiresAt: in.ExpiresAt,
		LastSeenAt: in.At, Audience: in.Audience, ClientID: in.ClientID,
	}
	if in.GrantID != nil {
		id := *in.GrantID
		sess.GrantID = &id
	}
	if in.CodeID != nil {
		id := *in.CodeID
		sess.CodeID = &id
	}
	m.sessions[sess.ID] = sessionRec{Session: sess, hash: cloneBytes(in.TokenHash)}
	m.sessionByHash[hashKey(in.TokenHash)] = sess.ID
	return cloneSession(sess)
}
