// Package memstore is the in-memory Store used by handler and WebSocket tests.
// A single mutex makes join-token consumption, invite acceptance, and device consumption atomic.
package memstore

import (
	"context"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

var dummyHash = make([]byte, 32)

// Mem implements store.Store.
type Mem struct {
	mu sync.Mutex

	users     map[uuid.UUID]store.User
	byEmail   map[string]uuid.UUID
	idents    map[uuid.UUID]store.Identity
	bySubject map[string]uuid.UUID

	sessions      map[uuid.UUID]sessionRec
	sessionByHash map[string]uuid.UUID

	oauthClients  map[string]store.OAuthClient
	oauthRequests map[string]store.OAuthRequest
	oauthCodes    map[uuid.UUID]oauthCodeRec
	codeByHash    map[string]uuid.UUID
	oauthGrants   map[uuid.UUID]store.OAuthGrant

	projects map[uuid.UUID]store.Project
	bySlug   map[string]uuid.UUID
	members  map[string]memberRec

	tokens      map[uuid.UUID]tokenRec
	tokenByHash map[string]uuid.UUID

	invites      map[uuid.UUID]inviteRec
	inviteByHash map[string]uuid.UUID

	hosts      map[uuid.UUID]store.Host
	creds      map[uuid.UUID]credRec
	credByHash map[string]uuid.UUID
	shares     map[string]store.HostShare

	services map[uuid.UUID]store.Service
	checks   map[uuid.UUID]store.HealthCheck

	batches map[string]time.Time
	samples []store.Sample

	audits    []store.AuditEntry
	nextAudit int64

	devices      map[uuid.UUID]store.Device
	deviceByHash map[string]uuid.UUID
	deviceByCode map[string]uuid.UUID

	entries                   map[uuid.UUID]store.CatalogEntry
	entryByName               map[string]uuid.UUID
	grants                    map[uuid.UUID][]store.CatalogGrant
	approvals                 map[string]store.CatalogApproval
	confirmations             map[string]confirmationRec
	serviceConfirmations      map[string]serviceConfirmationRec
	catalogWriteConfirmations map[string]catalogWriteConfirmationRec
	idempotency               map[string]store.IdempotencyRecord

	envSets      map[string]envSetRec
	envValues    map[string][]envValueRec
	registries   map[string]registryRec
	projectFiles map[string]fileRec
	imageDeploys map[uuid.UUID]imageDeployRec
}

type sessionRec struct {
	store.Session
	hash []byte
}

type oauthCodeRec struct {
	store.OAuthCode
	hash []byte
}

type memberRec struct {
	ProjectID uuid.UUID
	UserID    uuid.UUID
	Role      string
	AddedBy   uuid.UUID
	CreatedAt time.Time
}

type tokenRec struct {
	store.JoinToken
	hash []byte
}

type inviteRec struct {
	store.Invite
	hash []byte
}

type credRec struct {
	store.Credential
}

var _ store.Store = (*Mem)(nil)

func New() *Mem {
	return &Mem{
		users:                     map[uuid.UUID]store.User{},
		byEmail:                   map[string]uuid.UUID{},
		idents:                    map[uuid.UUID]store.Identity{},
		bySubject:                 map[string]uuid.UUID{},
		sessions:                  map[uuid.UUID]sessionRec{},
		sessionByHash:             map[string]uuid.UUID{},
		oauthClients:              map[string]store.OAuthClient{},
		oauthRequests:             map[string]store.OAuthRequest{},
		oauthCodes:                map[uuid.UUID]oauthCodeRec{},
		codeByHash:                map[string]uuid.UUID{},
		oauthGrants:               map[uuid.UUID]store.OAuthGrant{},
		projects:                  map[uuid.UUID]store.Project{},
		bySlug:                    map[string]uuid.UUID{},
		members:                   map[string]memberRec{},
		tokens:                    map[uuid.UUID]tokenRec{},
		tokenByHash:               map[string]uuid.UUID{},
		invites:                   map[uuid.UUID]inviteRec{},
		inviteByHash:              map[string]uuid.UUID{},
		hosts:                     map[uuid.UUID]store.Host{},
		creds:                     map[uuid.UUID]credRec{},
		credByHash:                map[string]uuid.UUID{},
		shares:                    map[string]store.HostShare{},
		services:                  map[uuid.UUID]store.Service{},
		checks:                    map[uuid.UUID]store.HealthCheck{},
		batches:                   map[string]time.Time{},
		devices:                   map[uuid.UUID]store.Device{},
		deviceByHash:              map[string]uuid.UUID{},
		deviceByCode:              map[string]uuid.UUID{},
		entries:                   map[uuid.UUID]store.CatalogEntry{},
		entryByName:               map[string]uuid.UUID{},
		grants:                    map[uuid.UUID][]store.CatalogGrant{},
		approvals:                 map[string]store.CatalogApproval{},
		confirmations:             map[string]confirmationRec{},
		serviceConfirmations:      map[string]serviceConfirmationRec{},
		catalogWriteConfirmations: map[string]catalogWriteConfirmationRec{},
		idempotency:               map[string]store.IdempotencyRecord{},
		envSets:                   map[string]envSetRec{},
		envValues:                 map[string][]envValueRec{},
		registries:                map[string]registryRec{},
		projectFiles:              map[string]fileRec{},
		imageDeploys:              map[uuid.UUID]imageDeployRec{},
	}
}

// UserCount is for tests that must show a rejected sign-in created nobody.
func (m *Mem) UserCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users)
}

func hashKey(h []byte) string { return hex.EncodeToString(h) }

func memberKey(project, user uuid.UUID) string {
	return project.String() + "/" + user.String()
}

func subjectKey(provider, subject string) string { return provider + "/" + subject }

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

func (m *Mem) UpsertGoogleUser(_ context.Context, in store.GoogleSignIn) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.bySubject[subjectKey("google", in.Subject)]; ok {
		ident := m.idents[id]
		ident.Email = in.Email
		ident.EmailVerified = true
		ident.LastLoginAt = in.At
		m.idents[id] = ident
		user := m.users[ident.UserID]
		if in.Name != "" {
			user.Name = in.Name
		}
		if in.AvatarURL != "" {
			user.AvatarURL = in.AvatarURL
		}
		m.users[user.ID] = user
		return user, nil
	}
	if _, taken := m.byEmail[in.Email]; taken {
		return store.User{}, store.ErrConflict
	}
	user := store.User{
		ID:        uuid.New(),
		Email:     in.Email,
		Name:      in.Name,
		AvatarURL: in.AvatarURL,
		CreatedAt: in.At,
	}
	ident := store.Identity{
		ID:              uuid.New(),
		UserID:          user.ID,
		Provider:        "google",
		ProviderSubject: in.Subject,
		Email:           in.Email,
		EmailVerified:   true,
		CreatedAt:       in.At,
		LastLoginAt:     in.At,
	}
	m.users[user.ID] = user
	m.byEmail[user.Email] = user.ID
	m.idents[ident.ID] = ident
	m.bySubject[subjectKey("google", in.Subject)] = ident.ID
	return user, nil
}

func (m *Mem) GetUser(_ context.Context, id uuid.UUID) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (m *Mem) UserByEmail(_ context.Context, email string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byEmail[email]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return m.users[id], nil
}

func (m *Mem) ListIdentities(_ context.Context, userID uuid.UUID) ([]store.Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Identity
	for _, ident := range m.idents {
		if ident.UserID == userID {
			out = append(out, ident)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if out == nil {
		out = []store.Identity{}
	}
	return out, nil
}

func (m *Mem) CreateSession(_ context.Context, userID uuid.UUID, tokenHash []byte, kind string, expiresAt, at time.Time) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return store.Session{}, store.ErrNotFound
	}
	sess := store.Session{
		ID:         uuid.New(),
		UserID:     userID,
		Kind:       kind,
		CreatedAt:  at,
		ExpiresAt:  expiresAt,
		LastSeenAt: at,
	}
	m.sessions[sess.ID] = sessionRec{Session: sess, hash: cloneBytes(tokenHash)}
	m.sessionByHash[hashKey(tokenHash)] = sess.ID
	return sess, nil
}

func (m *Mem) GetSession(_ context.Context, tokenHash []byte, now time.Time) (store.Session, store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessionByHash[hashKey(tokenHash)]
	if !ok {
		secret.Equal(tokenHash, dummyHash)
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	rec := m.sessions[id]
	if !secret.Equal(tokenHash, rec.hash) || !now.Before(rec.ExpiresAt) {
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	user := m.users[rec.UserID]
	if user.DisabledAt != nil || grantRevoked(m, rec.Session) {
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	return cloneSession(rec.Session), user, nil
}

func grantRevoked(m *Mem, sess store.Session) bool {
	if sess.GrantID == nil {
		return false
	}
	g, ok := m.oauthGrants[*sess.GrantID]
	return !ok || g.RevokedAt != nil
}

func cloneSession(s store.Session) store.Session {
	if s.GrantID != nil {
		id := *s.GrantID
		s.GrantID = &id
	}
	if s.CodeID != nil {
		id := *s.CodeID
		s.CodeID = &id
	}
	if s.RotatedAt != nil {
		t := *s.RotatedAt
		s.RotatedAt = &t
	}
	return s
}

func (m *Mem) DeleteSession(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.sessions[id]
	if !ok {
		return nil
	}
	delete(m.sessionByHash, hashKey(rec.hash))
	delete(m.sessions, id)
	return nil
}

func (m *Mem) TouchSession(_ context.Context, id uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.sessions[id]
	if !ok {
		return store.ErrNotFound
	}
	rec.LastSeenAt = at
	m.sessions[id] = rec
	return nil
}
