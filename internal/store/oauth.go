package store

import (
	"time"

	"github.com/google/uuid"
)

const (
	ClientDevice = "deploybot-cli"
	ClientMCP    = "bot-mcp-server"

	KindConsole     = "console"
	KindLegacyMCP   = "mcp"
	KindMCPAccess   = "mcp_access"
	KindMCPRefresh  = "mcp_refresh"
	KindDelegated   = "api_delegated"
	GrantKindOAuth  = "oauth"
	GrantKindDevice = "device"
	ClientPublic    = "public"
	ClientInternal  = "internal"
)

// OAuthClient is a public dynamic client or an internal client (bot-mcp-server, deploybot-cli).
// SecretHash is nil for public clients.
type OAuthClient struct {
	ID            string
	Name          string
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	AuthMethod    string
	SecretHash    []byte
	Kind          string
	CreatedAt     time.Time
	LastUsedAt    *time.Time
}

// OAuthRequest is a pending authorization. Decision is allow, deny, or empty.
type OAuthRequest struct {
	ID          string
	ClientID    string
	RedirectURI string
	Challenge   string
	State       string
	Resource    string
	Scope       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DecidedAt   *time.Time
	Decision    string
	UserID      *uuid.UUID
}

// OAuthGrant is one token family.
type OAuthGrant struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	ClientID     string
	ClientName   string
	Resource     string
	RedirectHost string
	Kind         string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	RevokedAt    *time.Time
}

// OAuthCode is stored as a SHA-256 digest. Hash is the digest.
type OAuthCode struct {
	ID          uuid.UUID
	Hash        []byte
	ClientID    string
	RedirectURI string
	Challenge   string
	Resource    string
	UserID      uuid.UUID
	GrantID     uuid.UUID
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UsedAt      *time.Time
}

// ApproveCode is the consent approval. CodeHash is the SHA-256 of the plaintext code.
type ApproveCode struct {
	RequestID    string
	UserID       uuid.UUID
	At           time.Time
	CodeHash     []byte
	CodeExpires  time.Time
	RedirectHost string
}

// RedeemCode consumes an authorization code and inserts the first token pair.
type RedeemCode struct {
	Hash           []byte
	ClientID       string
	RedirectURI    string
	Resource       string
	At             time.Time
	AccessHash     []byte
	AccessExpires  time.Time
	RefreshHash    []byte
	RefreshExpires time.Time
	Audience       string
}

// RotateRefresh replaces one refresh token with a new access and refresh pair.
// ResourceSet is false when the client omitted resource.
type RotateRefresh struct {
	Hash           []byte
	ClientID       string
	Resource       string
	ResourceSet    bool
	At             time.Time
	AccessHash     []byte
	AccessExpires  time.Time
	RefreshHash    []byte
	RefreshExpires time.Time
	Audience       string
}

// IssueDelegated is an RFC 8693 exchange. SubjectAudience is the audience the subject must carry.
type IssueDelegated struct {
	SubjectHash     []byte
	TokenHash       []byte
	Audience        string
	SubjectAudience string
	ExpiresAt       time.Time
	At              time.Time
}

// IssueDevice is the device-flow session: mcp_access, no refresh token.
type IssueDevice struct {
	UserID    uuid.UUID
	TokenHash []byte
	Audience  string
	ExpiresAt time.Time
	At        time.Time
}

// BoundSession inserts one session with the OAuth columns set.
type BoundSession struct {
	UserID    uuid.UUID
	TokenHash []byte
	Kind      string
	ExpiresAt time.Time
	At        time.Time
	Audience  string
	GrantID   *uuid.UUID
	ClientID  string
	CodeID    *uuid.UUID
}

// RevokeResult is the outcome of a revocation attempt.
// Found is false for an unknown digest. Revoked is true when a family was revoked.
type RevokeResult struct {
	Found    bool
	Revoked  bool
	UserID   uuid.UUID
	GrantID  uuid.UUID
	ClientID string
}
