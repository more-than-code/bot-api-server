// Package store is the persistence contract for bot-api-server.
// Handlers and the agent socket depend on this interface. Postgres and the
// in-memory fake both implement it. Tokens are passed only as SHA-256 digests.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrUnknownMeasurement = errors.New("unknown measurement")
	ErrConflict           = errors.New("conflict")
	// ErrAutoActionLimit is an auto_action beyond AutoActionsPerHour.
	ErrAutoActionLimit = errors.New("auto action limit")
	// ErrPending is an idempotency key that was claimed and has no response yet.
	ErrPending      = errors.New("request in progress")
	ErrUnauthorized = errors.New("unauthorized")
	ErrOwner        = errors.New("owner")
	ErrExpired      = errors.New("expired")
	ErrState        = errors.New("invalid state")
	// ErrInvalid is a rejected write, such as sharing a host with its owner.
	ErrInvalid = errors.New("invalid")
	// ErrSecretFixed is a key PUT whose is_secret differs from the stored flag.
	ErrSecretFixed = errors.New("secret flag is fixed; delete and re-add the key")
	// ErrTooManyFiles is a new file name when the project already has MaxProjectFiles.
	ErrTooManyFiles = errors.New("too many files")
	// ErrReuse is a second redemption of an authorization code or a rotated refresh token.
	// The store has already revoked the tokens the contract requires.
	ErrReuse = errors.New("reuse")
	// ErrTarget is a resource that does not match the code or the grant family.
	ErrTarget = errors.New("invalid target")
)

// ValidShareLevel reports whether level is a host share level.
func ValidShareLevel(level string) bool {
	return level == "metrics" || level == "deploy"
}

// Cursor is the position of the last item returned by a list.
// Time-ordered lists set At and ID. ID is a UUID string, or the decimal
// audit id. Host lists set Rank, Name, and ID instead (rank 0 owned, rank 1
// shared) and leave At zero. A nil Rank is not a host cursor.
type Cursor struct {
	At   time.Time
	ID   string
	Rank *int
	Name string
}

type User struct {
	ID         uuid.UUID  `json:"id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	AvatarURL  string     `json:"avatar_url"`
	DisabledAt *time.Time `json:"-"`
	CreatedAt  time.Time  `json:"-"`
}

type Identity struct {
	ID              uuid.UUID `json:"-"`
	UserID          uuid.UUID `json:"-"`
	Provider        string    `json:"provider"`
	ProviderSubject string    `json:"-"`
	Email           string    `json:"email"`
	EmailVerified   bool      `json:"-"`
	CreatedAt       time.Time `json:"-"`
	LastLoginAt     time.Time `json:"-"`
}

type GoogleSignIn struct {
	Subject   string
	Email     string
	Name      string
	AvatarURL string
	At        time.Time
}

type Session struct {
	ID         uuid.UUID  `json:"-"`
	UserID     uuid.UUID  `json:"-"`
	Kind       string     `json:"-"`
	CreatedAt  time.Time  `json:"-"`
	ExpiresAt  time.Time  `json:"-"`
	LastSeenAt time.Time  `json:"-"`
	Audience   string     `json:"-"`
	GrantID    *uuid.UUID `json:"-"`
	ClientID   string     `json:"-"`
	CodeID     *uuid.UUID `json:"-"`
	RotatedAt  *time.Time `json:"-"`
}

type Project struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	Role      string     `json:"role"`
	CreatedBy uuid.UUID  `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	DeletedAt *time.Time `json:"-"`
}

type Member struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type JoinToken struct {
	ID           uuid.UUID  `json:"id"`
	ProjectID    uuid.UUID  `json:"-"`
	HostNameHint *string    `json:"host_name_hint"`
	CreatedBy    uuid.UUID  `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UsedAt       *time.Time `json:"used_at"`
	UsedByHostID *uuid.UUID `json:"used_by_host_id"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

// Invite is a project membership link. The plaintext token is never stored
// and is not a field on this struct.
type Invite struct {
	ID        uuid.UUID  `json:"id"`
	ProjectID uuid.UUID  `json:"-"`
	Role      string     `json:"role"`
	CreatedBy uuid.UUID  `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	RevokedAt *time.Time `json:"revoked_at"`
}

// InviteUsable is the v1.5 rule: not revoked, not expired, and uses remain.
func InviteUsable(inv Invite, at time.Time) bool {
	return inv.RevokedAt == nil && at.Before(inv.ExpiresAt) && inv.Uses < inv.MaxUses
}

// InviteLookup is the read-only preview of an invite. Role is the invite's
// role, not the caller's current membership role.
type InviteLookup struct {
	ProjectID     uuid.UUID
	ProjectName   string
	Role          string
	AlreadyMember bool
}

// InviteAccept is the result of joining, or of already being a member.
type InviteAccept struct {
	InviteID  uuid.UUID
	ProjectID uuid.UUID
	Role      string
}

type Host struct {
	ID           uuid.UUID  `json:"id"`
	ProjectID    uuid.UUID  `json:"project_id"`
	Name         string     `json:"name"`
	NodeType     string     `json:"node_type"`
	OS           string     `json:"os"`
	Arch         string     `json:"arch"`
	AlwaysOn     bool       `json:"always_on"`
	AgentVersion string     `json:"agent_version"`
	Status       string     `json:"status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	// Relation is "owner" or "shared" on host API responses. It is empty
	// when the row was not loaded for a project list or a caller relation.
	Relation string `json:"relation"`
	// ShareLevel is set when Relation is "shared". JSON null when the host
	// is owned by the project (or the caller) being described.
	ShareLevel *string `json:"share_level"`
	// Programs is the last hello programs object. Nil when the agent has
	// not reported a policy file.
	Programs *HostPrograms `json:"programs"`
}

// HostShare is one project a host is shared with.
type HostShare struct {
	HostID      uuid.UUID `json:"-"`
	ProjectID   uuid.UUID `json:"project_id"`
	ProjectName string    `json:"project_name"`
	Level       string    `json:"level"`
	CreatedBy   uuid.UUID `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// HostShareAccess is one share the caller is a member of on a host.
type HostShareAccess struct {
	ProjectID uuid.UUID
	Level     string
	Role      string
}

// HostFacts is the caller's membership in the host's owning project and
// every share project they belong to. OwnerRole is empty when they are not
// a member of the owning project. Shares is empty when they belong to none.
// The authz package decides that an owner role wins and drops the shares.
type HostFacts struct {
	OwnerRole string
	Shares    []HostShareAccess
}

// EnrollInput is the host facts from an enroll frame. Name is the requested
// hostname before collision suffixes.
type EnrollInput struct {
	Name         string
	NodeType     string
	OS           string
	Arch         string
	AlwaysOn     bool
	AgentVersion string
}

type Credential struct {
	ID        uuid.UUID
	HostID    uuid.UUID
	Hash      []byte
	RevokedAt *time.Time
}

type Service struct {
	ID            uuid.UUID `json:"id"`
	HostID        uuid.UUID `json:"host_id"`
	Name          string    `json:"name"`
	Source        string    `json:"source"`
	Kind          string    `json:"kind"`
	Ports         []int     `json:"ports"`
	SystemdUnit   *string   `json:"systemd_unit"`
	SystemdScope  *string   `json:"systemd_scope"`
	ContainerName *string   `json:"container_name"`
	ImageDigest   *string   `json:"image_digest"`
	ProcessName   *string   `json:"process_name"`
	ProjectID     uuid.UUID `json:"project_id"`
	DisplayName   *string   `json:"display_name"`
	OwnerUser     *string   `json:"owner_user"`
	CatalogEntry  *string   `json:"catalog_entry"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	// GoneAt is when the service was missing from its host's latest
	// complete services report. Null means that report included it.
	GoneAt *time.Time `json:"gone_at"`
	Health Health     `json:"health"`
}

// ProjectService is one row of GET /v1/projects/{id}/services.
// HostStatus is filled by the API with the same rules as Host.status.
// HostRevokedAt and HostAlwaysOn are not part of the JSON.
type ProjectService struct {
	Service
	HostName      string     `json:"host_name"`
	HostStatus    string     `json:"host_status"`
	ProjectName   string     `json:"project_name"`
	HostRevokedAt *time.Time `json:"-"`
	HostAlwaysOn  bool       `json:"-"`
}

// ServiceListQuery is the server-side filter for a project services list.
// Q is already trimmed. Sort is name, host, kind, status, or last_seen.
// Dir is asc or desc. Offset is the number of matching rows to skip.
// View is all, deploybot, or deploybot_and_discovered. Empty means all.
// The HTTP handler rejects any other value before it reaches the store.
type ServiceListQuery struct {
	Q      string
	HostID *uuid.UUID
	Sort   string
	Dir    string
	Limit  int
	Offset int
	View   string
}

// ServicePage is one page of a project services list. Total counts every
// matching row, including rows on other pages.
type ServicePage struct {
	Items []ProjectService
	Total int
}

type Health struct {
	Status        string     `json:"status"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	LatencyMS     *float64   `json:"latency_ms"`
	// Source is "docker" or "check" for the chosen row, and null when there is no row.
	Source *string `json:"source"`
}

type Discovered struct {
	Name          string
	Kind          string
	Ports         []int
	SystemdUnit   *string
	SystemdScope  *string
	ContainerName *string
	ImageDigest   *string
	ProcessName   *string
	// OwnerUser is the account that owns the listening socket.
	// The store drops values that are not printable or are longer than 64 bytes.
	OwnerUser *string
	// Owner is the agent-protocol v1.3 catalog owner. Nil when the agent
	// did not set one.
	Owner *DiscoveredOwner
}

type HealthCheck struct {
	ID              uuid.UUID `json:"id"`
	ServiceID       uuid.UUID `json:"service_id"`
	Protocol        string    `json:"protocol"`
	Port            int       `json:"port"`
	Path            *string   `json:"path"`
	IntervalSec     int       `json:"interval_sec"`
	ExpectStatusMin int       `json:"expect_status_min"`
	ExpectStatusMax int       `json:"expect_status_max"`
	Enabled         bool      `json:"enabled"`
}

type HealthCheckInput struct {
	Protocol        string
	Port            int
	Path            *string
	IntervalSec     int
	ExpectStatusMin int
	ExpectStatusMax int
	Enabled         bool
}

// AgentCheck is one health check in the agent config frame. Service is the
// service name, not its id.
type AgentCheck struct {
	ID              uuid.UUID
	Service         string
	Protocol        string
	Port            int
	Path            *string
	IntervalSec     int
	ExpectStatusMin int
	ExpectStatusMax int
}

// Sample is one validated metrics sample. HostID is set by the store on insert.
type Sample struct {
	HostID    uuid.UUID
	ServiceID *uuid.UUID
	M         string
	T         time.Time
	Tags      map[string]string
	Floats    map[string]float64
	Ints      map[string]int64
	Strs      map[string]string
	Nulls     map[string]bool
}

// ChartPoint is one aggregated bucket. V is nil when the bucket has no samples.
type ChartPoint struct {
	T time.Time
	V *float64
}

// ChartSeries is one named line. QueryChart returns at most 500 points.
type ChartSeries struct {
	Name   string
	Unit   string
	Points []ChartPoint
}

type ProcessItem struct {
	PID         int        `json:"pid"`
	ProcessName string     `json:"process_name"`
	User        string     `json:"user"`
	Cmdline     string     `json:"cmdline"`
	ServiceID   *uuid.UUID `json:"service_id"`
	CPUUsage    float64    `json:"cpu_usage"`
	MemoryRSS   int64      `json:"memory_rss"`
	MemoryUsage float64    `json:"memory_usage"`
	NumThreads  int        `json:"num_threads"`
	StartedAt   *time.Time `json:"started_at"`
}

type HealthPoint struct {
	T          time.Time  `json:"t"`
	CheckID    *uuid.UUID `json:"check_id"`
	Protocol   string     `json:"protocol"`
	Port       *int       `json:"port"`
	Result     string     `json:"result"`
	HTTPStatus *int       `json:"http_status"`
	LatencyMS  *float64   `json:"latency_ms"`
}

type AuditRow struct {
	At          time.Time
	ActorUserID *uuid.UUID
	Via         string
	ProjectID   *uuid.UUID
	HostID      *uuid.UUID
	ServiceID   *uuid.UUID
	Action      string
	Decision    string
	TaskID      *uuid.UUID
	Result      *string
	ErrorCode   *string
	Detail      map[string]any
}

type AuditEntry struct {
	ID          string          `json:"id"`
	At          time.Time       `json:"at"`
	ActorUserID *uuid.UUID      `json:"actor_user_id"`
	Via         string          `json:"via"`
	ProjectID   *uuid.UUID      `json:"project_id"`
	HostID      *uuid.UUID      `json:"host_id"`
	ServiceID   *uuid.UUID      `json:"service_id"`
	Action      string          `json:"action"`
	Decision    string          `json:"decision"`
	TaskID      *uuid.UUID      `json:"task_id"`
	Result      *string         `json:"result"`
	ErrorCode   *string         `json:"error_code"`
	Detail      json.RawMessage `json:"detail"`
}

type Device struct {
	ID         uuid.UUID
	Hash       []byte
	UserCode   string
	ClientName string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ApprovedBy *uuid.UUID
	ApprovedAt *time.Time
	DeniedAt   *time.Time
	ConsumedAt *time.Time
}

// Store is the full phase-1 persistence surface.
type Store interface {
	UpsertGoogleUser(ctx context.Context, in GoogleSignIn) (User, error)
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	ListIdentities(ctx context.Context, userID uuid.UUID) ([]Identity, error)

	CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte, kind string, expiresAt, at time.Time) (Session, error)
	// GetSession returns ErrUnauthorized when the token is unknown, expired, or the user is disabled.
	GetSession(ctx context.Context, tokenHash []byte, now time.Time) (Session, User, error)
	DeleteSession(ctx context.Context, id uuid.UUID) error
	TouchSession(ctx context.Context, id uuid.UUID, at time.Time) error

	CreateProject(ctx context.Context, ownerID uuid.UUID, name, baseSlug string, at time.Time) (Project, error)
	ListProjects(ctx context.Context, userID uuid.UUID, limit int, cursor *Cursor) ([]Project, *Cursor, error)
	ListAllProjects(ctx context.Context, userID uuid.UUID) ([]Project, error)
	GetProject(ctx context.Context, id uuid.UUID) (Project, error)
	// Role returns ErrNotFound when the user is not a member or the project is deleted or missing.
	Role(ctx context.Context, projectID, userID uuid.UUID) (string, error)
	RenameProject(ctx context.Context, id uuid.UUID, name string) (Project, error)
	// DeleteProject soft-deletes the project, revokes every host credential, and returns the host ids.
	// Shares of the project and of its hosts are removed. Invites of the project are deleted.
	// Services of the project that sit on another project's host move to that host's owner,
	// in the same transaction.
	DeleteProject(ctx context.Context, id uuid.UUID, at time.Time) ([]uuid.UUID, error)

	ListMembers(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]Member, *Cursor, error)
	AddMember(ctx context.Context, projectID, userID uuid.UUID, role string, addedBy uuid.UUID, at time.Time) (Member, error)
	UpdateMemberRole(ctx context.Context, projectID, userID uuid.UUID, role string) (Member, error)
	RemoveMember(ctx context.Context, projectID, userID uuid.UUID) error
	TransferOwnership(ctx context.Context, projectID, newOwner uuid.UUID) error

	CreateJoinToken(ctx context.Context, projectID uuid.UUID, hash []byte, hint *string, createdBy uuid.UUID, expiresAt, at time.Time) (JoinToken, error)
	ListJoinTokens(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]JoinToken, *Cursor, error)
	RevokeJoinToken(ctx context.Context, projectID, tokenID uuid.UUID, at time.Time) error
	// ConsumeJoinToken marks the token used and creates the host and credential in one step.
	// A bad, used, revoked, or expired token returns ErrUnauthorized.
	ConsumeJoinToken(ctx context.Context, tokenHash []byte, in EnrollInput, credentialID uuid.UUID, credentialHash []byte, at time.Time) (Host, error)

	CreateInvite(ctx context.Context, projectID uuid.UUID, hash []byte, role string, createdBy uuid.UUID, expiresAt, at time.Time, maxUses int) (Invite, error)
	// ListInvites returns every invite of the project, newest first, including unusable rows.
	ListInvites(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]Invite, *Cursor, error)
	// RevokeInvite sets revoked_at. A second call keeps the original time. Another project's invite is ErrNotFound.
	RevokeInvite(ctx context.Context, projectID, inviteID uuid.UUID, at time.Time) error
	// LookupInvite does not change state. An unknown digest, or an expired, revoked, used-up, or deleted-project invite, is ErrNotFound.
	LookupInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (InviteLookup, error)
	// AcceptInvite locks the invite and either returns the caller's current role or inserts one membership and increments uses.
	// Those two outcomes never both happen. Unknown and unusable tokens are ErrNotFound.
	AcceptInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (InviteAccept, error)

	GetHost(ctx context.Context, id uuid.UUID) (Host, error)
	// ListHosts returns hosts owned by projectID, then hosts shared with it.
	// Each group is ordered by name, then id. Relation and ShareLevel describe
	// that project, not the caller. A cursor resumes by comparing
	// (rank, name, id) with the cursor's values. It does not look the cursor
	// host up, so a host that was unshared or renamed does not drop the rest.
	ListHosts(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]Host, *Cursor, error)
	// HostFacts returns ErrNotFound when the host does not exist.
	HostFacts(ctx context.Context, userID, hostID uuid.UUID) (HostFacts, error)
	ListHostShares(ctx context.Context, hostID uuid.UUID) ([]HostShare, error)
	// PutHostShare inserts or updates a share. created is true on insert.
	// Sharing with the owning project returns ErrInvalid. A missing host or
	// a missing or deleted project returns ErrNotFound.
	PutHostShare(ctx context.Context, hostID, projectID uuid.UUID, level string, createdBy uuid.UUID, at time.Time) (HostShare, bool, error)
	// DeleteHostShare removes the share. ErrConflict when that project still
	// has services on the host, unless reassignOwner moves them to the host's
	// owning project in the same transaction. The returned share is the row
	// that was removed.
	DeleteHostShare(ctx context.Context, hostID, projectID uuid.UUID, reassignOwner bool) (HostShare, error)
	RevokeHost(ctx context.Context, hostID uuid.UUID, at time.Time) error
	TouchHost(ctx context.Context, hostID uuid.UUID, at time.Time, version, osName, arch string) error

	// LookupCredential finds the credential by digest. Revoked rows are returned
	// so the caller can answer forbidden rather than unauthenticated.
	// Unknown digests return ErrUnauthorized.
	LookupCredential(ctx context.Context, hash []byte) (Credential, Host, error)

	// ListServices returns at most 500 services on the host, ordered by name.
	// projects nil returns every service. A non-nil slice, including an empty
	// one, returns services whose project_id is in that set.
	ListServices(ctx context.Context, hostID uuid.UUID, projects []uuid.UUID, now time.Time) ([]Service, error)
	GetService(ctx context.Context, id uuid.UUID, now time.Time) (Service, error)
	// ListProjectServices returns the v1.3 rows for projectID, inside View.
	// Filtering, search, sort, total, and paging happen in the store.
	// A HostID those rows cannot reach returns ErrInvalid.
	ListProjectServices(ctx context.Context, projectID uuid.UUID, q ServiceListQuery, now time.Time) (ServicePage, error)
	// SetServiceDisplayName sets or clears display_name. name nil clears it.
	// A case-insensitive duplicate on the same host returns ErrConflict.
	// A missing service returns ErrNotFound. Rediscovery does not call this.
	SetServiceDisplayName(ctx context.Context, id uuid.UUID, name *string, now time.Time) (Service, error)
	// UpsertDiscovered stores one services report for hostID.
	// complete false writes nothing and does not read the host; presence
	// is ignored. complete true upserts items and clears gone_at on those
	// rows. presence true also sets gone_at to at on this host's other
	// rows that are still present. A row that is already gone keeps its
	// time. Other hosts are not modified. Ids, display_name, and health
	// checks are not modified.
	UpsertDiscovered(ctx context.Context, hostID uuid.UUID, items []Discovered, at time.Time, complete bool, presence bool) error
	ReplaceHealthChecks(ctx context.Context, serviceID uuid.UUID, checks []HealthCheckInput) ([]HealthCheck, error)
	ListHealthChecks(ctx context.Context, serviceID uuid.UUID) ([]HealthCheck, error)
	HealthChecksForHost(ctx context.Context, hostID uuid.UUID) ([]AgentCheck, error)

	// InsertBatch inserts samples once per (host, batch). inserted is false when the batch was already stored.
	InsertBatch(ctx context.Context, hostID, batchID uuid.UUID, samples []Sample, at time.Time) (inserted bool, err error)
	// QueryChart returns at most 500 aggregated buckets per series. It does not return raw samples.
	QueryChart(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time, stepSec int) ([]ChartSeries, error)
	LoadMetric(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time) ([]Sample, error)
	// LatestProcesses returns the newest sample group for the host, sorted and
	// limited in the store. It is not filtered by service project.
	LatestProcesses(ctx context.Context, hostID uuid.UUID, since time.Time, sortKey string, limit int) (*time.Time, []ProcessItem, error)
	HealthHistory(ctx context.Context, serviceID uuid.UUID, from, to time.Time, limit int) ([]HealthPoint, error)
	// DeleteExpiredDevices removes device codes with expires_at before the cutoff and returns their hashes.
	DeleteExpiredDevices(ctx context.Context, before time.Time) ([][]byte, error)
	// DeleteOldBatches removes ingest batch ids received before the cutoff.
	DeleteOldBatches(ctx context.Context, before time.Time) error

	InsertAudit(ctx context.Context, row AuditRow) error
	ListAudit(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]AuditEntry, *Cursor, error)

	CreateDevice(ctx context.Context, row Device) error
	DeviceByUserCode(ctx context.Context, code string) (Device, error)
	DeviceByHash(ctx context.Context, hash []byte) (Device, error)
	ApproveDevice(ctx context.Context, code string, userID uuid.UUID, at time.Time) error
	DenyDevice(ctx context.Context, code string, userID uuid.UUID, at time.Time) error
	// ConsumeDevice marks an approved, unconsumed, unexpired device used and returns it.
	// A lost race returns ErrConflict.
	ConsumeDevice(ctx context.Context, hash []byte, at time.Time) (Device, error)

	PutOAuthClient(ctx context.Context, c OAuthClient) error
	GetOAuthClient(ctx context.Context, id string) (OAuthClient, error)
	TouchOAuthClient(ctx context.Context, id string, at time.Time) error
	DeleteStalePublicClients(ctx context.Context, before time.Time) error

	InsertOAuthRequest(ctx context.Context, req OAuthRequest) error
	GetOAuthRequest(ctx context.Context, id string) (OAuthRequest, error)
	// ApproveOAuth reuses or creates the grant, stores the code, and marks the request allowed.
	// An unknown, expired, or already decided request returns ErrNotFound.
	ApproveOAuth(ctx context.Context, in ApproveCode) (OAuthGrant, error)
	// DenyOAuth marks the request denied. An unknown, expired, or decided request returns ErrNotFound.
	DenyOAuth(ctx context.Context, requestID string, userID uuid.UUID, at time.Time) (OAuthRequest, error)

	FindLiveGrant(ctx context.Context, userID uuid.UUID, clientID, resource string) (OAuthGrant, error)
	ListUserGrants(ctx context.Context, userID uuid.UUID) ([]OAuthGrant, error)
	// RevokeUserGrant revokes the family when the grant is active and owned by userID.
	// Anything else returns ErrNotFound.
	RevokeUserGrant(ctx context.Context, userID, grantID uuid.UUID, at time.Time) error

	PeekOAuthCode(ctx context.Context, hash []byte) (OAuthCode, error)
	// RedeemOAuthCode consumes a code and inserts the access and refresh sessions.
	// A second call revokes the sessions issued from the first redemption and returns ErrReuse.
	// A resource mismatch returns ErrTarget and does not consume the code.
	// A client or redirect mismatch returns ErrInvalid and does not consume the code.
	// An expired code returns ErrExpired and does not consume the code.
	RedeemOAuthCode(ctx context.Context, in RedeemCode) (access Session, refresh Session, err error)
	// RotateRefresh revokes the presented refresh token and inserts a new pair.
	// An already-rotated token revokes the family and returns ErrReuse.
	// A resource mismatch returns ErrTarget and does not rotate.
	RotateRefresh(ctx context.Context, in RotateRefresh) (access Session, refresh Session, err error)
	// IssueDelegated checks the subject under a lock and inserts an api_delegated session.
	// A subject that fails the oauth-v1 §4.3 rules returns ErrUnauthorized.
	IssueDelegated(ctx context.Context, in IssueDelegated) (Session, error)
	// IssueDeviceAccess opens a device grant family and inserts an mcp_access session.
	IssueDeviceAccess(ctx context.Context, in IssueDevice) (Session, error)
	// RevokeTokenFamily revokes the grant family of an mcp_access or mcp_refresh token.
	// Unknown digests return Found false and a nil error.
	RevokeTokenFamily(ctx context.Context, tokenHash []byte, at time.Time, allowClient string, confidential bool) (RevokeResult, error)

	CreateBoundSession(ctx context.Context, in BoundSession) (Session, error)

	CreateCatalogEntry(ctx context.Context, projectID uuid.UUID, in CatalogWrite) (CatalogEntry, error)
	// ReplaceCatalogEntry updates the spec. A changed spec_hash deletes every
	// host approval of the entry. oldHash is the hash before the write.
	ReplaceCatalogEntry(ctx context.Context, projectID uuid.UUID, name string, in CatalogWrite) (oldHash string, entry CatalogEntry, err error)
	// DeleteCatalogEntry removes the entry. Grants, approvals, and confirmations go with it.
	DeleteCatalogEntry(ctx context.Context, projectID uuid.UUID, name string) (CatalogEntry, error)
	GetCatalogEntry(ctx context.Context, projectID uuid.UUID, name string) (CatalogEntry, error)
	ListCatalogEntries(ctx context.Context, projectID uuid.UUID) ([]CatalogEntry, error)
	ListCatalogGrants(ctx context.Context, entryID uuid.UUID) ([]CatalogGrant, error)
	ReplaceCatalogGrants(ctx context.Context, projectID uuid.UUID, name string, grants []CatalogGrant) error

	// HostProjectRelation is "owner", "deploy", "metrics", or "" when the
	// host exists and the project cannot see it. A missing host is ErrNotFound.
	HostProjectRelation(ctx context.Context, projectID, hostID uuid.UUID) (string, error)
	ListCatalogApprovals(ctx context.Context, hostID uuid.UUID) ([]CatalogApproval, error)
	// ApproveCatalog records an approval for the entry's current spec.
	// A hash that is not current is ErrConflict. A missing entry or host is ErrNotFound.
	ApproveCatalog(ctx context.Context, hostID, entryID uuid.UUID, specHash string, approver uuid.UUID, at time.Time) (CatalogApproval, error)
	DeleteCatalogApproval(ctx context.Context, hostID, entryID uuid.UUID) error
	// UpsertPendingApproval stores a pending row for specHash.
	// An approved row for that same hash is left as it is.
	// A pending row, or an approved row for a different hash, becomes pending
	// with requested_by = userID.
	UpsertPendingApproval(ctx context.Context, entryID, hostID uuid.UUID, specHash string, userID uuid.UUID, at time.Time) error

	PutConfirmation(ctx context.Context, hash []byte, c CatalogConfirmation) error
	GetConfirmation(ctx context.Context, hash []byte) (CatalogConfirmation, error)
	// MarkConfirmationUsed sets used_at when the row is unused, unexpired, and owned by userID.
	// Anything else is ErrNotFound.
	MarkConfirmationUsed(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) error
	// PutServiceConfirmation inserts one health-check plan. A duplicate token hash is ErrConflict.
	PutServiceConfirmation(ctx context.Context, hash []byte, c ServiceConfirmation) error
	GetServiceConfirmation(ctx context.Context, hash []byte) (ServiceConfirmation, error)
	// MarkServiceConfirmationUsed sets used_at when the row is unused, unexpired, and owned by userID.
	// Anything else is ErrNotFound. It does not read catalog_confirmations.
	MarkServiceConfirmationUsed(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) error
	// CommitHealthReplacement locks the service row, compares its check set
	// with the confirmation's current hash, marks the plan used, and replaces
	// the checks. A mismatch is ErrConflict and does not mark the plan.
	// Unknown, used, expired, and foreign plans are ErrNotFound.
	// The console ReplaceHealthChecks takes the same service lock.
	CommitHealthReplacement(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) ([]HealthCheck, error)
	// PutCatalogWriteConfirmation inserts one catalog-write plan. A duplicate token hash is ErrConflict.
	PutCatalogWriteConfirmation(ctx context.Context, hash []byte, c CatalogWriteConfirmation) error
	GetCatalogWriteConfirmation(ctx context.Context, hash []byte) (CatalogWriteConfirmation, error)
	// CountEntryApprovals is the host-approval rows for the named entry, pending and approved.
	// A missing entry is 0.
	CountEntryApprovals(ctx context.Context, projectID uuid.UUID, name string) (int, error)
	// CommitCatalogWrite locks the plan, re-checks the name or spec_hash, applies
	// the write through the console create, replace, or delete path, and marks
	// the plan used. in.Name must equal the row's entry name. For create and
	// update, in.ImageRaw must be the same JSON value as the stored body.
	// A taken create name, a spec_hash mismatch, a missing update or delete
	// entry, or a body mismatch is ErrConflict and does not mark the plan.
	// Unknown, used, expired, and foreign plans are ErrNotFound.
	// oldHash is empty for create and is the previous hash for update.
	CommitCatalogWrite(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time, in CatalogWrite) (oldHash string, entry CatalogEntry, err error)
	// GetIdempotency returns ErrNotFound when the key is missing or older than IdempotencyTTL.
	// A stale row is deleted. A claimed row with no response has Pending set.
	GetIdempotency(ctx context.Context, userID uuid.UUID, key string, at time.Time) (IdempotencyRecord, error)
	// ClaimIdempotency inserts (user, key, hash) before the handler acts.
	// claimed is true only for the insert. A finished row with the same hash
	// is returned with claimed false. A different finished hash is ErrConflict.
	// A row with no response yet is ErrPending. A stale row is replaced.
	ClaimIdempotency(ctx context.Context, userID uuid.UUID, key string, hash []byte, at time.Time) (IdempotencyRecord, bool, error)
	PutIdempotency(ctx context.Context, userID uuid.UUID, key string, rec IdempotencyRecord) error
	ReplaceIdempotencyResponse(ctx context.Context, userID uuid.UUID, key string, status int, body []byte) error
	SetHostPrograms(ctx context.Context, hostID uuid.UUID, programs *HostPrograms) error

	// BeginImageOp inserts one in-flight deploy for (host, entry).
	// until is the deadline stored on the row. A second in-flight row whose
	// deadline is still after at returns ErrConflict. A row whose deadline
	// is missing or not after at is marked outcome timeout in the same
	// transaction, and the new row proceeds.
	BeginImageOp(ctx context.Context, entryID, hostID uuid.UUID, specHash string, by uuid.UUID, via string, at, until time.Time) (ImageDeploy, error)
	// FinishImageDeploy records the outcome and clears in-flight.
	FinishImageDeploy(ctx context.Context, id uuid.UUID, outcome string, digest *string, exitCode *int, at time.Time) (ImageDeploy, error)
	// ReleaseImageOp deletes an in-flight row. A finished row is left as it is.
	ReleaseImageOp(ctx context.Context, id uuid.UUID) error
	// ListImageDeploys returns finished rows newest first: the newest 50
	// non-automatic rows, plus at most the newest 20 automatic (via agent)
	// rows newer than the oldest of those (v1.15 rev 2 item 5).
	ListImageDeploys(ctx context.Context, entryID, hostID uuid.UUID) ([]ImageDeploy, error)
	// RollbackDigests returns up to three newest distinct succeeded or unchanged digests.
	RollbackDigests(ctx context.Context, entryID, hostID uuid.UUID) ([]string, error)
	// AutoActionTarget resolves an auto_action's project slug and entry name
	// for one host. ErrNotFound: unknown or deleted project, no image entry of
	// that name, or a host that is neither the project's nor shared with it
	// at deploy level. It writes nothing.
	AutoActionTarget(ctx context.Context, hostID uuid.UUID, projectSlug, entry string) (AutoTarget, error)
	// RecordAutoAction stores one agent automatic action as a finished
	// image_deploys row with via agent and no user (api-v1 v1.15 item 3).
	// spec_hash is the entry's last finished row on the host (the entry's
	// hash when there is none). A nil digest becomes the digest of the last
	// succeeded or unchanged user deploy (never an agent row), except for
	// auto_failed, which stays null. A replayed id returns
	// inserted false and writes nothing. ErrAutoActionLimit when the
	// (entry, host) already has AutoActionsPerHour agent rows in the hour
	// before in.At.
	RecordAutoAction(ctx context.Context, in AutoAction) (row ImageDeploy, inserted bool, err error)

	// ListEnvKeyNames returns key names only, including sets that have none.
	ListEnvKeyNames(ctx context.Context, projectID uuid.UUID) (map[string][]string, error)
	ListEnvSets(ctx context.Context, projectID uuid.UUID) ([]EnvSet, error)
	GetEnvSet(ctx context.Context, projectID uuid.UUID, name string) (EnvSet, error)
	// PutEnvSet replaces the set. A key already in the set keeps is_secret.
	// A key new to the set is secret when newKeysSecret is true.
	// Keys left out are removed.
	// Referencing image entries are rehashed. A changed hash voids approvals.
	PutEnvSet(ctx context.Context, projectID uuid.UUID, name string, keys []EnvSecret, actor uuid.UUID, at time.Time, newKeysSecret bool) (EnvSet, error)
	// PutEnvKey creates the set when it is absent and upserts one key.
	// A Secret that differs from the stored flag is ErrSecretFixed.
	// The bool is true when the key was created. Only a created key rehashes.
	PutEnvKey(ctx context.Context, projectID uuid.UUID, name string, in EnvKeyPut, actor uuid.UUID, at time.Time) (EnvKey, bool, error)
	// DeleteEnvKey removes one key and leaves the set, including an empty set.
	// A missing set or key is ErrNotFound. Referencing entries are rehashed.
	DeleteEnvKey(ctx context.Context, projectID uuid.UUID, name, key string, actor uuid.UUID, at time.Time) error
	// DeleteEnvSet returns ErrConflict when an image entry references the set.
	DeleteEnvSet(ctx context.Context, projectID uuid.UUID, name string) error
	// ListEnvMaterial returns plaintext and ciphertext for one set. It is not an HTTP body.
	ListEnvMaterial(ctx context.Context, projectID uuid.UUID, name string) ([]EnvMaterial, error)

	ListRegistries(ctx context.Context, projectID uuid.UUID) ([]Registry, error)
	PutRegistry(ctx context.Context, projectID uuid.UUID, host string, in RegistryWrite, actor uuid.UUID, at time.Time) (Registry, error)
	DeleteRegistry(ctx context.Context, projectID uuid.UUID, host string) error
	// GetRegistryMaterial returns one ciphertext. A missing host is ErrNotFound.
	GetRegistryMaterial(ctx context.Context, projectID uuid.UUID, host string) (RegistryMaterial, error)

	// ListProjectFiles returns metadata sorted by name. SHA256 is nil when secret.
	ListProjectFiles(ctx context.Context, projectID uuid.UUID) ([]ProjectFile, error)
	// GetProjectFile returns metadata. Plain is set only for a plain file.
	GetProjectFile(ctx context.Context, projectID uuid.UUID, name string) (ProjectFile, error)
	// PutProjectFile creates or replaces one file. A new name past MaxProjectFiles
	// is ErrTooManyFiles. Replacing an existing name is allowed at the limit.
	PutProjectFile(ctx context.Context, projectID uuid.UUID, name string, in FileWrite, actor uuid.UUID, at time.Time) (ProjectFile, error)
	// DeleteProjectFile returns *FileInUse when an image entry names the file.
	DeleteProjectFile(ctx context.Context, projectID uuid.UUID, name string) error
	// ListFileMaterial returns plaintext and ciphertext. It is not an HTTP body.
	ListFileMaterial(ctx context.Context, projectID uuid.UUID) ([]FileMaterial, error)
}
