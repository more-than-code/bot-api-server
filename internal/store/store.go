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
	ErrUnauthorized       = errors.New("unauthorized")
	ErrOwner              = errors.New("owner")
	ErrExpired            = errors.New("expired")
	ErrState              = errors.New("invalid state")
)

// Cursor is the position of the last item returned by a list.
// ID is a UUID string, or the decimal audit id.
type Cursor struct {
	At time.Time
	ID string
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
	ID         uuid.UUID `json:"-"`
	UserID     uuid.UUID `json:"-"`
	Kind       string    `json:"-"`
	CreatedAt  time.Time `json:"-"`
	ExpiresAt  time.Time `json:"-"`
	LastSeenAt time.Time `json:"-"`
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
	ProcessName   *string   `json:"process_name"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	Health        Health    `json:"health"`
}

type Health struct {
	Status        string     `json:"status"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	LatencyMS     *float64   `json:"latency_ms"`
}

type Discovered struct {
	Name          string
	Kind          string
	Ports         []int
	SystemdUnit   *string
	SystemdScope  *string
	ContainerName *string
	ProcessName   *string
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
	T          time.Time `json:"t"`
	CheckID    uuid.UUID `json:"check_id"`
	Result     string    `json:"result"`
	HTTPStatus *int      `json:"http_status"`
	LatencyMS  float64   `json:"latency_ms"`
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

	GetHost(ctx context.Context, id uuid.UUID) (Host, error)
	ListHosts(ctx context.Context, projectID uuid.UUID, limit int, cursor *Cursor) ([]Host, *Cursor, error)
	RevokeHost(ctx context.Context, hostID uuid.UUID, at time.Time) error
	TouchHost(ctx context.Context, hostID uuid.UUID, at time.Time, version, osName, arch string) error

	// LookupCredential finds the credential by digest. Revoked rows are returned
	// so the caller can answer forbidden rather than unauthenticated.
	// Unknown digests return ErrUnauthorized.
	LookupCredential(ctx context.Context, hash []byte) (Credential, Host, error)

	ListServices(ctx context.Context, hostID uuid.UUID, now time.Time) ([]Service, error)
	GetService(ctx context.Context, id uuid.UUID, now time.Time) (Service, error)
	UpsertDiscovered(ctx context.Context, hostID uuid.UUID, items []Discovered, at time.Time) error
	ReplaceHealthChecks(ctx context.Context, serviceID uuid.UUID, checks []HealthCheckInput) ([]HealthCheck, error)
	ListHealthChecks(ctx context.Context, serviceID uuid.UUID) ([]HealthCheck, error)
	HealthChecksForHost(ctx context.Context, hostID uuid.UUID) ([]AgentCheck, error)

	// InsertBatch inserts samples once per (host, batch). inserted is false when the batch was already stored.
	InsertBatch(ctx context.Context, hostID, batchID uuid.UUID, samples []Sample, at time.Time) (inserted bool, err error)
	// QueryChart returns at most 500 aggregated buckets per series. It does not return raw samples.
	QueryChart(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time, stepSec int) ([]ChartSeries, error)
	LoadMetric(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time) ([]Sample, error)
	// LatestProcesses returns the newest sample group, sorted and limited in the store.
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
}
