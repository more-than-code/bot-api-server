package store

import (
	"encoding/json"
	"reflect"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// serviceNameRe is the agent service name rule. A fallback unit name that
// fails it is not stored as the service name.
var serviceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// IdempotencyTTL is how long a run, stop, or restart response is replayed.
const IdempotencyTTL = 24 * time.Hour

// ConfirmationTTL is how long a delegated confirmation stays usable.
const ConfirmationTTL = 5 * time.Minute

// HostPrograms is the agent hello programs object. A nil pointer on Host
// means the agent reported no policy file.
type HostPrograms struct {
	Enabled      bool     `json:"enabled"`
	RunAs        []string `json:"run_as"`
	AllowShell   bool     `json:"allow_shell"`
	PolicyHash   string   `json:"policy_hash"`
	Images       bool     `json:"images"`
	Docker       bool     `json:"docker"`
	Files        bool     `json:"files"`
	DockerHealth bool     `json:"docker_health"`
	Healthcheck  bool     `json:"healthcheck"`
	Logging      bool     `json:"logging"`
}

// ProgramSpec is the stored program document. Env and Args are never nil
// after a write.
type ProgramSpec struct {
	Dir     string            `json:"dir"`
	Exec    string            `json:"exec"`
	Args    []string          `json:"args"`
	Shell   bool              `json:"shell"`
	RunAs   string            `json:"run_as"`
	Env     map[string]string `json:"env"`
	Port    *int              `json:"port"`
	Restart string            `json:"restart"`
}

// CatalogEntry is one program the project may run. MyActions is filled by
// the API for the caller; the store leaves it nil.
type CatalogEntry struct {
	ID             uuid.UUID       `json:"id"`
	ProjectID      uuid.UUID       `json:"project_id"`
	Name           string          `json:"name"`
	Kind           string          `json:"kind"`
	Spec           ProgramSpec     `json:"spec"`
	ImageRaw       json.RawMessage `json:"-"`
	SpecHash       string          `json:"spec_hash"`
	CommandDisplay string          `json:"command_display"`
	CreatedBy      uuid.UUID       `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	MyActions      []string        `json:"my_actions"`
}

// CatalogWrite is a new or replaced catalog entry.
// Kind is program or image. Empty means program.
// ImageRaw is the ImageSpec JSON when Kind is image.
type CatalogWrite struct {
	Name           string
	Kind           string
	Spec           ProgramSpec
	ImageRaw       json.RawMessage
	SpecHash       string
	CommandDisplay string
	Actor          uuid.UUID
	At             time.Time
}

// MarshalJSON keeps a program entry on the v1.6 shape. An image entry
// returns its stored ImageSpec instead of the program spec.
func (e CatalogEntry) MarshalJSON() ([]byte, error) {
	if e.Kind != "image" {
		type alias CatalogEntry
		return json.Marshal(alias(e))
	}
	spec := e.ImageRaw
	if len(spec) == 0 {
		spec = json.RawMessage("null")
	} else {
		spec = ensureFiles(spec)
	}
	return json.Marshal(struct {
		ID             uuid.UUID       `json:"id"`
		ProjectID      uuid.UUID       `json:"project_id"`
		Name           string          `json:"name"`
		Kind           string          `json:"kind"`
		Spec           json.RawMessage `json:"spec"`
		SpecHash       string          `json:"spec_hash"`
		CommandDisplay string          `json:"command_display"`
		CreatedBy      uuid.UUID       `json:"created_by"`
		CreatedAt      time.Time       `json:"created_at"`
		UpdatedAt      time.Time       `json:"updated_at"`
		MyActions      []string        `json:"my_actions"`
	}{
		ID: e.ID, ProjectID: e.ProjectID, Name: e.Name, Kind: e.Kind, Spec: spec,
		SpecHash: e.SpecHash, CommandDisplay: e.CommandDisplay, CreatedBy: e.CreatedBy,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, MyActions: e.MyActions,
	})
}

// ensureFiles adds "files":[] when a stored image spec omitted the key.
// A spec that already has the key is returned unchanged.
func ensureFiles(raw json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return raw
	}
	if _, ok := fields["files"]; ok {
		return raw
	}
	fields["files"] = json.RawMessage(`[]`)
	out, err := json.Marshal(fields)
	if err != nil {
		return raw
	}
	return out
}

// CatalogGrant is one subject allowed to act on an entry.
// Subject is role:admin, role:viewer, or user:<uuid>.
type CatalogGrant struct {
	Subject string   `json:"subject"`
	Actions []string `json:"actions"`
}

// CatalogApproval is a pending or approved run of one entry on one host.
type CatalogApproval struct {
	EntryID        uuid.UUID         `json:"entry_id"`
	EntryName      string            `json:"entry_name"`
	ProjectID      uuid.UUID         `json:"project_id"`
	ProjectName    string            `json:"project_name"`
	HostID         uuid.UUID         `json:"host_id"`
	SpecHash       string            `json:"spec_hash"`
	CommandDisplay string            `json:"command_display"`
	Dir            string            `json:"dir"`
	Exec           string            `json:"exec"`
	Args           []string          `json:"args"`
	Env            map[string]string `json:"env"`
	RunAs          string            `json:"run_as"`
	Shell          bool              `json:"shell"`
	Status         string            `json:"status"`
	RequestedBy    uuid.UUID         `json:"requested_by"`
	RequestedAt    time.Time         `json:"requested_at"`
	ApprovedBy     *uuid.UUID        `json:"approved_by"`
	ApprovedAt     *time.Time        `json:"approved_at"`
}

// CatalogConfirmation is a single-use delegated action, stored by token hash.
type CatalogConfirmation struct {
	UserID         uuid.UUID
	ProjectID      uuid.UUID
	EntryID        uuid.UUID
	EntryName      string
	HostID         uuid.UUID
	Action         string
	SpecHash       string
	IdempotencyKey string
	RequestHash    []byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
	// ImageDigest and ImageForce rebuild a confirmed rollback or deploy.
	// They are nil for program actions. They are not secrets.
	ImageDigest *string
	ImageForce  *bool
}

// ServiceConfirmation is a single-use delegated health-check replacement.
// It is stored by token hash in app.service_confirmations, separate from
// catalog confirmations. Checks is the normalized set to apply. RequestHash
// binds the request. CurrentHash binds the check set at issue time.
type ServiceConfirmation struct {
	UserID         uuid.UUID
	ProjectID      uuid.UUID
	ServiceID      uuid.UUID
	Action         string
	RequestHash    []byte
	CurrentHash    []byte
	Checks         []HealthCheckInput
	IdempotencyKey string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
}

// CatalogWriteConfirmation is a single-use delegated catalog create, update,
// or delete. It is stored by token hash in app.catalog_write_confirmations.
// Body is the normalized ImageSpec for create and update, and nil for delete.
// It is never returned on the 202. BaseSpecHash is empty for create; the
// store writes that empty string, and a nil Body, as SQL NULL. RequestHash
// binds the request. It does not include the idempotency key.
type CatalogWriteConfirmation struct {
	UserID         uuid.UUID
	ProjectID      uuid.UUID
	Action         string
	EntryName      string
	BaseSpecHash   string
	Body           json.RawMessage
	RequestHash    []byte
	IdempotencyKey string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
}

// SameJSON reports whether a and b are the same JSON value.
// Object key order does not matter. A nil slice and a JSON null are not equal.
func SameJSON(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

// IdempotencyRecord is one stored run, stop, or restart response.
// Body is the full JSON envelope. Pending means the response is not stored yet.
type IdempotencyRecord struct {
	RequestHash []byte
	Status      int
	Body        []byte
	CreatedAt   time.Time
	Pending     bool
}

// DiscoveredOwner is the agent-protocol v1.3 owner object.
type DiscoveredOwner struct {
	Kind    string
	Project string
	Entry   string
}

// PlaceDiscovered decides the service row for one reported item.
// lookup reports the project id when that slug has a live catalog entry
// of the given name and kind. A matching owner is stored as source owned.
// A program owner that misses falls back to the unit name. An image owner
// that misses keeps the reported container name.
func PlaceDiscovered(item Discovered, hostProject uuid.UUID, lookup func(slug, entry, kind string) (uuid.UUID, bool)) (name, source string, projectID uuid.UUID, catalog *string) {
	if item.Owner == nil || item.Owner.Project == "" || item.Owner.Entry == "" {
		return item.Name, "discovered", hostProject, nil
	}
	if item.Owner.Kind != "program" && item.Owner.Kind != "image" {
		return item.Name, "discovered", hostProject, nil
	}
	if id, ok := lookup(item.Owner.Project, item.Owner.Entry, item.Owner.Kind); ok {
		ce := item.Owner.Entry
		return item.Owner.Entry, "owned", id, &ce
	}
	if item.Owner.Kind == "image" {
		return item.Name, "discovered", hostProject, nil
	}
	name = item.Name
	if item.SystemdUnit != nil && serviceNameRe.MatchString(*item.SystemdUnit) {
		name = *item.SystemdUnit
	}
	return name, "discovered", hostProject, nil
}
