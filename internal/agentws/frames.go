package agentws

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
)

var errClosed = errors.New("closed")

type frame struct {
	V                int             `json:"v"`
	Type             string          `json:"type"`
	JoinToken        string          `json:"join_token"`
	Hostname         string          `json:"hostname"`
	AgentVersion     string          `json:"agent_version"`
	OS               string          `json:"os"`
	Arch             string          `json:"arch"`
	AlwaysOn         bool            `json:"always_on"`
	HostID           string          `json:"host_id"`
	CredentialID     string          `json:"credential_id"`
	Services         json.RawMessage `json:"services"`
	ServicesComplete json.RawMessage `json:"services_complete"`
	Programs         json.RawMessage `json:"programs"`
	BatchID          string          `json:"batch_id"`
	Samples          json.RawMessage `json:"samples"`
	TaskID           string          `json:"task_id"`
	State            string          `json:"state"`
	ErrorCode        json.RawMessage `json:"error_code"`
	Payload          json.RawMessage `json:"payload"`
}

type errorFrame struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

type enrolledFrame struct {
	V            int       `json:"v"`
	Type         string    `json:"type"`
	HostID       uuid.UUID `json:"host_id"`
	CredentialID uuid.UUID `json:"credential_id"`
	Credential   string    `json:"credential"`
}

type helloOKFrame struct {
	V            int        `json:"v"`
	Type         string     `json:"type"`
	HostID       uuid.UUID  `json:"host_id"`
	HeartbeatSec int        `json:"heartbeat_sec"`
	ServerTime   string     `json:"server_time"`
	Config       configBody `json:"config"`
}

type configUpdate struct {
	V      int        `json:"v"`
	Type   string     `json:"type"`
	Config configBody `json:"config"`
}

type configBody struct {
	MetricsIntervalSec int         `json:"metrics_interval_sec"`
	ProcessIntervalSec int         `json:"process_interval_sec"`
	HealthChecks       []checkJSON `json:"health_checks"`
}

type checkJSON struct {
	ID              uuid.UUID `json:"id"`
	Service         string    `json:"service"`
	Protocol        string    `json:"protocol"`
	Port            int       `json:"port"`
	Path            *string   `json:"path"`
	IntervalSec     int       `json:"interval_sec"`
	ExpectStatusMin int       `json:"expect_status_min"`
	ExpectStatusMax int       `json:"expect_status_max"`
}

type taskFrame struct {
	V          int       `json:"v"`
	Type       string    `json:"type"`
	TaskID     uuid.UUID `json:"task_id"`
	HostID     uuid.UUID `json:"host_id"`
	Kind       string    `json:"kind"`
	Service    *string   `json:"service"`
	ExpiresAt  string    `json:"expires_at"`
	TimeoutSec int       `json:"timeout_sec"`
	Spec       any       `json:"spec"`
}

func parseFrame(b []byte) (frame, error) {
	var f frame
	if err := json.Unmarshal(b, &f); err != nil {
		return frame{}, err
	}
	if err := validServicesComplete(f.ServicesComplete); err != nil {
		return frame{}, err
	}
	return f, nil
}

// validServicesComplete accepts an absent field and JSON null.
// Any other non-bool fails the frame.
func validServicesComplete(raw json.RawMessage) error {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil
	}
	var v bool
	return json.Unmarshal(raw, &v)
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
