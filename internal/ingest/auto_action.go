package ingest

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
)

// MaxAutoReason is the agent-protocol v1.9 item 5 limit on reason, in bytes.
const MaxAutoReason = 200

// autoOutcomes maps the frame action to the image_deploys outcome.
var autoOutcomes = map[string]string{
	"restart":  "auto_restarted",
	"rollback": "auto_rolled_back",
	"gave_up":  "auto_gave_up",
}

// AutoAction is a checked auto_action frame. Digest is nil for JSON null.
type AutoAction struct {
	ID        uuid.UUID
	At        time.Time
	Project   string
	Entry     string
	Container string
	Action    string
	Outcome   string
	Reason    string
	Result    string
	Digest    *string
}

// ParseAutoActionID reads only the frame id, so an invalid frame can still
// be acknowledged. ok is false when the id is missing or not a uuid.
func ParseAutoActionID(raw []byte) (uuid.UUID, bool) {
	var peek struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(peek.ID)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// ValidateAutoAction checks the agent-protocol v1.9 item 5 shape: closed
// keys, uuid id, RFC3339 t, the enums, an image entry name, a printable
// container name, reason within MaxAutoReason, and a null or sha256 digest.
// Project membership and the entry's existence are checked by the store.
// Errors carry a short reason and never the frame's values.
func ValidateAutoAction(raw []byte) (AutoAction, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in struct {
		V         int     `json:"v"`
		Type      string  `json:"type"`
		ID        string  `json:"id"`
		T         string  `json:"t"`
		Project   string  `json:"project"`
		Entry     string  `json:"entry"`
		Container string  `json:"container"`
		Action    string  `json:"action"`
		Reason    string  `json:"reason"`
		Result    string  `json:"result"`
		Digest    *string `json:"digest"`
	}
	if err := dec.Decode(&in); err != nil {
		return AutoAction{}, &Reject{Reason: "shape"}
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return AutoAction{}, &Reject{Reason: "shape"}
	}
	id, err := uuid.Parse(in.ID)
	if err != nil {
		return AutoAction{}, &Reject{Reason: "id"}
	}
	at, err := time.Parse(time.RFC3339, in.T)
	if err != nil {
		return AutoAction{}, &Reject{Reason: "t"}
	}
	if !printable(in.Project, 80) {
		return AutoAction{}, &Reject{Reason: "project"}
	}
	if !catalog.ValidImageName(in.Entry) {
		return AutoAction{}, &Reject{Reason: "entry"}
	}
	if !printable(in.Container, 128) {
		return AutoAction{}, &Reject{Reason: "container"}
	}
	outcome, ok := autoOutcomes[in.Action]
	if !ok {
		return AutoAction{}, &Reject{Reason: "action"}
	}
	if in.Result != "ok" && in.Result != "error" {
		return AutoAction{}, &Reject{Reason: "result"}
	}
	if len(in.Reason) > MaxAutoReason || !utf8.ValidString(in.Reason) || hasControl(in.Reason) {
		return AutoAction{}, &Reject{Reason: "reason"}
	}
	if in.Digest != nil && !catalog.ValidDigest(*in.Digest) {
		return AutoAction{}, &Reject{Reason: "digest"}
	}
	return AutoAction{
		ID:        id,
		At:        at.UTC(),
		Project:   in.Project,
		Entry:     in.Entry,
		Container: in.Container,
		Action:    in.Action,
		Outcome:   outcome,
		Reason:    in.Reason,
		Result:    in.Result,
		Digest:    in.Digest,
	}, nil
}

// printable is 1..max bytes of printable ASCII.
func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasControl reports control characters, line separators, and bidi
// overrides, which could alter how the reason reads in a log or the console.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}
