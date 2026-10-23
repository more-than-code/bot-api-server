package catalog

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Health policy defaults and bounds (api-v1 v1.15). The defaults are the
// behaviour of an entry without the field.
const (
	DefaultOnDeployFailure   = "rollback"
	DefaultOnUnhealthy       = "none"
	DefaultUnhealthyAfterSec = 45
	DefaultMaxActionsPerHour = 3
	minUnhealthyAfter        = 15
	maxUnhealthyAfter        = 600
	minActionsPerHour        = 1
	maxActionsPerHour        = 10
)

// HealthPolicy is the optional services-only health_policy object, stored as
// written: a nil field is a key the spec omitted. Effective fills defaults.
type HealthPolicy struct {
	OnDeployFailure   *string `json:"on_deploy_failure"`
	OnUnhealthy       *string `json:"on_unhealthy"`
	UnhealthyAfterSec *int    `json:"unhealthy_after_sec"`
	MaxActionsPerHour *int    `json:"max_actions_per_hour"`
}

// EffectivePolicy is a health policy with every default filled in.
type EffectivePolicy struct {
	OnDeployFailure   string
	OnUnhealthy       string
	UnhealthyAfterSec int
	MaxActionsPerHour int
}

// DefaultPolicy is the policy of an entry without health_policy.
var DefaultPolicy = EffectivePolicy{
	OnDeployFailure:   DefaultOnDeployFailure,
	OnUnhealthy:       DefaultOnUnhealthy,
	UnhealthyAfterSec: DefaultUnhealthyAfterSec,
	MaxActionsPerHour: DefaultMaxActionsPerHour,
}

// Effective fills omitted keys with the defaults. A nil policy is all defaults.
func (p *HealthPolicy) Effective() EffectivePolicy {
	out := DefaultPolicy
	if p == nil {
		return out
	}
	if p.OnDeployFailure != nil {
		out.OnDeployFailure = *p.OnDeployFailure
	}
	if p.OnUnhealthy != nil {
		out.OnUnhealthy = *p.OnUnhealthy
	}
	if p.UnhealthyAfterSec != nil {
		out.UnhealthyAfterSec = *p.UnhealthyAfterSec
	}
	if p.MaxActionsPerHour != nil {
		out.MaxActionsPerHour = *p.MaxActionsPerHour
	}
	return out
}

// PolicyIsDefault is true when the spec has no health_policy or one equal
// to the defaults. Such an entry keeps its spec_hash and is not gated.
func PolicyIsDefault(img Image) bool {
	return img.HealthPolicy.Effective() == DefaultPolicy
}

// policyKeyRe is the rev 2 rule for naming an unknown key in the error.
// Anything else is reported as invalid health_policy, so the message never
// echoes arbitrary caller text.
var policyKeyRe = regexp.MustCompile(`^[a-z_]{1,64}$`)

// decodeHealthPolicy accepts null as absent and rejects a job before it
// inspects the object. A non-object names health_policy. An unknown key is
// named when it matches policyKeyRe (rev 2).
// A bad value names the key. A key whose value is null counts as omitted.
func decodeHealthPolicy(raw json.RawMessage, kind string, hc *Healthcheck) (*HealthPolicy, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	if kind == "job" {
		return nil, fieldErr("health_policy applies to services")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, fieldErr("invalid health_policy")
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return nil, fieldErr("invalid health_policy")
	}
	allowed := map[string]struct{}{
		"on_deploy_failure": {}, "on_unhealthy": {}, "unhealthy_after_sec": {}, "max_actions_per_hour": {},
	}
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			if policyKeyRe.MatchString(key) {
				return nil, fieldErr("unknown field health_policy." + key)
			}
			return nil, fieldErr("invalid health_policy")
		}
	}
	var p HealthPolicy
	var err error
	if p.OnDeployFailure, err = decodePolicyEnum(obj["on_deploy_failure"], "health_policy.on_deploy_failure", "rollback", "stop", "keep"); err != nil {
		return nil, err
	}
	if p.OnUnhealthy, err = decodePolicyEnum(obj["on_unhealthy"], "health_policy.on_unhealthy", "none", "restart", "rollback"); err != nil {
		return nil, err
	}
	if p.UnhealthyAfterSec, err = decodePolicyInt(obj["unhealthy_after_sec"], "health_policy.unhealthy_after_sec", minUnhealthyAfter, maxUnhealthyAfter); err != nil {
		return nil, err
	}
	if p.MaxActionsPerHour, err = decodePolicyInt(obj["max_actions_per_hour"], "health_policy.max_actions_per_hour", minActionsPerHour, maxActionsPerHour); err != nil {
		return nil, err
	}
	eff := p.Effective()
	if eff.OnUnhealthy != DefaultOnUnhealthy && hc == nil {
		return nil, fieldErr("health_policy.on_unhealthy needs a healthcheck")
	}
	if eff.OnUnhealthy != DefaultOnUnhealthy && eff.OnDeployFailure == "keep" {
		return nil, fieldErr("health_policy.on_unhealthy cannot be combined with keep")
	}
	return &p, nil
}

func decodePolicyEnum(raw json.RawMessage, name string, values ...string) (*string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return nil, fieldErr("invalid " + name)
	}
	for _, v := range values {
		if s == v {
			return &s, nil
		}
	}
	return nil, fieldErr("invalid " + name)
}

func decodePolicyInt(raw json.RawMessage, name string, min, max int) (*int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	n, err := decodeRequiredInt(raw, name, min, max)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// healthPolicyJSON is the stored object: only the keys the spec wrote, in
// sorted order. An empty policy is {}.
func healthPolicyJSON(p HealthPolicy) string {
	var parts []string
	if p.MaxActionsPerHour != nil {
		parts = append(parts, `"max_actions_per_hour":`+strconv.Itoa(*p.MaxActionsPerHour))
	}
	if p.OnDeployFailure != nil {
		parts = append(parts, `"on_deploy_failure":`+jsonString(*p.OnDeployFailure))
	}
	if p.OnUnhealthy != nil {
		parts = append(parts, `"on_unhealthy":`+jsonString(*p.OnUnhealthy))
	}
	if p.UnhealthyAfterSec != nil {
		parts = append(parts, `"unhealthy_after_sec":`+strconv.Itoa(*p.UnhealthyAfterSec))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// effectivePolicyJSON is the spec_hash form: every key with defaults filled
// in, so two spellings of the same policy hash alike.
func effectivePolicyJSON(e EffectivePolicy) string {
	return `{"max_actions_per_hour":` + strconv.Itoa(e.MaxActionsPerHour) +
		`,"on_deploy_failure":` + jsonString(e.OnDeployFailure) +
		`,"on_unhealthy":` + jsonString(e.OnUnhealthy) +
		`,"unhealthy_after_sec":` + strconv.Itoa(e.UnhealthyAfterSec) + `}`
}
