package catalog

import (
	"errors"
	"strings"
	"testing"
)

const policyHC = `"healthcheck":{"test":["redis-cli","ping"]}`

func TestHealthPolicyRules(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"job", `{"kind":"job","image":"nginx","health_policy":{}}`, "health_policy applies to services"},
		{"job bad value", `{"kind":"job","image":"nginx","health_policy":{"on_unhealthy":"x"}}`, "health_policy applies to services"},
		{"unknown key", `{"kind":"service","image":"nginx","health_policy":{"on_failure":"stop"}}`, "unknown field health_policy.on_failure"},
		{"unknown key 64", `{"kind":"service","image":"nginx","health_policy":{"` + strings.Repeat("k", 64) + `":1}}`, "unknown field health_policy." + strings.Repeat("k", 64)},
		{"unknown key 65", `{"kind":"service","image":"nginx","health_policy":{"` + strings.Repeat("k", 65) + `":1}}`, "invalid health_policy"},
		{"unknown key upper", `{"kind":"service","image":"nginx","health_policy":{"OnFailure":1}}`, "invalid health_policy"},
		{"unknown key digit", `{"kind":"service","image":"nginx","health_policy":{"on_failure2":1}}`, "invalid health_policy"},
		{"unknown key quote", `{"kind":"service","image":"nginx","health_policy":{"a\"b":1}}`, "invalid health_policy"},
		{"keep with restart", `{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_deploy_failure":"keep","on_unhealthy":"restart"}}`, "health_policy.on_unhealthy cannot be combined with keep"},
		{"keep with rollback", `{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_deploy_failure":"keep","on_unhealthy":"rollback"}}`, "health_policy.on_unhealthy cannot be combined with keep"},
		{"not object", `{"kind":"service","image":"nginx","health_policy":"rollback"}`, "invalid health_policy"},
		{"array", `{"kind":"service","image":"nginx","health_policy":[]}`, "invalid health_policy"},
		{"bad deploy enum", `{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"restart"}}`, "invalid health_policy.on_deploy_failure"},
		{"deploy not string", `{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":1}}`, "invalid health_policy.on_deploy_failure"},
		{"bad unhealthy enum", `{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_unhealthy":"stop"}}`, "invalid health_policy.on_unhealthy"},
		{"low after", `{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":14}}`, "invalid health_policy.unhealthy_after_sec"},
		{"high after", `{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":601}}`, "invalid health_policy.unhealthy_after_sec"},
		{"float after", `{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":45.0}}`, "invalid health_policy.unhealthy_after_sec"},
		{"string after", `{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":"45"}}`, "invalid health_policy.unhealthy_after_sec"},
		{"low actions", `{"kind":"service","image":"nginx","health_policy":{"max_actions_per_hour":0}}`, "invalid health_policy.max_actions_per_hour"},
		{"high actions", `{"kind":"service","image":"nginx","health_policy":{"max_actions_per_hour":11}}`, "invalid health_policy.max_actions_per_hour"},
		{"bool actions", `{"kind":"service","image":"nginx","health_policy":{"max_actions_per_hour":true}}`, "invalid health_policy.max_actions_per_hour"},
		{"restart without healthcheck", `{"kind":"service","image":"nginx","health_policy":{"on_unhealthy":"restart"}}`, "health_policy.on_unhealthy needs a healthcheck"},
		{"rollback without healthcheck", `{"kind":"service","image":"nginx","health_policy":{"on_unhealthy":"rollback"}}`, "health_policy.on_unhealthy needs a healthcheck"},
	}
	for _, tc := range cases {
		_, err := BuildImage("web", []byte(tc.spec), nil, nil)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Msg != tc.want || fe.Code != CodeBadRequest {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}

	ok := []string{
		`{"kind":"service","image":"nginx","health_policy":{}}`,
		`{"kind":"service","image":"nginx","health_policy":null}`,
		`{"kind":"job","image":"nginx","health_policy":null}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"stop"}}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"keep","on_unhealthy":"none"}}`,
		`{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":15,"max_actions_per_hour":1}}`,
		`{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":600,"max_actions_per_hour":10}}`,
		`{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_unhealthy":"restart"}}`,
		`{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_unhealthy":"rollback","on_deploy_failure":"rollback"}}`,
		`{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_unhealthy":"restart","on_deploy_failure":"stop"}}`,
		`{"kind":"service","image":"nginx",` + policyHC + `,"health_policy":{"on_unhealthy":"none","on_deploy_failure":"keep"}}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_unhealthy":null}}`,
	}
	for _, spec := range ok {
		if _, err := BuildImage("web", []byte(spec), nil, nil); err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
	}

	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx",`+policyHC+`,"health_policy":{"on_unhealthy":"restart"}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	eff := img.HealthPolicy.Effective()
	if eff.OnDeployFailure != "rollback" || eff.OnUnhealthy != "restart" || eff.UnhealthyAfterSec != 45 || eff.MaxActionsPerHour != 3 {
		t.Fatalf("effective %+v", eff)
	}
	if PolicyIsDefault(img) {
		t.Fatal("restart policy reported as default")
	}
}

func TestHealthPolicyStoredAsWritten(t *testing.T) {
	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx",`+policyHC+`,"health_policy":{"on_unhealthy":"restart","max_actions_per_hour":5}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored := SpecJSON(img)
	want := `"health_policy":{"max_actions_per_hour":5,"on_unhealthy":"restart"}`
	if !strings.Contains(stored, want) {
		t.Fatalf("stored %s", stored)
	}
	filesAt := strings.Index(stored, `"files"`)
	policyAt := strings.Index(stored, `"health_policy"`)
	hcAt := strings.Index(stored, `"healthcheck"`)
	if filesAt < 0 || policyAt < filesAt || hcAt < policyAt {
		t.Fatalf("key order %s", stored)
	}
	again, err := ParseStored([]byte(stored))
	if err != nil || again.HealthPolicy == nil || SpecJSON(again) != stored {
		t.Fatalf("round trip %v %s", err, SpecJSON(again))
	}
	if ImageHash(again, nil) != ImageHash(img, nil) {
		t.Fatal("round trip changed spec_hash")
	}
	empty, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","health_policy":{}}`), nil, nil)
	if err != nil || empty.HealthPolicy == nil || !strings.Contains(SpecJSON(empty), `"health_policy":{}`) {
		t.Fatalf("empty policy %v %s", err, SpecJSON(empty))
	}
	if _, err := ParseStored([]byte(strings.Replace(stored, `"on_unhealthy"`, `"on_sick"`, 1))); err == nil {
		t.Fatal("stored parser accepted an unknown policy key")
	}
}

func TestHealthPolicyHash(t *testing.T) {
	bare, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "578b58b80ed177e86358709c3a24c704c76e0f70c90fe3ae9fd47ffc025a7e30"
	if ImageHash(bare, nil) != pinned {
		t.Fatalf("bare hash %s", ImageHash(bare, nil))
	}
	defaults := []string{
		`{"kind":"service","image":"nginx","health_policy":null}`,
		`{"kind":"service","image":"nginx","health_policy":{}}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"rollback"}}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"rollback","on_unhealthy":"none","unhealthy_after_sec":45,"max_actions_per_hour":3}}`,
	}
	for _, spec := range defaults {
		img, err := BuildImage("web", []byte(spec), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !PolicyIsDefault(img) || ImageHash(img, nil) != pinned || strings.Contains(CanonicalImage(img, nil), "health_policy") {
			t.Fatalf("default policy changed the hash: %s", spec)
		}
	}

	stop, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"stop"}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ImageHash(stop, nil) == pinned {
		t.Fatal("on_deploy_failure did not change spec_hash")
	}
	full := `"health_policy":{"max_actions_per_hour":3,"on_deploy_failure":"stop","on_unhealthy":"none","unhealthy_after_sec":45}`
	if !strings.Contains(CanonicalImage(stop, nil), full) {
		t.Fatalf("canonical %s", CanonicalImage(stop, nil))
	}
	spelled, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"stop","unhealthy_after_sec":45}}`), nil, nil)
	if err != nil || ImageHash(spelled, nil) != ImageHash(stop, nil) {
		t.Fatal("two spellings of one policy hash differently")
	}
	others := []string{
		`{"kind":"service","image":"nginx","health_policy":{"unhealthy_after_sec":60}}`,
		`{"kind":"service","image":"nginx","health_policy":{"max_actions_per_hour":4}}`,
		`{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"keep"}}`,
	}
	seen := map[string]bool{pinned: true, ImageHash(stop, nil): true}
	for _, spec := range others {
		img, err := BuildImage("web", []byte(spec), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := ImageHash(img, nil)
		if seen[h] {
			t.Fatalf("hash collision for %s", spec)
		}
		seen[h] = true
	}
	withHC, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx",`+policyHC+`}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restart, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx",`+policyHC+`,"health_policy":{"on_unhealthy":"restart"}}`), nil, nil)
	if err != nil || ImageHash(restart, nil) == ImageHash(withHC, nil) {
		t.Fatal("on_unhealthy did not change spec_hash")
	}
}
