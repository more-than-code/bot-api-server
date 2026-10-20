package catalog

import (
	"errors"
	"strings"
	"testing"
)

func TestHealthcheckRules(t *testing.T) {
	const sentinel = "SENTINEL_ARGV"
	args33 := `["` + sentinel + `"`
	for i := 0; i < 32; i++ {
		args33 += `,"a"`
	}
	args33 += `]`
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"low interval", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"interval_sec":4}}`, "invalid healthcheck.interval_sec"},
		{"high interval", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"interval_sec":301}}`, "invalid healthcheck.interval_sec"},
		{"float interval", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"interval_sec":30.0}}`, "invalid healthcheck.interval_sec"},
		{"low timeout", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"timeout_sec":0}}`, "invalid healthcheck.timeout_sec"},
		{"high timeout", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"timeout_sec":61}}`, "invalid healthcheck.timeout_sec"},
		{"timeout equals interval", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"interval_sec":5}}`, "invalid healthcheck.timeout_sec"},
		{"timeout not less", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"interval_sec":30,"timeout_sec":30}}`, "invalid healthcheck.timeout_sec"},
		{"retries", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"retries":0}}`, "invalid healthcheck.retries"},
		{"retries high", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"retries":11}}`, "invalid healthcheck.retries"},
		{"retries bool", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"retries":true}}`, "invalid healthcheck.retries"},
		{"start", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"start_period_sec":601}}`, "invalid healthcheck.start_period_sec"},
		{"nul", `{"kind":"service","image":"nginx","healthcheck":{"test":["` + sentinel + `\u0000"]}}`, "invalid healthcheck.test"},
		{"empty arg", `{"kind":"service","image":"nginx","healthcheck":{"test":[""]}}`, "invalid healthcheck.test"},
		{"long arg", `{"kind":"service","image":"nginx","healthcheck":{"test":["` + strings.Repeat("a", 1025) + `"]}}`, "invalid healthcheck.test"},
		{"33 args", `{"kind":"service","image":"nginx","healthcheck":{"test":` + args33 + `}}`, "invalid healthcheck.test"},
		{"test string", `{"kind":"service","image":"nginx","healthcheck":{"test":"` + sentinel + `"}}`, "invalid healthcheck.test"},
		{"missing test", `{"kind":"service","image":"nginx","healthcheck":{}}`, "invalid healthcheck.test"},
		{"unknown", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD"],"shell":true}}`, "invalid healthcheck"},
		{"not object", `{"kind":"service","image":"nginx","healthcheck":"` + sentinel + `"}`, "invalid healthcheck"},
		{"job", `{"kind":"job","image":"nginx","healthcheck":{"test":["` + sentinel + `"]}}`, "healthcheck applies to services"},
		{"job junk", `{"kind":"job","image":"nginx","healthcheck":"` + sentinel + `"}`, "healthcheck applies to services"},
	}
	for _, tc := range cases {
		_, err := BuildImage("web", []byte(tc.spec), nil, nil)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Msg != tc.want || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}

	ok, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","healthcheck":{"test":["`+strings.Repeat("b", 1024)+`"],"interval_sec":300,"timeout_sec":60,"retries":10,"start_period_sec":600}}`), nil, nil)
	if err != nil || ok.Healthcheck == nil || ok.Healthcheck.IntervalSec != 300 || ok.Healthcheck.TimeoutSec != 60 || ok.Healthcheck.Retries != 10 || ok.Healthcheck.StartPeriodSec != 600 || len(ok.Healthcheck.Test) != 1 || len(ok.Healthcheck.Test[0]) != 1024 {
		t.Fatalf("bounds %+v %v", ok.Healthcheck, err)
	}
	job, err := BuildImage("job", []byte(`{"kind":"job","image":"nginx"}`), nil, nil)
	if err != nil || job.Healthcheck != nil {
		t.Fatalf("job without healthcheck %+v %v", job.Healthcheck, err)
	}
	nulled, err := BuildImage("web", []byte(`{"kind":"job","image":"nginx","healthcheck":null}`), nil, nil)
	if err != nil || nulled.Healthcheck != nil {
		t.Fatalf("null healthcheck on a job %+v %v", nulled.Healthcheck, err)
	}
}

func TestHealthcheckDefaultsAndHash(t *testing.T) {
	bare, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "578b58b80ed177e86358709c3a24c704c76e0f70c90fe3ae9fd47ffc025a7e30"
	if ImageHash(bare, nil) != pinned || strings.Contains(SpecJSON(bare), "healthcheck") || strings.Contains(CanonicalImage(bare, nil), "healthcheck") {
		t.Fatalf("absent healthcheck changed the hash %s", ImageHash(bare, nil))
	}
	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","healthcheck":{"test":["CMD","wget"]}}`), nil, nil)
	if err != nil || img.Healthcheck == nil {
		t.Fatal(err)
	}
	h := img.Healthcheck
	if h.IntervalSec != 30 || h.TimeoutSec != 5 || h.Retries != 3 || h.StartPeriodSec != 0 {
		t.Fatalf("defaults %+v", h)
	}
	want := `"healthcheck":{"interval_sec":30,"retries":3,"start_period_sec":0,"test":["CMD","wget"],"timeout_sec":5}`
	stored := SpecJSON(img)
	if !strings.Contains(stored, want) || !strings.Contains(CanonicalImage(img, nil), want) {
		t.Fatalf("stored %s", stored)
	}
	filesAt := strings.Index(stored, `"files"`)
	hcAt := strings.Index(stored, `"healthcheck"`)
	healthyAt := strings.Index(stored, `"healthy_after_sec"`)
	if filesAt < 0 || hcAt < filesAt || healthyAt < hcAt {
		t.Fatalf("key order %s", stored)
	}
	if ImageHash(img, nil) == pinned {
		t.Fatal("healthcheck did not change spec_hash")
	}
	again, err := ParseStored([]byte(stored))
	if err != nil || SpecJSON(again) != stored {
		t.Fatalf("round trip %v %s", err, SpecJSON(again))
	}
	changed, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","healthcheck":{"test":["CMD","wget"],"retries":4}}`), nil, nil)
	if err != nil || ImageHash(changed, nil) == ImageHash(img, nil) {
		t.Fatal("retries did not change spec_hash")
	}
}

func TestHealthcheckTimeoutBudget(t *testing.T) {
	bare, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if DeployTimeoutSec(bare) != 300+30+60 || RollbackTimeoutSec(bare) != 300+30+60 {
		t.Fatalf("bare deploy %d rollback %d", DeployTimeoutSec(bare), RollbackTimeoutSec(bare))
	}
	job, err := BuildImage("job", []byte(`{"kind":"job","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if DeployTimeoutSec(job) != 300+600+60 || RollbackTimeoutSec(job) != 300+0+60 {
		t.Fatalf("job deploy %d rollback %d", DeployTimeoutSec(job), RollbackTimeoutSec(job))
	}
	// healthy_after_sec wins when it is longer than the healthcheck wait.
	short, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","healthy_after_sec":100,"healthcheck":{"test":["CMD"],"interval_sec":5,"timeout_sec":1,"retries":1,"start_period_sec":0}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if DeployTimeoutSec(short) != 300+100+60 || RollbackTimeoutSec(short) != 300+100+60 {
		t.Fatalf("healthy wins deploy %d rollback %d", DeployTimeoutSec(short), RollbackTimeoutSec(short))
	}
	maxImg, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","healthy_after_sec":600,"healthcheck":{"test":["CMD"],"interval_sec":300,"timeout_sec":60,"retries":10,"start_period_sec":600}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const wait = 600 + 300*(10+1)
	want := 300 + wait + 60
	if DeployTimeoutSec(maxImg) != want || RollbackTimeoutSec(maxImg) != want {
		t.Fatalf("max deploy %d rollback %d want %d", DeployTimeoutSec(maxImg), RollbackTimeoutSec(maxImg), want)
	}
	if DeployTimeoutSec(maxImg) < wait+60 || RollbackTimeoutSec(maxImg) < wait+60 {
		t.Fatal("max budget is below the healthcheck wait plus slack")
	}
}
