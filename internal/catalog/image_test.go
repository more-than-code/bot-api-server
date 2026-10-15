package catalog

import (
	"strings"
	"testing"
)

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		in, image, host string
		ok              bool
	}{
		{in: "nginx", image: "docker.io/library/nginx:latest", host: "docker.io", ok: true},
		{in: "nginx:latest", image: "docker.io/library/nginx:latest", host: "docker.io", ok: true},
		{in: "library/nginx", image: "docker.io/library/nginx:latest", host: "docker.io", ok: true},
		{in: "ghcr.io/joe/app", image: "ghcr.io/joe/app:latest", host: "ghcr.io", ok: true},
		{in: "GHCR.IO/joe/app:1", image: "ghcr.io/joe/app:1", host: "ghcr.io", ok: true},
		{in: "localhost:5000/app", image: "localhost:5000/app:latest", host: "localhost:5000", ok: true},
		{in: "nginx@sha256:" + strings.Repeat("ab", 32), image: "docker.io/library/nginx@sha256:" + strings.Repeat("ab", 32), host: "docker.io", ok: true},
		{in: "Nginx", ok: false},
		{in: "ghcr.io/Joe/app", ok: false},
		{in: "nginx:NOT A TAG", ok: false},
		{in: "http://ghcr.io/joe/app", ok: false},
		{in: strings.Repeat("a", 300), ok: false},
	}
	for _, tc := range cases {
		got, err := ParseImageRef(tc.in)
		if tc.ok {
			if err != nil || got.Image != tc.image || got.Host != tc.host {
				t.Fatalf("ref %q: %+v %v", tc.in, got, err)
			}
			if strings.Contains(got.Image, tc.in) && tc.in != got.Image && strings.ContainsAny(tc.in, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				t.Fatal("uppercase survived")
			}
			continue
		}
		if err == nil || err.Error() != "invalid image" || strings.Contains(err.Error(), tc.in) {
			t.Fatalf("ref %q error %v", tc.in, err)
		}
	}
	if ValidRegistryHost("ghcr.io") && ValidRegistryHost("localhost:5000") && !ValidRegistryHost("GHCR.IO") && !ValidRegistryHost("localhost:99999") && !ValidRegistryHost("https://ghcr.io") {
		return
	}
	t.Fatal("registry host rule")
}

func TestBuildImageRules(t *testing.T) {
	sets := SetKeys{"services": {"MONGODB_URI", "DB_PASSWORD"}}
	base := func(spec string) (Image, error) {
		return BuildImage("web", []byte(spec), sets)
	}
	img, err := base(`{"kind":"service","image":"nginx"}`)
	if err != nil {
		t.Fatal(err)
	}
	if img.Image != "docker.io/library/nginx:latest" || img.Restart != "unless-stopped" || img.HealthyAfterSec != 30 || img.TimeoutSec != 0 {
		t.Fatalf("defaults %+v", img)
	}
	if img.Command != nil || img.Env == nil || img.EnvSets == nil || img.Ports == nil {
		t.Fatal("empty collections")
	}
	job, err := base(`{"kind":"job","image":"nginx","restart":"unless-stopped","timeout_sec":10}`)
	if err != nil || job.Restart != "no" || job.TimeoutSec != 10 || job.HealthyAfterSec != 0 {
		t.Fatalf("job %+v %v", job, err)
	}
	if _, err := base(`{"kind":"job","image":"nginx","healthy_after_sec":30}`); err == nil || err.Error() != "invalid healthy_after_sec" {
		t.Fatalf("job health %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","timeout_sec":10}`); err == nil || err.Error() != "invalid timeout_sec" {
		t.Fatalf("service timeout %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","healthy_after_sec":4}`); err == nil || err.Error() != "invalid healthy_after_sec" {
		t.Fatalf("health range %v", err)
	}
	if _, err := base(`{"kind":"job","image":"nginx","timeout_sec":9}`); err == nil || err.Error() != "invalid timeout_sec" {
		t.Fatalf("timeout range %v", err)
	}
	mem, err := base(`{"kind":"service","image":"nginx","memory_mb":16}`)
	if err != nil || mem.MemoryMB == nil || *mem.MemoryMB != 16 {
		t.Fatalf("memory %+v %v", mem, err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","memory_mb":0}`); err == nil || err.Error() != "invalid memory_mb" {
		t.Fatalf("memory 0 %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","memory_mb":15}`); err == nil || !strings.Contains(err.Error(), "memory_mb") {
		t.Fatalf("memory low %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","healthy_after_sec":601}`); err == nil || err.Error() != "invalid healthy_after_sec" {
		t.Fatalf("health high %v", err)
	}
	if _, err := base(`{"kind":"job","image":"nginx","timeout_sec":3601}`); err == nil || err.Error() != "invalid timeout_sec" {
		t.Fatalf("timeout high %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","memory_mb":65537}`); err == nil || err.Error() != "invalid memory_mb" {
		t.Fatalf("memory high %v", err)
	}
	if _, err := base("{\"kind\":\"service\",\"image\":\"nginx\",\"entrypoint\":[\"a\\nb\"]}"); err == nil || err.Error() != "invalid entrypoint" {
		t.Fatalf("entrypoint newline %v", err)
	}
	if _, err := base(`{"kind":"service","image":"nginx","entrypoint":["` + strings.Repeat("e", 4097) + `"]}`); err == nil || err.Error() != "invalid entrypoint" {
		t.Fatalf("entrypoint size %v", err)
	}
	only, err := base(`{"kind":"service","image":"nginx","secret_env":{"DB_PASSWORD":"services.DB_PASSWORD"}}`)
	if err != nil || only.SecretEnv["DB_PASSWORD"] != "services.DB_PASSWORD" || len(only.EnvSets) != 0 {
		t.Fatalf("secret_env without env_sets %+v %v", only, err)
	}

	refusals := []struct{ name, spec, want string }{
		{"name", "", "invalid name"},
		{"trailing", "", "invalid name"},
		{"prev", "", "invalid name"},
		{"upper image", `{"kind":"service","image":"Nginx"}`, "invalid image"},
		{"command long", `{"kind":"service","image":"nginx","command":["` + strings.Repeat("x", 4097) + `"]}`, "invalid command"},
		{"command nul", `{"kind":"service","image":"nginx","command":["a\u0000b"]}`, "invalid command"},
		{"too many args", `{"kind":"service","image":"nginx","command":` + manyArgs(33) + `}`, "invalid command"},
		{"ports", `{"kind":"service","image":"nginx","ports":[{"host":1,"container":1},{"host":1,"container":2}]}`, "invalid ports"},
		{"port range", `{"kind":"service","image":"nginx","ports":[{"host":0,"container":1}]}`, "invalid ports"},
		{"env secret", `{"kind":"service","image":"nginx","env":{"DB_PASSWORD":"x"}}`, "use secret_env"},
		{"env path", `{"kind":"service","image":"nginx","env":{"PATH":"/tmp"}}`, "PATH is reserved"},
		{"env deny", `{"kind":"service","image":"nginx","env":{"NODE_OPTIONS":"x"}}`, "this variable changes what the program runs"},
		{"env sets dup", `{"kind":"service","image":"nginx","env_sets":["services","services"]}`, "invalid env_sets"},
		{"env sets unknown", `{"kind":"service","image":"nginx","env_sets":["missing"]}`, "unknown env set"},
		{"secret ok shape", `{"kind":"service","image":"nginx","secret_env":{"DB_PASSWORD":"nope"}}`, "invalid secret_env"},
		{"secret unknown set", `{"kind":"service","image":"nginx","secret_env":{"DB_PASSWORD":"other.DB_PASSWORD"}}`, "unknown env set"},
		{"secret unknown key", `{"kind":"service","image":"nginx","secret_env":{"DB_PASSWORD":"services.NOPE"}}`, "unknown env key"},
		{"volume name", `{"kind":"service","image":"nginx","volumes":[{"name":"Bad","target":"/data"}]}`, "invalid volumes"},
		{"volume dot", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/a/../b"}]}`, "invalid volumes"},
		{"volume dup", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data"},{"name":"other","target":"/data"}]}`, "invalid volumes"},
		{"user root", `{"kind":"service","image":"nginx","user":"root"}`, "invalid user"},
		{"user zero", `{"kind":"service","image":"nginx","user":"0"}`, "invalid user"},
		{"user gid", `{"kind":"service","image":"nginx","user":"joe:0"}`, "invalid user"},
		{"user lead", `{"kind":"service","image":"nginx","user":"01"}`, "invalid user"},
		{"restart", `{"kind":"service","image":"nginx","restart":"always"}`, "invalid restart"},
		{"extra", `{"kind":"service","image":"nginx","cap_add":["SYS_ADMIN"]}`, "invalid spec"},
	}
	for _, tc := range refusals {
		n := "web"
		switch tc.name {
		case "name":
			n = "Bad"
		case "trailing":
			n = "web-"
		case "prev":
			n = "web-prev"
		}
		_, err := BuildImage(n, []byte(tc.spec), sets)
		if tc.spec == "" && tc.name != "name" && tc.name != "trailing" && tc.name != "prev" {
			continue
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "/a/../b") || strings.Contains(err.Error(), "missing") {
			t.Fatalf("%s echoes a value: %v", tc.name, err)
		}
	}
	ok, err := base(`{"kind":"service","image":"nginx","user":"joe:100","secret_env":{"DB_PASSWORD":"services.DB_PASSWORD"},"env_sets":["services"],"ports":[{"host":8080,"container":80,"public":false}],"volumes":[{"name":"data","target":"/var/data","read_only":true}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ok.User != "joe:100" || ok.SecretEnv["DB_PASSWORD"] != "services.DB_PASSWORD" || len(ok.Ports) != 1 || !ok.Volumes[0].ReadOnly {
		t.Fatalf("accepted %+v", ok)
	}
	body := SpecJSON(ok)
	if !strings.Contains(body, `"image":"docker.io/library/nginx:latest"`) {
		t.Fatal("spec json dropped the image")
	}
	again, err := ParseStored([]byte(body))
	if err != nil || again.Image != ok.Image || again.User != ok.User || again.RegistryHost != "docker.io" || again.SecretEnv["DB_PASSWORD"] != ok.SecretEnv["DB_PASSWORD"] {
		t.Fatalf("round trip %+v %v", again, err)
	}
}

func TestImageHashKeysNotValues(t *testing.T) {
	sets := SetKeys{"services": {"A"}}
	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["services"],"env":{"NODE_ENV":"a"}}`), sets)
	if err != nil {
		t.Fatal(err)
	}
	one := map[string]string{"services": EnvKeyDigest([]string{"A"})}
	two := map[string]string{"services": EnvKeyDigest([]string{"A", "B"})}
	same := map[string]string{"services": EnvKeyDigest([]string{"A"})}
	if ImageHash(img, one) != ImageHash(img, same) {
		t.Fatal("value-independent digest changed the hash")
	}
	if ImageHash(img, one) == ImageHash(img, two) {
		t.Fatal("added key did not change the hash")
	}
	if EnvKeyDigest(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty key digest")
	}
	before := ImageHash(img, one)
	img.Env["NODE_ENV"] = "b"
	if ImageHash(img, one) == before {
		t.Fatal("inline env value did not change the hash")
	}
	if !ReferencesSet(img, "services") || ReferencesSet(img, "other") {
		t.Fatal("references")
	}
	if DeployTimeoutSec(img) != 300+30+60 {
		t.Fatal("service timeout")
	}
	job, err := BuildImage("job", []byte(`{"kind":"job","image":"nginx"}`), nil)
	if err != nil || DeployTimeoutSec(job) != 300+600+60 || RollbackTimeoutSec(job) != 360 {
		t.Fatalf("job timeout %+v %v", job, err)
	}
}

func manyArgs(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"a"`
	}
	return "[" + strings.Join(parts, ",") + "]"
}
