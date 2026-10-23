package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/registry"
	"github.com/more-than-code/bot-api-server/internal/registry/registrytest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type registryFixture struct {
	w                                *world
	fake                             *registrytest.Fake
	sc                               scene
	project                          string
	owner, admin, viewer, extra, del string
	adminDel                         string

	mu    sync.Mutex
	calls map[string]int
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, w.user("spare@ex.com", "Spare"), extra)
	f := registrytest.New(t)
	w.srv.Registry = f.Service()
	return &registryFixture{
		w: w, fake: f, sc: sc, project: sc.project.ID.String(),
		owner: w.token(owner.ID), admin: w.token(admin.ID), viewer: w.token(viewer.ID), extra: w.token(extra.ID),
		del:      tokenKind(t, w, owner.ID, store.KindDelegated),
		adminDel: tokenKind(t, w, admin.ID, store.KindMCPAccess),
		calls:    map[string]int{},
	}
}

func (f *registryFixture) count(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.Method+" "+r.Host+r.URL.Path]++
}

func (f *registryFixture) upstream(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

// public serves anonymous tags and HEAD digests for every repository.
func (f *registryFixture) public(tags []string, digest string) {
	body, _ := json.Marshal(map[string]any{"tags": tags})
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		f.count(r)
		if strings.Contains(r.URL.Path, "/manifests/") {
			if strings.HasSuffix(r.URL.Path, "/missing") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", digest)
			return
		}
		_, _ = w.Write(body)
	})
}

func tagsPath(project, image string) string {
	return "/v1/projects/" + project + "/image-tags?image=" + url.QueryEscape(image)
}

func digestPath(project, image string) string {
	return "/v1/projects/" + project + "/image-digest?image=" + url.QueryEscape(image)
}

func callHeaders(t *testing.T, w *world, token, path string) (int, envelope, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, w.http.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := w.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, env, res.Header
}

func tagNames(t *testing.T, env envelope) ([]string, bool) {
	t.Helper()
	p := objectPayload(t, env)
	items, _ := p["items"].([]any)
	out := make([]string, len(items))
	for i, it := range items {
		m, _ := it.(map[string]any)
		out[i], _ = m["tag"].(string)
	}
	truncated, _ := p["truncated"].(bool)
	return out, truncated
}

func TestImageTagsAccess(t *testing.T) {
	f := newRegistryFixture(t)
	f.public([]string{"latest", "v1.4.1", "v1.4.2", "edge"}, "")
	path := tagsPath(f.project, "ghcr.io/joe/mo-services:v1@sha256:"+strings.Repeat("a", 64))
	for _, tok := range []string{f.owner, f.admin} {
		status, env, _ := mustCall(t, f.w, tok, http.MethodGet, path, "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		tags, truncated := tagNames(t, env)
		if strings.Join(tags, ",") != "v1.4.2,v1.4.1,latest,edge" || truncated {
			t.Fatalf("tags %v truncated %v", tags, truncated)
		}
	}
	status, env, _ := mustCall(t, f.w, f.viewer, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, f.w, f.del, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, f.w, f.adminDel, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusUnauthorized, "invalid_token", "invalid token")
	status, env, _ = mustCall(t, f.w, f.extra, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	for _, bad := range []string{"", "Ghcr.io/Joe/App", "ghcr.io/joe/app:bad tag", "a//b"} {
		status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, bad), "")
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid image")
	}
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "registry.example.org/app"), "")
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "registry not allowed")
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "registry.example.org/app:v1"), "")
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "registry not allowed")
	if n := f.upstream("GET ghcr.io/v2/joe/mo-services/tags/list"); n != 1 {
		t.Fatalf("upstream %d, want 1 (the project cache serves the admin)", n)
	}
	// Viewer and delegated digest calls are refused too.
	dpath := digestPath(f.project, "ghcr.io/joe/app:v1")
	status, env, _ = mustCall(t, f.w, f.viewer, http.MethodGet, dpath, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, f.w, f.del, http.MethodGet, dpath, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
}

func TestImageTagsStoredHostAllowed(t *testing.T) {
	f := newRegistryFixture(t)
	buf := captureLog(f.w)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "reg.test", "bot", "stored-token")
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("bot:stored-token")) {
			w.Header().Set("WWW-Authenticate", `Basic realm="reg"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"tags":["1.0.0"]}`)
	})
	status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "reg.test/team/app"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(buf.String(), "auth=stored") || !strings.Contains(buf.String(), "host=reg.test path=team/app outcome=ok") {
		t.Fatalf("log line: %s", buf.String())
	}
}

// TestImageLookupMissingKeyMatchesDeploy: a stored registry with no secrets
// key answers exactly as an image deploy that needs the key does.
func TestImageLookupMissingKeyMatchesDeploy(t *testing.T) {
	f := newRegistryFixture(t)
	f.public([]string{"v1"}, "sha256:"+strings.Repeat("d", 64))
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "ghcr.io", "bot", "stored-token")
	createImage(t, f.w, f.owner, f.sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app"}`)
	helloAgent(t, f.w, f.sc.host, f.sc.credPlain, f.sc.credID, allowImages(), nil)
	f.w.srv.Secrets = nil
	dStatus, dEnv, dRaw := postImage(t, f.w, f.owner, f.project, "web", "deploy", f.sc.host.ID.String(), "need-key", nil)
	mustHTTP(t, dStatus, dEnv, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	for _, path := range []string{tagsPath(f.project, "ghcr.io/joe/app"), digestPath(f.project, "ghcr.io/joe/app:v1")} {
		status, _, raw := mustCall(t, f.w, f.owner, http.MethodGet, path, "")
		if status != dStatus || raw != dRaw {
			t.Fatalf("%s: %d %s, deploy %d %s", path, status, raw, dStatus, dRaw)
		}
	}
	if len(f.fake.Dialed()) != 0 {
		t.Fatal("a lookup went upstream without the key")
	}
}

// TestCatalogEntryNamedImageTags: the lookup routes sit outside /catalog/,
// so entries with these names stay readable.
func TestCatalogEntryNamedImageTags(t *testing.T) {
	f := newRegistryFixture(t)
	for _, name := range []string{"image-tags", "image-digest"} {
		createImage(t, f.w, f.owner, f.sc.project.ID, name, `{"kind":"service","image":"nginx"}`)
		got := createImageGet(t, f.w, f.owner, f.sc.project.ID, name)
		if got["name"] != name {
			t.Fatalf("GET catalog/%s returned %#v", name, got)
		}
	}
}

func TestImageTagsTruncated(t *testing.T) {
	f := newRegistryFixture(t)
	tags := make([]string, 260)
	for i := range tags {
		tags[i] = fmt.Sprintf("1.%d.0", i)
	}
	f.public(append(tags, "latest"), "")
	status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "nginx"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got, truncated := tagNames(t, env)
	if len(got) != 200 || !truncated || got[0] != "1.259.0" {
		t.Fatalf("len %d truncated %v first %s", len(got), truncated, got[0])
	}
	if f.upstream("GET registry-1.docker.io/v2/library/nginx/tags/list") != 1 {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestImageLookupCacheAndRateLimit(t *testing.T) {
	f := newRegistryFixture(t)
	digest := "sha256:" + strings.Repeat("b", 64)
	f.public([]string{"v1"}, digest)
	for i := 0; i < 5; i++ {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/app"), "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	if n := f.upstream("GET ghcr.io/v2/joe/app/tags/list"); n != 1 {
		t.Fatalf("cache: upstream %d", n)
	}
	for i := 1; i < 20; i++ {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, fmt.Sprintf("ghcr.io/joe/app%d", i)), "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	status, env, hdr := callHeaders(t, f.w, f.owner, tagsPath(f.project, "ghcr.io/joe/app21"))
	mustHTTP(t, status, env, http.StatusTooManyRequests, "rate_limited", "rate limited")
	if hdr.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	status, env, hdr = callHeaders(t, f.w, f.owner, digestPath(f.project, "ghcr.io/joe/app:v1"))
	mustHTTP(t, status, env, http.StatusTooManyRequests, "rate_limited", "rate limited")
	if hdr.Get("Retry-After") == "" {
		t.Fatal("digest 429 without Retry-After")
	}
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/app"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = mustCall(t, f.w, f.admin, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:v1"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["digest"] != digest {
		t.Fatalf("digest %#v", env.Payload)
	}
}

func TestImageLookupErrorsNotCached(t *testing.T) {
	f := newRegistryFixture(t)
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		f.count(r)
		http.NotFound(w, r)
	})
	for i := 0; i < 2; i++ {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/gone"), "")
		if status != http.StatusBadGateway || env.Code != "registry_unavailable" || env.Msg != "registry unavailable" {
			t.Fatalf("status %d env %#v", status, env)
		}
		if p := objectPayload(t, env); len(p) != 1 || p["reason"] != "not_found" {
			t.Fatalf("payload %#v", p)
		}
	}
	if n := f.upstream("GET ghcr.io/v2/joe/gone/tags/list"); n != 2 {
		t.Fatalf("errors were cached: upstream %d", n)
	}
}

func TestImageDigestRoute(t *testing.T) {
	f := newRegistryFixture(t)
	good := "sha256:" + strings.Repeat("c", 64)
	f.public(nil, good)
	status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:v1.4.2"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["digest"] != good {
		t.Fatalf("digest %#v", env.Payload)
	}
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:v1.4.2"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if n := f.upstream("HEAD ghcr.io/v2/joe/app/manifests/v1.4.2"); n != 1 {
		t.Fatalf("digest cache: upstream %d", n)
	}
	for _, bad := range []string{"ghcr.io/joe/app", "ghcr.io/joe/app@" + good, "ghcr.io/joe/app:v1@" + good} {
		status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, bad), "")
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid image")
	}
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:missing"), "")
	if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "not_found" {
		t.Fatalf("missing tag %d %#v", status, env)
	}
	f.public(nil, "sha256:NOTHEX")
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:v2"), "")
	if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "bad_response" {
		t.Fatalf("invalid header %d %#v", status, env)
	}
	f.fake.Resolve("ghcr.io", "127.0.0.1")
	f.w.srv.Registry = f.fake.Service() // a fresh pool, so no kept-alive connection is reused
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, digestPath(f.project, "ghcr.io/joe/app:v3"), "")
	if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "unreachable" {
		t.Fatalf("guard %d %#v", status, env)
	}
}

func TestImageLookupNeverLeaks(t *testing.T) {
	const canary = "stored-registry-token-canary-7f3a9c41"
	const bearerCanary = "tok-CANARY-bearer-0123456789abcdef"
	const bodyCanary = "registry-body-CANARY-text"
	f := newRegistryFixture(t)
	buf := captureLog(f.w)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "ghcr.io", "bot", canary)
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprintf(w, `{"token":%q}`, bearerCanary)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://ghcr.io/token",service="ghcr.io"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, bodyCanary)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, bodyCanary+" "+canary)
	})
	var seen strings.Builder
	for _, path := range []string{tagsPath(f.project, "ghcr.io/joe/private"), digestPath(f.project, "ghcr.io/joe/private:v1")} {
		status, env, raw := mustCall(t, f.w, f.owner, http.MethodGet, path, "")
		if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "auth_failed" {
			t.Fatalf("%s: %d %#v", path, status, env)
		}
		seen.WriteString(raw)
	}
	seen.WriteString(buf.String())
	for _, secret := range []string{canary, bearerCanary, bodyCanary, base64.StdEncoding.EncodeToString([]byte("bot:" + canary))} {
		if strings.Contains(seen.String(), secret) {
			t.Fatalf("leaked %q", secret)
		}
	}
	if !strings.Contains(buf.String(), "outcome=auth_failed") || !strings.Contains(buf.String(), "auth=stored") {
		t.Fatalf("log line: %s", buf.String())
	}
}

// projectB creates a second project owned by the fixture owner.
func (f *registryFixture) projectB(t *testing.T) string {
	t.Helper()
	owner := f.w.user("owner@ex.com", "Owner")
	p, err := f.w.mem.CreateProject(context.Background(), owner.ID, "Other", "other", f.w.now)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID.String()
}

func TestImageLookupCachePerProject(t *testing.T) {
	f := newRegistryFixture(t)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "ghcr.io", "bot", "stored-token")
	other := f.projectB(t)
	digest := "sha256:" + strings.Repeat("e", 64)
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		f.count(r)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot:stored-token"))
		private := r.Header.Get("Authorization") == want
		switch {
		case r.Header.Get("Authorization") == "" && r.Host == "ghcr.io" && r.URL.Path != "/token":
			w.Header().Set("WWW-Authenticate", `Basic realm="ghcr"`)
			w.WriteHeader(http.StatusUnauthorized)
		case !private:
			w.WriteHeader(http.StatusForbidden)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", digest)
		default:
			fmt.Fprint(w, `{"tags":["private-1"]}`)
		}
	})
	// Project A answers a Basic challenge (2 requests); project B is
	// anonymous and refused (1 request). A shared cache would make B 0.
	for _, tc := range []struct{ path, other, key string }{
		{tagsPath(f.project, "ghcr.io/joe/app"), tagsPath(other, "ghcr.io/joe/app"), "GET ghcr.io/v2/joe/app/tags/list"},
		{digestPath(f.project, "ghcr.io/joe/app:v1"), digestPath(other, "ghcr.io/joe/app:v1"), "HEAD ghcr.io/v2/joe/app/manifests/v1"},
	} {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tc.path, "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		afterA := f.upstream(tc.key)
		status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tc.path, "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		if f.upstream(tc.key) != afterA {
			t.Fatal("project A repeat was not a cache hit")
		}
		status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tc.other, "")
		if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "not_found" {
			t.Fatalf("project B was served project A's result: %d %#v", status, env)
		}
		if n := f.upstream(tc.key); afterA != 2 || n != 3 {
			t.Fatalf("%s upstream A %d total %d, want 2 and 3", tc.key, afterA, n)
		}
	}
}

func TestImageLookupStoredHostIsPerProject(t *testing.T) {
	f := newRegistryFixture(t)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "reg.test", "bot", "stored-token")
	other := f.projectB(t)
	for _, path := range []string{tagsPath(other, "reg.test/app"), digestPath(other, "reg.test/app:v1")} {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, path, "")
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "registry not allowed")
	}
	if r := f.fake.Resolved(); len(r) != 0 {
		t.Fatalf("resolved %v", r)
	}
}

func TestImageLookupStoredHostPort(t *testing.T) {
	f := newRegistryFixture(t)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "reg.test:5000", "bot", "stored-token")
	status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "reg.test:5000/app"), "")
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "registry not allowed")
	if len(f.fake.Resolved()) != 0 || len(f.fake.Dialed()) != 0 {
		t.Fatal("a non-443 stored host was contacted")
	}
}

func TestImageLookupClock(t *testing.T) {
	f := newRegistryFixture(t)
	f.public([]string{"v1"}, "sha256:"+strings.Repeat("f", 64))
	cur := f.w.now
	f.w.srv.Now = func() time.Time { return cur }
	path := tagsPath(f.project, "ghcr.io/joe/app")
	for i := 0; i < 2; i++ {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, path, "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	cur = cur.Add(61 * time.Second)
	status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if n := f.upstream("GET ghcr.io/v2/joe/app/tags/list"); n != 2 {
		t.Fatalf("after TTL upstream %d, want 2", n)
	}
	for i := 0; i < 19; i++ {
		status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, fmt.Sprintf("ghcr.io/joe/x%d", i)), "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/over"), "")
	mustHTTP(t, status, env, http.StatusTooManyRequests, "rate_limited", "rate limited")
	cur = cur.Add(61 * time.Second)
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/over"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
}

func TestImageLookupConcurrencyCap(t *testing.T) {
	f := newRegistryFixture(t)
	opts := f.fake.Options(false)
	opts.Concurrency = 2
	f.w.srv.Registry = registry.NewService(opts)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		f.count(r)
		<-release
		fmt.Fprint(w, `{"tags":["a"]}`)
	})
	done := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			status, _, _, err := callRaw(f.w, f.owner, http.MethodGet, tagsPath(f.project, fmt.Sprintf("ghcr.io/joe/held%d", i)), "")
			if err != nil {
				status = -1
			}
			done <- status
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.upstream("GET ghcr.io/v2/joe/held0/tags/list")+f.upstream("GET ghcr.io/v2/joe/held1/tags/list") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("held lookups did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	status, env, hdr := callHeaders(t, f.w, f.admin, digestPath(f.project, "ghcr.io/joe/third:v1"))
	mustHTTP(t, status, env, http.StatusTooManyRequests, "rate_limited", "rate limited")
	if hdr.Get("Retry-After") != "1" {
		t.Fatalf("Retry-After %q", hdr.Get("Retry-After"))
	}
	unblock()
	for i := 0; i < 2; i++ {
		if st := <-done; st != http.StatusOK {
			t.Fatalf("held lookup %d", st)
		}
	}
}

func TestImageLookupAccessGaps(t *testing.T) {
	f := newRegistryFixture(t)
	f.public([]string{"v1"}, "sha256:"+strings.Repeat("a", 64))
	for _, path := range []string{tagsPath(f.project, "nginx"), digestPath(f.project, "nginx:1")} {
		status, env, _ := mustCall(t, f.w, "", http.MethodGet, path, "")
		mustHTTP(t, status, env, http.StatusUnauthorized, "unauthorized", "unauthorized")
	}
	_, _, tagsRaw := mustCall(t, f.w, f.extra, http.MethodGet, tagsPath(f.project, "nginx"), "")
	status, env, digestRaw := mustCall(t, f.w, f.extra, http.MethodGet, digestPath(f.project, "nginx:1"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if tagsRaw != digestRaw {
		t.Fatalf("non-member: tags %s digest %s", tagsRaw, digestRaw)
	}
	f.w.srv.Registry = nil
	status, env, _ = mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "nginx"), "")
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "registry lookups unavailable")
	if len(f.fake.Resolved()) != 0 {
		t.Fatal("went upstream")
	}
}

func TestImageLookupUpstreamOverload(t *testing.T) {
	f := newRegistryFixture(t)
	for i, st := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		f.fake.Handle(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(st) })
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, fmt.Sprintf("ghcr.io/joe/busy%d", i)), "")
		if status != http.StatusBadGateway || objectPayload(t, env)["reason"] != "unreachable" {
			t.Fatalf("upstream %d: %d %#v", st, status, env)
		}
	}
}

func TestImageLookupLogLine(t *testing.T) {
	f := newRegistryFixture(t)
	buf := captureLog(f.w)
	f.w.srv.Secrets = testBox(t)
	putRegistry(t, f.w, f.owner, f.project, "ghcr.io", "bot", "stored-token")
	f.fake.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "evil.test" {
			fmt.Fprint(w, `{"token":"tok-123"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://evil.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"tags":["a"]}`)
	})
	for i := 0; i < 2; i++ {
		status, env, _ := mustCall(t, f.w, f.owner, http.MethodGet, tagsPath(f.project, "ghcr.io/joe/app"), "")
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	log := buf.String()
	if !strings.Contains(log, "kind=tags host=ghcr.io path=joe/app outcome=ok") || !strings.Contains(log, "auth=anonymous") {
		t.Fatalf("log: %s", log)
	}
	if strings.Contains(log, "auth=stored") {
		t.Fatalf("a withheld credential was logged as sent: %s", log)
	}
	if !strings.Contains(log, "outcome=cache ms=0 auth=cache") {
		t.Fatalf("cache hit not logged: %s", log)
	}
}
