package registry_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/registry"
	"github.com/more-than-code/bot-api-server/internal/registry/registrytest"
)

const bearer = "Bearer tok-123"

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// seen records the Authorization header per host and path.
type seen struct {
	mu   sync.Mutex
	auth map[string][]string
}

func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auth == nil {
		s.auth = map[string][]string{}
	}
	key := r.Host + r.URL.Path
	s.auth[key] = append(s.auth[key], r.Header.Get("Authorization"))
}

func (s *seen) get(key string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth[key]...)
}

// tokenRegistry answers tags on regHost behind a Bearer challenge whose
// realm is https://realmHost/token. tags is the list body.
func tokenRegistry(f *registrytest.Fake, s *seen, regHost, realmHost, tagsBody string) {
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		switch {
		case r.Host == realmHost && r.URL.Path == "/token":
			if r.URL.Query().Get("scope") == "" {
				http.Error(w, "no scope", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"token":"tok-123"}`)
		case r.Host == regHost && strings.HasSuffix(r.URL.Path, "/tags/list"):
			if r.Header.Get("Authorization") != bearer {
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+realmHost+`/token",service="`+regHost+`",scope="repository:x:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, tagsBody)
		default:
			http.NotFound(w, r)
		}
	})
}

func code(t *testing.T, err error) string {
	t.Helper()
	var re *registry.Error
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a registry.Error", err)
	}
	return re.Code
}

func TestTagsAnonymousTokenFlow(t *testing.T) {
	f := registrytest.New(t)
	s := &seen{}
	tokenRegistry(f, s, "ghcr.io", "ghcr.io", `{"tags":["v1","v2"]}`)
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(list.Tags, ",") != "v1,v2" || list.More {
		t.Fatalf("list %#v", list)
	}
	if got := s.get("ghcr.io/token"); len(got) != 1 || got[0] != "" {
		t.Fatalf("anonymous token request sent %q", got)
	}
}

func TestTagsBasicThroughSameHostRealm(t *testing.T) {
	f := registrytest.New(t)
	s := &seen{}
	tokenRegistry(f, s, "ghcr.io", "ghcr.io", `{"tags":["v1"]}`)
	cred := &registry.Credential{Username: "bot", Token: "ghp_secret"}
	if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app", Cred: cred}); err != nil {
		t.Fatal(err)
	}
	if got := s.get("ghcr.io/token"); len(got) != 1 || got[0] != basic("bot", "ghp_secret") {
		t.Fatalf("realm auth %q", got)
	}
	for _, a := range s.get("ghcr.io/v2/o/app/tags/list") {
		if strings.HasPrefix(a, "Basic") {
			t.Fatal("Basic sent to the tags endpoint")
		}
	}
}

func TestHostileRealmGetsNoCredentials(t *testing.T) {
	f := registrytest.New(t)
	s := &seen{}
	tokenRegistry(f, s, "ghcr.io", "evil.test", `{"tags":["v1"]}`)
	cred := &registry.Credential{Username: "bot", Token: "ghp_secret"}
	if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app", Cred: cred}); err != nil {
		t.Fatal(err)
	}
	got := s.get("evil.test/token")
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("hostile realm received %q", got)
	}
}

func TestDockerHubRealmException(t *testing.T) {
	f := registrytest.New(t)
	s := &seen{}
	tokenRegistry(f, s, "registry-1.docker.io", "auth.docker.io", `{"tags":["1.27"]}`)
	cred := &registry.Credential{Username: "joe", Token: "dckr_pat"}
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "docker.io", Path: "library/nginx", Cred: cred})
	if err != nil || len(list.Tags) != 1 {
		t.Fatalf("%v %#v", err, list)
	}
	if got := s.get("auth.docker.io/token"); len(got) != 1 || got[0] != basic("joe", "dckr_pat") {
		t.Fatalf("auth.docker.io auth %q", got)
	}
	if len(s.get("docker.io/v2/library/nginx/tags/list")) != 0 {
		t.Fatal("docker.io was fetched instead of registry-1.docker.io")
	}
}

func TestBasicChallengeUsesStoredCredential(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != basic("u", "p") {
			w.Header().Set("WWW-Authenticate", `Basic realm="reg"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"tags":["a"]}`)
	})
	c := f.Client()
	if _, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app", Cred: &registry.Credential{Username: "u", Token: "p"}}); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if code(t, err) != registry.CodeNotFound {
		t.Fatalf("anonymous basic challenge: %v", err)
	}
}

func pagedRegistry(f *registrytest.Fake, pages int, next func(page int) string) func() int {
	served := 0
	var mu sync.Mutex
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		page := 0
		fmt.Sscanf(r.URL.Query().Get("last"), "p%d", &page)
		if page+1 < pages {
			w.Header().Set("Link", next(page+1))
		}
		fmt.Fprintf(w, `{"tags":["t%d-a","t%d-b"]}`, page, page)
	})
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return served
	}
}

func TestTagsPagination(t *testing.T) {
	f := registrytest.New(t)
	pagedRegistry(f, 3, func(p int) string { return fmt.Sprintf(`</v2/app/tags/list?n=100&last=p%d>; rel="next"`, p) })
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tags) != 6 || list.More {
		t.Fatalf("list %#v", list)
	}
}

func TestTagsPageCap(t *testing.T) {
	f := registrytest.New(t)
	served := pagedRegistry(f, 100, func(p int) string {
		return fmt.Sprintf(`<https://reg.test/v2/app/tags/list?n=100&last=p%d>; rel="next"`, p)
	})
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if served() != 5 || len(list.Tags) != 10 || !list.More {
		t.Fatalf("served %d, list %d more %v", served(), len(list.Tags), list.More)
	}
}

func TestTagsRawCap(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		tags := make([]string, 300)
		for i := range tags {
			tags[i] = fmt.Sprintf(`"%s-%03d"`, r.URL.Query().Get("last"), i)
		}
		w.Header().Set("Link", `</v2/app/tags/list?last=z>; rel="next"`)
		fmt.Fprintf(w, `{"tags":[%s]}`, strings.Join(tags, ","))
	})
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tags) != 500 || !list.More {
		t.Fatalf("read %d more %v", len(list.Tags), list.More)
	}
}

func TestTagsCrossHostNextRefused(t *testing.T) {
	for _, link := range []string{
		`<https://other.test/v2/app/tags/list?last=p1>; rel="next"`,
		`<http://reg.test/v2/app/tags/list?last=p1>; rel="next"`,
		`<//other.test/v2/app/tags/list?last=p1>; rel="next"`,
	} {
		f := registrytest.New(t)
		pagedRegistry(f, 3, func(int) string { return link })
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
		if code(t, err) != registry.CodeBadResponse {
			t.Fatalf("%s: %v", link, err)
		}
		for _, h := range f.Resolved() {
			if h == "other.test" {
				t.Fatalf("%s: next host was resolved", link)
			}
		}
	}
}

func TestTagsBodyCap(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tags":["`+strings.Repeat("a", 1<<20)+`"]}`)
	})
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if code(t, err) != registry.CodeBadResponse {
		t.Fatalf("over-cap body: %v", err)
	}
}

func TestTagsErrorCodes(t *testing.T) {
	// want is the reason for an anonymous lookup; stored, when set, is the
	// reason when a stored credential is sent to the same-host realm.
	cases := []struct {
		name   string
		h      http.HandlerFunc
		want   string
		stored string
	}{
		{"401 after token", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				fmt.Fprint(w, `{"token":"tok-123"}`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token",service="reg.test"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeNotFound, registry.CodeAuthFailed},
		{"403 after token", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				fmt.Fprint(w, `{"token":"tok-123"}`)
				return
			}
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		}, registry.CodeNotFound, registry.CodeAuthFailed},
		{"realm refuses", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeNotFound, registry.CodeAuthFailed},
		{"anonymous 403 without challenge", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, registry.CodeNotFound, ""},
		{"http realm", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeBadResponse, ""},
		{"404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, registry.CodeNotFound, ""},
		{"500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, registry.CodeUnreachable, ""},
		{"503", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, registry.CodeUnreachable, ""},
		{"429", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }, registry.CodeUnreachable, ""},
		{"realm 503", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeUnreachable, ""},
		{"realm 429", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeUnreachable, ""},
		{"400", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }, registry.CodeBadResponse, ""},
		{"bad token json", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				fmt.Fprint(w, `{"token":`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, registry.CodeBadResponse, ""},
		{"bad json", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":[`) }, registry.CodeBadResponse, ""},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}, registry.CodeTimeout, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := registrytest.New(t)
			f.Handle(tc.h)
			c := f.Client()
			registry.SetTimeouts(c, 200*time.Millisecond, 0)
			stored := tc.stored
			if stored == "" {
				stored = tc.want
			}
			for _, run := range []struct {
				cred *registry.Credential
				want string
			}{{nil, tc.want}, {&registry.Credential{Username: "u", Token: "p"}, stored}} {
				_, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app", Cred: run.cred})
				if got := code(t, err); got != run.want {
					t.Fatalf("stored=%v: code %s, want %s", run.cred != nil, got, run.want)
				}
				if strings.Contains(err.Error(), "reg.test") {
					t.Fatalf("error text carries a URL: %v", err)
				}
			}
		})
	}
}

// TestDockerHubMissingRepository: Hub issues a token for any scope and then
// answers UNAUTHORIZED for a repository that does not exist.
func TestDockerHubMissingRepository(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.docker.io" {
			fmt.Fprint(w, `{"token":"tok-123"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nope:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`)
	})
	c := f.Client()
	_, _, err := c.Tags(context.Background(), registry.Repo{Host: "docker.io", Path: "library/nope"})
	if code(t, err) != registry.CodeNotFound {
		t.Fatalf("anonymous missing repository: %v", err)
	}
	_, _, err = c.Digest(context.Background(), registry.Repo{Host: "docker.io", Path: "library/nope"}, "v1")
	if code(t, err) != registry.CodeNotFound {
		t.Fatalf("anonymous missing repository digest: %v", err)
	}
	_, _, err = c.Tags(context.Background(), registry.Repo{Host: "docker.io", Path: "joe/private", Cred: &registry.Credential{Username: "joe", Token: "bad"}})
	if code(t, err) != registry.CodeAuthFailed {
		t.Fatalf("refused stored credential: %v", err)
	}
}

// TestHostileRealmCredentialNotUsed: a stored credential withheld from a
// foreign realm was not used, so a later 401 is not_found.
func TestHostileRealmCredentialNotUsed(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "evil.test" {
			fmt.Fprint(w, `{"token":"tok-123"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://evil.test/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app", Cred: &registry.Credential{Username: "u", Token: "p"}})
	if code(t, err) != registry.CodeNotFound {
		t.Fatalf("withheld credential: %v", err)
	}
}

func TestLookupTimeout(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Link", `</v2/app/tags/list?last=x>; rel="next"`)
		fmt.Fprint(w, `{"tags":["a"]}`)
	})
	c := f.Client()
	registry.SetTimeouts(c, time.Second, 200*time.Millisecond)
	_, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if code(t, err) != registry.CodeTimeout {
		t.Fatalf("lookup budget: %v", err)
	}
}

func TestOrder(t *testing.T) {
	in := []string{"latest", "alpha", "v1.2.0", "1.10.0", "1.9.3", "zeta", "1.10.0-rc1", "bad tag", "-x", "1.10", "v1.2.0", "2", strings.Repeat("a", 129)}
	got, truncated := registry.Order(registry.TagList{Tags: in})
	want := "2,1.10.0,1.10.0-rc1,1.10,1.9.3,v1.2.0,latest,zeta,alpha"
	if strings.Join(got, ",") != want || truncated {
		t.Fatalf("order %s truncated %v", strings.Join(got, ","), truncated)
	}
	got, _ = registry.Order(registry.TagList{Tags: []string{strings.Repeat("b", 128), strings.Repeat("b", 129)}})
	if len(got) != 1 || len(got[0]) != 128 {
		t.Fatalf("128/129 boundary: %v", got)
	}
	many := make([]string, 250)
	for i := range many {
		many[i] = fmt.Sprintf("1.0.%d", i)
	}
	got, truncated = registry.Order(registry.TagList{Tags: many})
	if len(got) != registry.MaxItems || !truncated || got[0] != "1.0.249" {
		t.Fatalf("len %d truncated %v first %s", len(got), truncated, got[0])
	}
	_, truncated = registry.Order(registry.TagList{Tags: []string{"a"}, More: true})
	if !truncated {
		t.Fatal("unread pages did not mark truncated")
	}
}

func TestBlocked(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "fd12::1",
		"ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.1", "198.51.100.1", "203.0.113.10", "240.0.0.1",
		"168.63.129.16", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "::7f00:1", "2002:7f00:1::", "100::1", "fec0::1",
		"::ffff:192.0.2.1",
		"64:ff9b::a9fe:a9fe%x", "::a00:1%1", "2002:7f00:1::%x", "fec0::1%x", "fe80::1%eth0", "2606:4700::1%x",
	} {
		if !registry.Blocked(netip.MustParseAddr(a)) {
			t.Errorf("%s is not blocked", a)
		}
	}
	for _, a := range []string{"93.184.216.10", "140.82.112.33", "2606:4700::1", "100.128.0.1", "168.63.129.17", "64:ff9b:2::1", "2003::1"} {
		if registry.Blocked(netip.MustParseAddr(a)) {
			t.Errorf("%s is blocked", a)
		}
	}
}

func TestGuardRefusesHostileResolutions(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "100.64.0.1", "::ffff:127.0.0.1",
		"0.0.0.0", "::", "224.0.0.1", "ff02::1", "172.16.0.1", "192.168.1.1", "fd00::1",
		"64:ff9b::a9fe:a9fe", "::7f00:1", "2002:7f00:1::", "168.63.129.16",
		"64:ff9b::a9fe:a9fe%x", "::a00:1%1", "2002:7f00:1::%x", "fec0::1%x", "fe80::1%eth0",
	} {
		f := registrytest.New(t)
		f.Handle(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) })
		f.Resolve("ghcr.io", addr)
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
		if code(t, err) != registry.CodeUnreachable {
			t.Fatalf("%s: %v", addr, err)
		}
		if d := f.Dialed(); len(d) != 0 {
			t.Fatalf("%s: dialled %v", addr, d)
		}
	}
}

func TestGuardRefusesIPLiteralHost(t *testing.T) {
	f := registrytest.New(t)
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "10.0.0.1:5000", Path: "app"})
	if code(t, err) != registry.CodeUnreachable || len(f.Dialed()) != 0 {
		t.Fatalf("literal: %v dialled %v", err, f.Dialed())
	}
}

func TestGuardSkipsBlockedAndDialsPublic(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) })
	f.Resolve("ghcr.io", "127.0.0.1", "93.184.216.20")
	if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}); err != nil {
		t.Fatal(err)
	}
	if d := f.Dialed(); len(d) != 1 || d[0] != "93.184.216.20:443" {
		t.Fatalf("dialled %v", d)
	}
}

func TestGuardOnRedirect(t *testing.T) {
	f := registrytest.New(t)
	f.Resolve("internal.test", "10.0.0.1")
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "ghcr.io" {
			http.Redirect(w, r, "https://internal.test/v2/x/tags/list", http.StatusFound)
			return
		}
		fmt.Fprint(w, `{"tags":["a"]}`)
	})
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
	if code(t, err) != registry.CodeUnreachable {
		t.Fatalf("redirect to private: %v", err)
	}
	for _, d := range f.Dialed() {
		if strings.HasPrefix(d, "10.") {
			t.Fatalf("dialled %s", d)
		}
	}
}

func TestRedirectRules(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		f := registrytest.New(t)
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://reg.test/v2/app/tags/list", http.StatusFound)
		})
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
		if code(t, err) != registry.CodeUnreachable {
			t.Fatalf("http redirect: %v", err)
		}
	})
	t.Run("limit", func(t *testing.T) {
		for _, hops := range []int{3, 4} {
			f := registrytest.New(t)
			f.Handle(func(w http.ResponseWriter, r *http.Request) {
				n := 0
				fmt.Sscanf(r.URL.Query().Get("hop"), "%d", &n)
				if n < hops {
					http.Redirect(w, r, fmt.Sprintf("/v2/app/tags/list?hop=%d", n+1), http.StatusFound)
					return
				}
				fmt.Fprint(w, `{"tags":["a"]}`)
			})
			_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
			if hops == 3 && err != nil {
				t.Fatalf("3 redirects: %v", err)
			}
			if hops == 4 && (err == nil || code(t, err) != registry.CodeUnreachable) {
				t.Fatalf("4 redirects: %v", err)
			}
		}
	})
	t.Run("auth dropped across hosts", func(t *testing.T) {
		f := registrytest.New(t)
		s := &seen{}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			s.add(r)
			switch {
			case r.Host == "reg.test" && r.URL.Path == "/token":
				http.Redirect(w, r, "https://other.test/token", http.StatusFound)
			case r.Host == "other.test":
				fmt.Fprint(w, `{"token":"tok-123"}`)
			case r.Header.Get("Authorization") != bearer:
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
				w.WriteHeader(http.StatusUnauthorized)
			default:
				fmt.Fprint(w, `{"tags":["a"]}`)
			}
		})
		cred := &registry.Credential{Username: "u", Token: "p"}
		if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app", Cred: cred}); err != nil {
			t.Fatal(err)
		}
		if got := s.get("other.test/token"); len(got) != 1 || got[0] != "" {
			t.Fatalf("redirected realm received %q", got)
		}
	})
}

func TestGuardOnRealm(t *testing.T) {
	f := registrytest.New(t)
	f.Resolve("meta.test", "169.254.169.254")
	s := &seen{}
	tokenRegistry(f, s, "ghcr.io", "meta.test", `{"tags":["a"]}`)
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
	if code(t, err) != registry.CodeUnreachable {
		t.Fatalf("realm on link-local: %v", err)
	}
	if len(s.get("meta.test/token")) != 0 {
		t.Fatal("realm was reached")
	}
}

func TestAllowPrivate(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) })
	f.Resolve("reg.test", "127.0.0.1")
	if _, _, err := registry.New(f.Options(true)).Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"}); err != nil {
		t.Fatalf("allow private: %v", err)
	}
}

func TestDigestHead(t *testing.T) {
	f := registrytest.New(t)
	d := "sha256:" + strings.Repeat("a", 64)
	var mu sync.Mutex
	var accept string
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/v2/o/app/manifests/v1" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		mu.Lock()
		accept = r.Header.Get("Accept")
		mu.Unlock()
		w.Header().Set("Docker-Content-Digest", d)
	})
	got, _, err := f.Client().Digest(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}, "v1")
	if err != nil || got != d {
		t.Fatalf("%q %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, mt := range []string{"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"} {
		if !strings.Contains(accept, mt) {
			t.Fatalf("Accept %q lacks %s", accept, mt)
		}
	}
}

func TestDigestGetFallback(t *testing.T) {
	f := registrytest.New(t)
	body := `{"schemaVersion":2,"manifests":[]}`
	var mu sync.Mutex
	var methods []string
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		if r.Header.Get("Authorization") != bearer {
			if r.URL.Path == "/token" {
				fmt.Fprint(w, `{"access_token":"tok-123"}`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://ghcr.io/token",service="ghcr.io"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			fmt.Fprint(w, body)
		}
	})
	got, _, err := f.Client().Digest(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}, "v1")
	sum := sha256.Sum256([]byte(body))
	if err != nil || got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("%q %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(methods, ",") != "HEAD,GET,HEAD,GET" {
		t.Fatalf("methods %v", methods)
	}
}

func TestDigestErrors(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	_, _, err := f.Client().Digest(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}, "nope")
	if code(t, err) != registry.CodeNotFound {
		t.Fatalf("missing tag: %v", err)
	}
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, strings.Repeat("x", 4<<20+1))
		}
	})
	_, _, err = f.Client().Digest(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}, "v1")
	if code(t, err) != registry.CodeBadResponse {
		t.Fatalf("manifest over cap: %v", err)
	}
	f.Resolve("ghcr.io", "::1")
	_, _, err = f.Client().Digest(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"}, "v1")
	if code(t, err) != registry.CodeUnreachable {
		t.Fatalf("digest guard: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	l := registry.NewLimiter(2, time.Minute)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("u", now.Add(time.Duration(i)*time.Second)); !ok {
			t.Fatal("under limit refused")
		}
	}
	ok, wait := l.Allow("u", now.Add(10*time.Second))
	if ok || wait != 50*time.Second {
		t.Fatalf("over limit %v wait %v", ok, wait)
	}
	if ok, _ := l.Allow("other", now); !ok {
		t.Fatal("buckets are not per key")
	}
	if ok, _ := l.Allow("u", now.Add(61*time.Second)); !ok {
		t.Fatal("window did not slide")
	}
}

func TestCache(t *testing.T) {
	c := registry.NewCache(time.Minute, 2)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	c.Put("a", 1, now)
	if v, ok := c.Get("a", now.Add(59*time.Second)); !ok || v != 1 {
		t.Fatal("fresh entry missing")
	}
	if _, ok := c.Get("a", now.Add(time.Minute)); ok {
		t.Fatal("expired entry returned")
	}
	c.Put("b", 2, now)
	c.Put("c", 3, now)
	if _, ok := c.Get("c", now); ok {
		t.Fatal("cache grew past Max")
	}
	c.Put("c", 3, now.Add(2*time.Minute))
	if _, ok := c.Get("c", now.Add(2*time.Minute)); !ok {
		t.Fatal("expired entries were not dropped when full")
	}
}

func TestTagsBodyAtCap(t *testing.T) {
	f := registrytest.New(t)
	head, tail := `{"tags":["a"],"pad":"`, `"}`
	body := head + strings.Repeat("x", 1<<20-len(head)-len(tail)) + tail
	f.Handle(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	list, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
	if err != nil || len(list.Tags) != 1 || len(body) != 1<<20 {
		t.Fatalf("body at cap: %v %#v", err, list)
	}
}

func TestGuardPublicThenPrivate(t *testing.T) {
	f := registrytest.New(t)
	f.Handle(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) })
	f.Resolve("ghcr.io", "93.184.216.30", "10.0.0.5")
	f.FailDial("93.184.216.30:443")
	_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
	if code(t, err) != registry.CodeUnreachable {
		t.Fatalf("err %v", err)
	}
	for _, d := range f.Dialed() {
		if d != "93.184.216.30:443" {
			t.Fatalf("dialled %s", d)
		}
	}
	if len(f.Dialed()) == 0 {
		t.Fatal("public address was not tried")
	}
}

func TestSubdomainRedirectDropsAuth(t *testing.T) {
	cred := &registry.Credential{Username: "u", Token: "p"}
	t.Run("token request with Basic", func(t *testing.T) {
		f := registrytest.New(t)
		s := &seen{}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			s.add(r)
			switch {
			case r.Host == "reg.test" && r.URL.Path == "/token":
				http.Redirect(w, r, "https://sub.reg.test/token?"+r.URL.RawQuery, http.StatusFound)
			case r.Host == "sub.reg.test":
				fmt.Fprint(w, `{"token":"tok-123"}`)
			case r.Header.Get("Authorization") != bearer:
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
				w.WriteHeader(http.StatusUnauthorized)
			default:
				fmt.Fprint(w, `{"tags":["a"]}`)
			}
		})
		if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app", Cred: cred}); err != nil {
			t.Fatal(err)
		}
		if got := s.get("reg.test/token"); len(got) != 1 || got[0] != basic("u", "p") {
			t.Fatalf("realm %q", got)
		}
		if got := s.get("sub.reg.test/token"); len(got) != 1 || got[0] != "" {
			t.Fatalf("subdomain received %q", got)
		}
	})
	t.Run("tags request with Bearer", func(t *testing.T) {
		f := registrytest.New(t)
		s := &seen{}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			s.add(r)
			switch {
			case r.URL.Path == "/token":
				fmt.Fprint(w, `{"token":"tok-123"}`)
			case r.Host == "sub.reg.test":
				fmt.Fprint(w, `{"tags":["a"]}`)
			case r.Header.Get("Authorization") != bearer:
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
				w.WriteHeader(http.StatusUnauthorized)
			default:
				http.Redirect(w, r, "https://sub.reg.test"+r.URL.Path, http.StatusFound)
			}
		})
		if _, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app", Cred: cred}); err != nil {
			t.Fatal(err)
		}
		got := s.get("sub.reg.test/v2/app/tags/list")
		if len(got) != 1 || got[0] != "" {
			t.Fatalf("subdomain received %q", got)
		}
	})
}

func TestRealmLookalikes(t *testing.T) {
	cred := &registry.Credential{Username: "bot", Token: "ghp_secret"}
	cases := []struct {
		realm, host string
		// sent is "anonymous" (the realm is asked without credentials),
		// "refused" (the realm is not contacted), or "basic".
		sent string
	}{
		{"https://ghcr.io.evil.test/token", "ghcr.io.evil.test", "anonymous"},
		{"https://evilghcr.io/token", "evilghcr.io", "anonymous"},
		{"https://auth.docker.io/token", "auth.docker.io", "anonymous"},
		{"https://ghcr.io:8443/token", "ghcr.io:8443", "refused"},
		{"https://ghcr.io@evil.test/token", "evil.test", "refused"},
		{"https://GHCR.IO/token", "GHCR.IO", "basic"},
	}
	for _, tc := range cases {
		t.Run(tc.realm, func(t *testing.T) {
			f := registrytest.New(t)
			s := &seen{}
			f.Handle(func(w http.ResponseWriter, r *http.Request) {
				s.add(r)
				if r.URL.Path == "/token" {
					fmt.Fprint(w, `{"token":"tok-123"}`)
					return
				}
				if r.Header.Get("Authorization") != bearer {
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+tc.realm+`",service="ghcr.io"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				fmt.Fprint(w, `{"tags":["a"]}`)
			})
			_, sent, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app", Cred: cred})
			got := s.get(tc.host + "/token")
			switch tc.sent {
			case "anonymous":
				if err != nil || sent || len(got) != 1 || got[0] != "" {
					t.Fatalf("err %v sent %v realm got %q", err, sent, got)
				}
			case "basic":
				if err != nil || !sent || len(got) != 1 || got[0] != basic("bot", "ghp_secret") {
					t.Fatalf("err %v sent %v realm got %q", err, sent, got)
				}
			case "refused":
				if code(t, err) != registry.CodeUnreachable || sent || len(got) != 0 {
					t.Fatalf("err %v sent %v realm got %q", err, sent, got)
				}
				for _, d := range f.Dialed() {
					if !strings.HasSuffix(d, ":443") {
						t.Fatalf("dialled %s", d)
					}
				}
				if n := len(f.Dialed()); n != 1 {
					t.Fatalf("dials %v, want only the registry", f.Dialed())
				}
			}
		})
	}
}

func TestPorts(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"tags":["a"]}`) }
	t.Run("registry host port", func(t *testing.T) {
		f := registrytest.New(t)
		f.Handle(ok)
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test:5000", Path: "app"})
		if code(t, err) != registry.CodeUnreachable || len(f.Dialed()) != 0 {
			t.Fatalf("%v dialled %v", err, f.Dialed())
		}
		svc := f.Service()
		if svc.HostAllowed("reg.test:5000", true) || !svc.HostAllowed("reg.test:443", true) || !svc.HostAllowed("reg.test", true) {
			t.Fatal("stored host port rule")
		}
		if svc.HostAllowed("reg.test", false) || !svc.HostAllowed("ghcr.io", false) {
			t.Fatal("public list rule")
		}
		if !registry.NewService(f.Options(true)).HostAllowed("reg.test:5000", true) {
			t.Fatal("allow private keeps the port rule")
		}
	})
	t.Run("redirect port", func(t *testing.T) {
		f := registrytest.New(t)
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://other.test:8443/v2/app/tags/list", http.StatusFound)
		})
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
		if code(t, err) != registry.CodeUnreachable {
			t.Fatalf("%v", err)
		}
		for _, h := range f.Resolved() {
			if h == "other.test" {
				t.Fatal("redirect target was resolved")
			}
		}
	})
	t.Run("next page port", func(t *testing.T) {
		f := registrytest.New(t)
		pagedRegistry(f, 3, func(p int) string {
			return fmt.Sprintf(`<https://reg.test:8443/v2/app/tags/list?last=p%d>; rel="next"`, p)
		})
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test", Path: "app"})
		if code(t, err) != registry.CodeBadResponse || len(f.Dialed()) != 1 {
			t.Fatalf("%v dialled %v", err, f.Dialed())
		}
	})
	t.Run("allow private", func(t *testing.T) {
		f := registrytest.New(t)
		f.Handle(ok)
		f.Resolve("reg.test", "10.0.0.7")
		c := registry.New(f.Options(true))
		if _, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test:5000", Path: "app"}); err != nil {
			t.Fatalf("port 5000: %v", err)
		}
		if d := f.Dialed(); len(d) != 1 || d[0] != "10.0.0.7:5000" {
			t.Fatalf("dialled %v", d)
		}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://reg.test/v2/app/tags/list", http.StatusFound)
		})
		if _, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test:5000", Path: "other"}); code(t, err) != registry.CodeUnreachable {
			t.Fatalf("http redirect: %v", err)
		}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			n := 0
			fmt.Sscanf(r.URL.Query().Get("hop"), "%d", &n)
			http.Redirect(w, r, fmt.Sprintf("/v2/app/tags/list?hop=%d", n+1), http.StatusFound)
		})
		if _, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test:5000", Path: "app"}); code(t, err) != registry.CodeUnreachable {
			t.Fatalf("redirect cap: %v", err)
		}
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		})
		if _, _, err := c.Tags(context.Background(), registry.Repo{Host: "reg.test:5000", Path: "app"}); code(t, err) != registry.CodeBadResponse {
			t.Fatalf("http realm: %v", err)
		}
	})
}

func TestServiceAcquire(t *testing.T) {
	f := registrytest.New(t)
	opts := f.Options(false)
	opts.Concurrency = 2
	svc := registry.NewService(opts)
	r1, ok1 := svc.Acquire()
	r2, ok2 := svc.Acquire()
	if _, ok := svc.Acquire(); !ok1 || !ok2 || ok {
		t.Fatal("cap of 2")
	}
	r1()
	r3, ok := svc.Acquire()
	if !ok {
		t.Fatal("released slot not reusable")
	}
	r2()
	r3()
}

var zonedHosts = []string{"[64:ff9b::a9fe:a9fe%25x]", "[::a00:1%251]", "[2002:7f00:1::%25x]", "[fec0::1%25x]", "[fe80::1%25eth0]"}

func TestZonedRealmRefused(t *testing.T) {
	for _, host := range zonedHosts {
		f := registrytest.New(t)
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+host+`/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		})
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app", Cred: &registry.Credential{Username: "u", Token: "p"}})
		if code(t, err) != registry.CodeUnreachable {
			t.Fatalf("%s: %v", host, err)
		}
		if d := f.Dialed(); len(d) != 1 || d[0] != registrytest.PublicAddr.String()+":443" {
			t.Fatalf("%s: dialled %v", host, d)
		}
	}
}

func TestZonedRedirectRefused(t *testing.T) {
	for _, host := range zonedHosts {
		f := registrytest.New(t)
		f.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://"+host+"/v2/app/tags/list")
			w.WriteHeader(http.StatusFound)
		})
		_, _, err := f.Client().Tags(context.Background(), registry.Repo{Host: "ghcr.io", Path: "o/app"})
		if code(t, err) != registry.CodeUnreachable {
			t.Fatalf("%s: %v", host, err)
		}
		if d := f.Dialed(); len(d) != 1 {
			t.Fatalf("%s: dialled %v", host, d)
		}
	}
}

func TestStoredHostWithExplicitPort443GetsBasic(t *testing.T) {
	f := registrytest.New(t)
	s := &seen{}
	f.Handle(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		switch {
		case r.URL.Path == "/token":
			fmt.Fprint(w, `{"token":"tok-123"}`)
		case r.Header.Get("Authorization") != bearer:
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://reg.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			fmt.Fprint(w, `{"tags":["a"]}`)
		}
	})
	_, sent, err := f.Client().Tags(context.Background(), registry.Repo{Host: "reg.test:443", Path: "app", Cred: &registry.Credential{Username: "u", Token: "p"}})
	if err != nil || !sent {
		t.Fatalf("%v sent %v", err, sent)
	}
	var got []string
	for _, k := range []string{"reg.test/token", "reg.test:443/token"} {
		got = append(got, s.get(k)...)
	}
	if len(got) != 1 || got[0] != basic("u", "p") {
		t.Fatalf("realm received %q", got)
	}
}
