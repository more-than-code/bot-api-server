package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/more-than-code/bot-api-server/internal/catalog"
)

// Reasons returned in the 502 payload (api-v1 v1.16).
const (
	// CodeAuthFailed is a stored credential that was sent and refused.
	CodeAuthFailed = "auth_failed"
	// CodeNotFound is a 404, or a 401/403 when no stored credential was sent.
	CodeNotFound = "not_found"
	CodeTimeout  = "timeout"
	// CodeUnreachable is DNS, connect, TLS, an address or port refusal, or a
	// registry answering 429 or 5xx.
	CodeUnreachable = "unreachable"
	// CodeBadResponse is a malformed answer or an invalid digest.
	CodeBadResponse = "bad_response"
)

const (
	requestTimeout = 5 * time.Second
	lookupTimeout  = 12 * time.Second
	tagsBodyMax    = 1 << 20
	manifestMax    = 4 << 20
	maxPages       = 5
	maxRawTags     = 500
	dockerHub      = "docker.io"
	dockerHubAPI   = "registry-1.docker.io"
	dockerHubAuth  = "auth.docker.io"
)

// manifestAccept lists the OCI index, the Docker manifest list v2, the OCI
// manifest, and the Docker manifest v2.
const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// Error is a lookup failure. Error() is only the reason: it never carries a
// registry body, a URL, or a token.
type Error struct {
	Code string
}

func (e *Error) Error() string { return "registry: " + e.Code }

func fail(code string) error { return &Error{Code: code} }

// Credential is a stored registry login.
type Credential struct {
	Username string
	Token    string
}

// Repo names one repository. Host is the normalised image host (docker.io
// explicit) and Path includes library/ for single-name Hub images.
type Repo struct {
	Host string
	Path string
	// Cred is nil for an anonymous lookup.
	Cred *Credential
}

// TagList is the raw, unsorted tag list read from the registry.
type TagList struct {
	Tags []string
	// More is true when a next page or more than 500 tags were left unread.
	More bool
}

// Client speaks the Distribution v2 tags and manifest calls.
//
// Basic credentials go only to a token realm whose host and port equal the
// registry's, or to auth.docker.io for docker.io. Any other realm gets an
// anonymous token request. The bool each lookup returns says whether the
// stored credential was sent.
type Client struct {
	http           *http.Client
	allowPrivate   bool
	requestTimeout time.Duration
	lookupTimeout  time.Duration
}

// New returns a client with the production timeouts.
func New(opts Options) *Client {
	return &Client{
		http:           newHTTPClient(opts),
		allowPrivate:   opts.AllowPrivate,
		requestTimeout: requestTimeout,
		lookupTimeout:  lookupTimeout,
	}
}

func endpoint(host string) string {
	if host == dockerHub {
		return dockerHubAPI
	}
	return host
}

// session is one lookup: the repository, its URL host, and the
// Authorization value once a challenge has been answered.
type session struct {
	c        *Client
	repo     Repo
	api      string
	auth     string
	credUsed bool
}

func (c *Client) session(repo Repo) *session {
	return &session{c: c, repo: repo, api: endpoint(repo.Host)}
}

// Tags reads up to five pages and 500 tags. Next pages must stay on the
// registry host.
func (c *Client) Tags(ctx context.Context, repo Repo) (TagList, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.lookupTimeout)
	defer cancel()
	s := c.session(repo)
	next := &url.URL{Scheme: "https", Host: s.api, Path: "/v2/" + repo.Path + "/tags/list", RawQuery: "n=100"}
	var out TagList
	for page := 0; next != nil; page++ {
		if page == maxPages || len(out.Tags) >= maxRawTags {
			out.More = true
			break
		}
		res, err := s.do(ctx, http.MethodGet, next, "application/json", tagsBodyMax)
		if err != nil {
			return TagList{}, s.credUsed, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(res.body, &body); err != nil {
			return TagList{}, s.credUsed, fail(CodeBadResponse)
		}
		out.Tags = append(out.Tags, body.Tags...)
		if len(out.Tags) > maxRawTags {
			out.Tags = out.Tags[:maxRawTags]
			out.More = true
			break
		}
		if next, err = s.nextPage(next, res.header.Get("Link")); err != nil {
			return TagList{}, s.credUsed, err
		}
	}
	return out, s.credUsed, nil
}

// Digest returns the manifest digest of tag. HEAD reads Docker-Content-Digest;
// without it a GET (body at most 4 MiB) is hashed with sha256.
func (c *Client) Digest(ctx context.Context, repo Repo, tag string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.lookupTimeout)
	defer cancel()
	s := c.session(repo)
	u := &url.URL{Scheme: "https", Host: s.api, Path: "/v2/" + repo.Path + "/manifests/" + tag}
	res, err := s.do(ctx, http.MethodHead, u, manifestAccept, 0)
	if err != nil {
		return "", s.credUsed, err
	}
	digest := res.header.Get("Docker-Content-Digest")
	if digest == "" {
		if res, err = s.do(ctx, http.MethodGet, u, manifestAccept, manifestMax); err != nil {
			return "", s.credUsed, err
		}
		sum := sha256.Sum256(res.body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	if !catalog.ValidDigest(digest) {
		return "", s.credUsed, fail(CodeBadResponse)
	}
	return digest, s.credUsed, nil
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends one registry request. A 401 runs the challenge once and retries.
func (s *session) do(ctx context.Context, method string, u *url.URL, accept string, max int64) (response, error) {
	if !urlAllowed(u, s.c.allowPrivate) {
		return response{}, fail(CodeUnreachable)
	}
	res, err := s.send(ctx, method, u.String(), accept, max, s.auth)
	if err != nil {
		return response{}, err
	}
	if res.status == http.StatusUnauthorized && s.auth == "" {
		if err := s.authorize(ctx, res.header.Get("WWW-Authenticate")); err != nil {
			return response{}, err
		}
		if res, err = s.send(ctx, method, u.String(), accept, max, s.auth); err != nil {
			return response{}, err
		}
	}
	if res.status >= 200 && res.status < 300 {
		return res, nil
	}
	return response{}, s.statusErr(res.status)
}

// statusErr maps a non-2xx answer from the registry or the realm.
func (s *session) statusErr(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		// Without a sent credential the image is missing or private; Docker
		// Hub answers a missing repository this way.
		if s.credUsed {
			return fail(CodeAuthFailed)
		}
		return fail(CodeNotFound)
	case status == http.StatusNotFound:
		return fail(CodeNotFound)
	case status == http.StatusTooManyRequests || status >= 500:
		return fail(CodeUnreachable)
	default:
		return fail(CodeBadResponse)
	}
}

// send performs one exchange inside the per-request budget. A 2xx body is
// read up to max bytes; a longer body is bad_response.
func (s *session) send(ctx context.Context, method, u, accept string, max int64, auth string) (response, error) {
	ctx, cancel := context.WithTimeout(ctx, s.c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return response{}, fail(CodeBadResponse)
	}
	req.Header.Set("Accept", accept)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := s.c.http.Do(req)
	if err != nil {
		return response{}, netErr(err)
	}
	defer res.Body.Close()
	out := response{status: res.StatusCode, header: res.Header}
	if max > 0 && res.StatusCode >= 200 && res.StatusCode < 300 {
		if out.body, err = io.ReadAll(io.LimitReader(res.Body, max+1)); err != nil {
			return response{}, netErr(err)
		}
		if int64(len(out.body)) > max {
			return response{}, fail(CodeBadResponse)
		}
	}
	return out, nil
}

// netErr maps a transport failure: a deadline is timeout, anything else
// (DNS, connect, TLS, a refused address, port, or redirect) is unreachable.
func netErr(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fail(CodeTimeout)
	}
	return fail(CodeUnreachable)
}

// authorize answers a 401 challenge. Bearer runs the token flow. A plain
// Basic challenge comes from the registry host itself and gets the stored
// credential.
func (s *session) authorize(ctx context.Context, challenge string) error {
	scheme, params := parseChallenge(challenge)
	switch scheme {
	case "basic":
		if s.repo.Cred == nil {
			return fail(CodeNotFound)
		}
		s.auth = basicHeader(*s.repo.Cred)
		s.credUsed = true
		return nil
	case "bearer":
	default:
		return s.statusErr(http.StatusUnauthorized)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil {
		return fail(CodeBadResponse)
	}
	if realm.Scheme != "https" {
		return fail(CodeBadResponse)
	}
	if !urlAllowed(realm, s.c.allowPrivate) {
		return fail(CodeUnreachable)
	}
	q := realm.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	q.Set("scope", "repository:"+s.repo.Path+":pull")
	realm.RawQuery = q.Encode()
	auth := ""
	if s.repo.Cred != nil && s.realmTrusted(realm) {
		auth = basicHeader(*s.repo.Cred)
		s.credUsed = true
	}
	res, err := s.send(ctx, http.MethodGet, realm.String(), "application/json", tagsBodyMax, auth)
	if err != nil {
		return err
	}
	if res.status < 200 || res.status >= 300 {
		return s.statusErr(res.status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(res.body, &tok); err != nil {
		return fail(CodeBadResponse)
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" || strings.ContainsAny(t, "\r\n\x00 ") {
		return fail(CodeBadResponse)
	}
	s.auth = "Bearer " + t
	return nil
}

// realmTrusted reports whether the stored credential may be sent to realm:
// the same host and port as the registry, or auth.docker.io for docker.io.
func (s *session) realmTrusted(realm *url.URL) bool {
	host := hostKey(realm.Host)
	return host == hostKey(s.api) || (s.repo.Host == dockerHub && host == dockerHubAuth)
}

// hostKey lowercases host[:port] and drops an explicit :443.
func hostKey(hostport string) string {
	return strings.TrimSuffix(strings.ToLower(hostport), ":"+httpsPort)
}

func basicHeader(c Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Token))
}

// parseChallenge returns the lowercased scheme and the key="value" pairs.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(rest, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	return strings.ToLower(scheme), params
}

// nextPage reads Link: <…>; rel="next". It returns nil when there is no next
// page. A next page on another host, scheme, or port is refused.
func (s *session) nextPage(cur *url.URL, link string) (*url.URL, error) {
	for _, part := range strings.Split(link, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok || !strings.Contains(strings.ReplaceAll(params, " ", ""), `rel="next"`) {
			continue
		}
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			return nil, fail(CodeBadResponse)
		}
		ref, err := url.Parse(target[1 : len(target)-1])
		if err != nil {
			return nil, fail(CodeBadResponse)
		}
		next := cur.ResolveReference(ref)
		if !strings.EqualFold(next.Host, cur.Host) || !urlAllowed(next, s.c.allowPrivate) {
			return nil, fail(CodeBadResponse)
		}
		return next, nil
	}
	return nil, nil
}
