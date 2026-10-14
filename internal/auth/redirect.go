package auth

import (
	"net/url"
	"strings"
	"unicode"
)

// invalidAuthorizationPage is the fixed HTML text for an authorization
// request that must not be redirected.
const invalidAuthorizationPage = "invalid authorization request"

func validateRedirectURI(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return ErrRedirect
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || r == '*' || r == '\\' || r == '#' || r == '\x00' {
			return ErrRedirect
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return ErrRedirect
	}
	if u.User != nil || u.Fragment != "" {
		return ErrRedirect
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !loopbackHost(u.Hostname()) {
			return ErrRedirect
		}
		return nil
	default:
		return ErrRedirect
	}
}

func loopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

// redirectMatches reports whether presented is the registered URI.
// Loopback http ignores the port. https compares the explicit port.
func redirectMatches(registered, presented string) bool {
	a, errA := url.Parse(registered)
	b, errB := url.Parse(presented)
	if errA != nil || errB != nil || a.Scheme != b.Scheme {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	if requestPath(a) != requestPath(b) || a.RawQuery != b.RawQuery {
		return false
	}
	if a.Scheme == "http" && loopbackHost(a.Hostname()) {
		return true
	}
	return a.Port() == b.Port()
}

func redirectMatchesAny(registered []string, presented string) bool {
	for _, uri := range registered {
		if redirectMatches(uri, presented) {
			return true
		}
	}
	return false
}

func requestPath(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	return u.EscapedPath()
}

// redirectHost is the host the consent screen shows, including a port.
func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func errorRedirect(raw, code, desc, state string, hasState bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ErrRedirect
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if hasState {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func codeRedirect(raw, code, state string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ErrRedirect
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}
