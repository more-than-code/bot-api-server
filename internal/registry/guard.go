// Package registry reads image tags and tag digests from a Distribution v2
// registry (api-v1 v1.16). Every connection goes through an address guard,
// so a registry host, a token realm, a redirect, or a next page cannot reach
// an internal, reserved, or translated address, or a port other than 443.
package registry

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const (
	// maxRedirects is the most redirects one request follows.
	maxRedirects = 3
	httpsPort    = "443"
	headerMax    = 32 << 10
)

var (
	errBlocked  = errors.New("registry: address not allowed")
	errRedirect = errors.New("registry: redirect refused")

	// blockedRanges are refused on top of the netip predicates in Blocked.
	// 240.0.0.0/4 includes the broadcast address.
	blockedRanges = prefixes(
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "168.63.129.16/32",
		"64:ff9b::/96", "64:ff9b:1::/48", "::/96", "2002::/16", "100::/64", "fec0::/10",
	)
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, p := range list {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Resolver looks up the addresses of a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options builds the outbound HTTP client. Zero values are the production
// settings: the system resolver, a real dialer, system roots, guard on.
type Options struct {
	// AllowPrivate lifts the address and port checks (BOT_API_REGISTRY_ALLOW_PRIVATE,
	// dev only). HTTPS, the redirect limit, and the same-host rules still apply.
	AllowPrivate bool
	// Resolver replaces net.DefaultResolver. Tests feed hostile answers here.
	Resolver Resolver
	// Dial replaces the TCP dial to one resolved IP:port. Tests use it to
	// reach an httptest server while the guard checks the resolved address.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS replaces the default TLS settings (tests supply their own roots).
	TLS *tls.Config
	// Concurrency is the most lookups at once; 0 means 32.
	Concurrency int
}

// Blocked reports whether addr is refused by the guard. A zoned address is
// always refused (netip.Prefix.Contains never matches one, and a registry
// address never carries a zone). IPv4-mapped IPv6 forms are unmapped first.
func Blocked(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return true
	}
	addr = addr.WithZone("").Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range blockedRanges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// urlAllowed is the rule for every URL the client requests: HTTPS, no
// userinfo, no IPv6 zone, and port 443 unless allowPrivate.
func urlAllowed(u *url.URL, allowPrivate bool) bool {
	if u.Scheme != "https" || u.User != nil || u.Hostname() == "" || strings.Contains(u.Hostname(), "%") {
		return false
	}
	port := u.Port()
	return allowPrivate || port == "" || port == httpsPort
}

func newHTTPClient(opts Options) *http.Client {
	g := &guard{allowPrivate: opts.AllowPrivate, resolver: opts.Resolver, dial: opts.Dial}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	if g.dial == nil {
		g.dial = g.dialer().DialContext
	}
	tlsConf := opts.TLS
	if tlsConf == nil {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            g.dialContext,
		TLSClientConfig:        tlsConf,
		TLSHandshakeTimeout:    requestTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		MaxResponseHeaderBytes: headerMax,
		MaxIdleConns:           16,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects || !urlAllowed(req.URL, opts.AllowPrivate) {
			return errRedirect
		}
		// Go keeps Authorization on a redirect to a subdomain; drop it on any host change.
		if req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}}
}

type guard struct {
	allowPrivate bool
	resolver     Resolver
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
}

// dialer is the production TCP dialer.
func (g *guard) dialer() *net.Dialer {
	// Control sees the socket address the kernel connects to, so a future
	// change to dialContext cannot skip the address check.
	return &net.Dialer{Timeout: requestTimeout, Control: g.control}
}

// dialContext resolves host, refuses blocked addresses and ports, and dials
// allowed addresses by IP in order, so the checked address is the one connected.
func (g *guard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !g.allowPrivate && port != httpsPort {
		return nil, errBlocked
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = g.resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	lastErr := errBlocked
	for _, ip := range addrs {
		if !g.allowPrivate && Blocked(ip) {
			continue
		}
		conn, err := g.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (g *guard) control(_, address string, _ syscall.RawConn) error {
	if g.allowPrivate {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || Blocked(ap.Addr()) || ap.Port() != 443 {
		return errBlocked
	}
	return nil
}
