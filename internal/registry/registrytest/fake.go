// Package registrytest is a fake network for registry tests: one TLS server
// that answers for every test host name, a stub resolver, and a dial hook
// that records which resolved address was dialled. No live network.
package registrytest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/registry"
)

// Hosts are the names the server certificate covers.
var Hosts = []string{
	"ghcr.io", "registry-1.docker.io", "auth.docker.io", "docker.io", "quay.io",
	"evil.test", "reg.test", "sub.reg.test", "other.test", "internal.test", "meta.test",
	"ghcr.io.evil.test", "evilghcr.io",
}

// PublicAddr is what an unlisted host resolves to. It passes the guard.
// It is only ever returned by the stub resolver; nothing dials it.
var PublicAddr = netip.MustParseAddr("93.184.216.10")

// Fake routes every allowed dial to one TLS server.
type Fake struct {
	Server *httptest.Server

	mu       sync.Mutex
	handler  http.Handler
	resolve  map[string][]netip.Addr
	dialed   []string
	resolved []string
	failDial map[string]bool
	roots    *x509.CertPool
}

// New starts the fake. It is closed when the test ends.
func New(t *testing.T) *Fake {
	t.Helper()
	f := &Fake{resolve: map[string][]netip.Addr{}, failDial: map[string]bool{}}
	cert, pool := selfSigned(t)
	f.roots = pool
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		h := f.handler
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	f.Server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	return f
}

// Handle sets the handler. It sees the requested host in r.Host.
func (f *Fake) Handle(h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
}

// Resolve makes host resolve to addrs.
func (f *Fake) Resolve(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		list[i] = netip.MustParseAddr(a)
	}
	f.resolve[host] = list
}

// Dialed returns the addresses dialled so far (ip:port).
func (f *Fake) Dialed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

// Resolved returns the host names looked up so far.
func (f *Fake) Resolved() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.resolved...)
}

// LookupNetIP implements registry.Resolver.
func (f *Fake) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, host)
	if addrs, ok := f.resolve[host]; ok {
		return addrs, nil
	}
	return []netip.Addr{PublicAddr}, nil
}

// FailDial makes a dial to addr (ip:port) fail with a connection error.
func (f *Fake) FailDial(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDial[addr] = true
}

func (f *Fake) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	fails := f.failDial[addr]
	f.mu.Unlock()
	if fails {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.Server.Listener.Addr().String())
}

// Options returns guard options wired to the fake network.
func (f *Fake) Options(allowPrivate bool) registry.Options {
	return registry.Options{
		AllowPrivate: allowPrivate,
		Resolver:     f,
		Dial:         f.dial,
		TLS:          &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12},
	}
}

// Client returns a registry client on the fake network with the guard on.
func (f *Fake) Client() *registry.Client {
	return registry.New(f.Options(false))
}

// Service returns a lookup service on the fake network with the guard on.
func (f *Fake) Service() *registry.Service {
	return registry.NewService(f.Options(false))
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "registrytest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              Hosts,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
