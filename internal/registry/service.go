package registry

import (
	"net"
	"time"
)

// Lookup limits (api-v1 v1.16).
const (
	cacheTTL      = 60 * time.Second
	cacheMax      = 1024
	userLimit     = 20
	userWindow    = time.Minute
	maxConcurrent = 32
)

// publicHosts may be looked up without a stored registry.
var publicHosts = map[string]bool{
	"docker.io":           true,
	"ghcr.io":             true,
	"quay.io":             true,
	"gcr.io":              true,
	"registry.gitlab.com": true,
	"public.ecr.aws":      true,
	"mcr.microsoft.com":   true,
}

// Service is the API's lookup state: the guarded client, the per-user
// limiter, the result cache, and the global concurrency cap.
type Service struct {
	Client  *Client
	Limiter *Limiter
	Cache   *Cache

	sem          chan struct{}
	allowPrivate bool
}

// NewService builds the production service from opts.
func NewService(opts Options) *Service {
	n := opts.Concurrency
	if n <= 0 {
		n = maxConcurrent
	}
	return &Service{
		Client:       New(opts),
		Limiter:      NewLimiter(userLimit, userWindow),
		Cache:        NewCache(cacheTTL, cacheMax),
		sem:          make(chan struct{}, n),
		allowPrivate: opts.AllowPrivate,
	}
}

// HostAllowed reports whether host may be looked up: a stored host or a
// public one, and port 443 unless the service allows private targets.
func (s *Service) HostAllowed(host string, stored bool) bool {
	if !stored && !publicHosts[host] {
		return false
	}
	if _, port, err := net.SplitHostPort(host); err == nil && port != httpsPort && !s.allowPrivate {
		return false
	}
	return true
}

// Acquire takes one of the concurrent lookup slots without waiting.
// The caller runs release when ok.
func (s *Service) Acquire() (release func(), ok bool) {
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, true
	default:
		return nil, false
	}
}
