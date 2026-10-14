package api

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleServiceList(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	rel, ok := s.gateHost(w, r, p, host, authz.CapHostServices, nil, nil, "")
	if !ok {
		return
	}
	items, err := s.Store.ListServices(r.Context(), host.ID, authz.ServiceProjectFilter(rel), s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeList(w, items, nil)
}

func (s *Server) handleServiceGet(w http.ResponseWriter, r *http.Request) {
	p, svc, host, ok := s.fetchService(w, r)
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapServiceRead, &svc.ProjectID, idPtr(svc.ID), ""); !ok {
		return
	}
	checks, err := s.Store.ListHealthChecks(r.Context(), svc.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if checks == nil {
		checks = []store.HealthCheck{}
	}
	writeOK(w, http.StatusOK, struct {
		store.Service
		HealthChecks []store.HealthCheck `json:"health_checks"`
	}{Service: svc, HealthChecks: checks})
}

func (s *Server) handleHealthPut(w http.ResponseWriter, r *http.Request) {
	p, svc, host, ok := s.fetchService(w, r)
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapServiceWrite, &svc.ProjectID, idPtr(svc.ID), audit.ActionHealthChecks); !ok {
		return
	}
	var body struct {
		Checks *[]checkIn `json:"checks"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Checks == nil {
		writeCode(w, "bad_request", "invalid json")
		return
	}
	if len(*body.Checks) > 10 {
		writeCode(w, "bad_request", "too many checks")
		return
	}
	inputs := make([]store.HealthCheckInput, 0, len(*body.Checks))
	for _, in := range *body.Checks {
		item, msg := normalizeCheck(in, svc.Ports)
		if msg != "" {
			writeCode(w, "bad_request", msg)
			return
		}
		inputs = append(inputs, item)
	}
	checks, err := s.Store.ReplaceHealthChecks(r.Context(), svc.ID, inputs)
	if err != nil {
		s.fail(w, err)
		return
	}
	if s.Hub != nil {
		s.Hub.PushConfig(r.Context(), host.ID)
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		ServiceID: idPtr(svc.ID),
		Action:    audit.ActionHealthChecks,
		Detail:    map[string]any{"count": len(checks)},
	})
	if checks == nil {
		checks = []store.HealthCheck{}
	}
	writeOK(w, http.StatusOK, map[string]any{"checks": checks})
}

func (s *Server) fetchService(w http.ResponseWriter, r *http.Request) (principal, store.Service, store.Host, bool) {
	p, ok := s.require(w, r)
	if !ok {
		return principal{}, store.Service{}, store.Host{}, false
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return principal{}, store.Service{}, store.Host{}, false
	}
	svc, err := s.Store.GetService(r.Context(), id, s.now())
	if err != nil {
		s.fail(w, err)
		return principal{}, store.Service{}, store.Host{}, false
	}
	host, err := s.Store.GetHost(r.Context(), svc.HostID)
	if err != nil {
		s.fail(w, err)
		return principal{}, store.Service{}, store.Host{}, false
	}
	return p, svc, host, true
}

type checkIn struct {
	Protocol  *string `json:"protocol"`
	Port      *int    `json:"port"`
	Path      *string `json:"path"`
	Interval  *int    `json:"interval_sec"`
	ExpectMin *int    `json:"expect_status_min"`
	ExpectMax *int    `json:"expect_status_max"`
	Enabled   *bool   `json:"enabled"`
}

func normalizeCheck(in checkIn, ports []int) (store.HealthCheckInput, string) {
	if in.Protocol == nil || (*in.Protocol != "http" && *in.Protocol != "tcp") {
		return store.HealthCheckInput{}, "invalid protocol"
	}
	if in.Port == nil || *in.Port < 1 || *in.Port > 65535 {
		return store.HealthCheckInput{}, "invalid port"
	}
	if !portOpen(ports, *in.Port) {
		return store.HealthCheckInput{}, "port is not open on the service"
	}
	var path *string
	if *in.Protocol == "http" {
		if in.Path == nil || !validHTTPPath(*in.Path) {
			return store.HealthCheckInput{}, "invalid path"
		}
		p := *in.Path
		path = &p
	} else if in.Path != nil && *in.Path != "" {
		return store.HealthCheckInput{}, "invalid path"
	}
	interval := 60
	if in.Interval != nil {
		interval = *in.Interval
	}
	if interval < 30 || interval > 300 {
		return store.HealthCheckInput{}, "invalid interval_sec"
	}
	min := 200
	max := 399
	if in.ExpectMin != nil {
		min = *in.ExpectMin
	}
	if in.ExpectMax != nil {
		max = *in.ExpectMax
	}
	if min < 200 || max > 399 || min > max {
		return store.HealthCheckInput{}, "invalid expect status"
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return store.HealthCheckInput{
		Protocol:        *in.Protocol,
		Port:            *in.Port,
		Path:            path,
		IntervalSec:     interval,
		ExpectStatusMin: min,
		ExpectStatusMax: max,
		Enabled:         enabled,
	}, ""
}

func validHTTPPath(p string) bool {
	if p == "" || len(p) > 512 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '@' || r == '\\' || r == '?' || r == '#' || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func portOpen(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
