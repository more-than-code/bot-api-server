package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, "", err)
		return
	}
	q := r.URL.Query()
	m := q.Get("m")
	from, to, ok := s.timeRange(w, r, time.Hour)
	if !ok {
		return
	}
	step := 0
	if raw := q.Get("step"); raw != "" {
		n, err := parseStep(raw)
		if err != nil {
			writeCode(w, "bad_request", "invalid step")
			return
		}
		step = n
	}
	step, err := ingest.ChooseStep(from, to, step)
	if err != nil {
		writeCode(w, "bad_request", "invalid range")
		return
	}
	series, err := s.Store.QueryChart(r.Context(), host.ID, m, from, to, step)
	if errors.Is(err, store.ErrUnknownMeasurement) {
		writeCode(w, "bad_request", "invalid m")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]seriesJSON, len(series))
	for i, ser := range series {
		points := make([]pointJSON, len(ser.Points))
		for j, p := range ser.Points {
			points[j] = pointJSON{T: p.T, V: p.V}
		}
		out[i] = seriesJSON{Name: ser.Name, Unit: ser.Unit, Points: points}
	}
	writeOK(w, http.StatusOK, map[string]any{
		"m": m, "from": from, "to": to, "step": step, "series": out,
	})
}

type seriesJSON struct {
	Name   string      `json:"name"`
	Unit   string      `json:"unit"`
	Points []pointJSON `json:"points"`
}

type pointJSON struct {
	T time.Time
	V *float64
}

func (p pointJSON) MarshalJSON() ([]byte, error) {
	ts, err := json.Marshal(p.T.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	if p.V == nil {
		return []byte(fmt.Sprintf("[%s,null]", ts)), nil
	}
	num, err := json.Marshal(*p.V)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("[%s,%s]", ts, num)), nil
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, "", err)
		return
	}
	sortKey := r.URL.Query().Get("sort")
	if sortKey == "" {
		sortKey = "cpu"
	}
	if sortKey != "cpu" && sortKey != "memory" {
		writeCode(w, "bad_request", "invalid sort")
		return
	}
	limit, ok := s.limit(w, r)
	if !ok {
		return
	}
	if limit > 200 {
		limit = 200
	}
	sampled, items, err := s.Store.LatestProcesses(r.Context(), host.ID, s.now().Add(-90*time.Second), sortKey, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []store.ProcessItem{}
	}
	writeOK(w, http.StatusOK, map[string]any{
		"sampled_at": sampled,
		"items":      items,
	})
}

func (s *Server) handleHealthHistory(w http.ResponseWriter, r *http.Request) {
	p, svc, host, ok := s.fetchService(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), idPtr(svc.ID), "", err)
		return
	}
	from, to, ok := s.timeRange(w, r, 24*time.Hour)
	if !ok {
		return
	}
	if to.Sub(from) > ingest.MaxSpan {
		writeCode(w, "bad_request", "invalid range")
		return
	}
	items, err := s.Store.HealthHistory(r.Context(), svc.ID, from, to, 1000)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapAuditRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	limit, ok := s.limit(w, r)
	if !ok {
		return
	}
	cur, ok := s.cursor(w, r)
	if !ok {
		return
	}
	items, next, err := s.Store.ListAudit(r.Context(), id, limit, cur)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeList(w, items, next)
}

func (s *Server) timeRange(w http.ResponseWriter, r *http.Request, def time.Duration) (time.Time, time.Time, bool) {
	q := r.URL.Query()
	rawFrom, rawTo := q.Get("from"), q.Get("to")
	now := s.now()
	var from, to time.Time
	switch {
	case rawFrom == "" && rawTo == "":
		return now.Add(-def), now, true
	case rawTo == "":
		parsed, ok := parseTime(rawFrom)
		if !ok {
			writeCode(w, "bad_request", "invalid range")
			return time.Time{}, time.Time{}, false
		}
		from, to = parsed, now
	case rawFrom == "":
		parsed, ok := parseTime(rawTo)
		if !ok {
			writeCode(w, "bad_request", "invalid range")
			return time.Time{}, time.Time{}, false
		}
		from, to = parsed.Add(-time.Hour), parsed
	default:
		parsedFrom, ok := parseTime(rawFrom)
		if !ok {
			writeCode(w, "bad_request", "invalid range")
			return time.Time{}, time.Time{}, false
		}
		parsedTo, ok := parseTime(rawTo)
		if !ok {
			writeCode(w, "bad_request", "invalid range")
			return time.Time{}, time.Time{}, false
		}
		from, to = parsedFrom, parsedTo
	}
	if !to.After(from) {
		writeCode(w, "bad_request", "invalid range")
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

func parseStep(raw string) (int, error) {
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' || n > 100000 {
			return 0, errors.New("bad step")
		}
		n = n*10 + int(c-'0')
	}
	if raw == "" {
		return 0, errors.New("bad step")
	}
	return n, nil
}
