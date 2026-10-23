package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type envelope struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	Payload any    `json:"payload"`
}

func phrase(code string) string {
	switch code {
	case "not_found":
		return "not found"
	case "bad_request":
		return "bad request"
	case "authorization_pending":
		return "authorization pending"
	case "slow_down":
		return "slow down"
	case "expired_token":
		return "expired token"
	case "access_denied":
		return "access denied"
	case "unavailable":
		return "host unavailable"
	case "timeout":
		return "timed out"
	case "error":
		return "internal error"
	case "invalid_token":
		return "invalid token"
	case "rate_limited":
		return "rate limited"
	case "not_implemented":
		return "not implemented"
	case "registry_unavailable":
		return "registry unavailable"
	default:
		return code
	}
}

func statusFor(code string) int {
	switch code {
	case "ok":
		return http.StatusOK
	case "bad_request", "authorization_pending", "slow_down", "expired_token", "access_denied":
		return http.StatusBadRequest
	case "unauthorized", "invalid_token":
		return http.StatusUnauthorized
	case "rate_limited":
		return http.StatusTooManyRequests
	case "forbidden":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "conflict":
		return http.StatusConflict
	case "unavailable":
		return http.StatusServiceUnavailable
	case "timeout":
		return http.StatusGatewayTimeout
	case "not_implemented":
		return http.StatusNotImplemented
	case "registry_unavailable":
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func write(w http.ResponseWriter, status int, code, msg string, payload any) {
	if msg == "" {
		msg = phrase(code)
	}
	raw, err := json.Marshal(envelope{Code: code, Msg: msg, Payload: payload})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, []byte(`{"code":"error","msg":"internal error","payload":null}`))
		return
	}
	writeJSON(w, status, raw)
}

func writeOK(w http.ResponseWriter, status int, payload any) {
	write(w, status, "ok", "ok", payload)
}

func writeCode(w http.ResponseWriter, code, msg string) {
	write(w, statusFor(code), code, msg, nil)
}

func writeList(w http.ResponseWriter, items any, next *store.Cursor) {
	writeOK(w, http.StatusOK, map[string]any{
		"items":       nonNilSlice(items),
		"next_cursor": encodeCursor(next),
	})
}

func nonNilSlice(items any) any {
	v := reflect.ValueOf(items)
	if !v.IsValid() || (v.Kind() == reflect.Slice && v.IsNil()) {
		return []any{}
	}
	return items
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeCode(w, "bad_request", "invalid json")
		return false
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		writeCode(w, "bad_request", "invalid json")
		return false
	}
	return true
}

type cursorWire struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

type hostCursorWire struct {
	RelRank *int   `json:"rel_rank"`
	Name    string `json:"name"`
	ID      string `json:"id"`
}

func encodeCursor(c *store.Cursor) *string {
	if c == nil {
		return nil
	}
	var raw []byte
	var err error
	if c.Rank != nil {
		rank := *c.Rank
		raw, err = json.Marshal(hostCursorWire{RelRank: &rank, Name: c.Name, ID: c.ID})
	} else {
		raw, err = json.Marshal(cursorWire{T: c.At.UTC(), ID: c.ID})
	}
	if err != nil {
		return nil
	}
	s := base64.RawURLEncoding.EncodeToString(raw)
	return &s
}

func decodeCursor(s string) (*store.Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var w cursorWire
	if err := json.Unmarshal(raw, &w); err != nil || w.ID == "" || w.T.IsZero() {
		return nil, errBadCursor
	}
	return &store.Cursor{At: w.T.UTC(), ID: w.ID}, nil
}

func (s *Server) limit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 200 {
		writeCode(w, "bad_request", "invalid limit")
		return 0, false
	}
	return n, true
}

func decodeHostCursor(s string) (*store.Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errBadCursor
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w hostCursorWire
	if err := dec.Decode(&w); err != nil || dec.More() {
		return nil, errBadCursor
	}
	if w.RelRank == nil || (*w.RelRank != 0 && *w.RelRank != 1) || w.Name == "" || w.ID == "" {
		return nil, errBadCursor
	}
	if _, err := uuid.Parse(w.ID); err != nil {
		return nil, errBadCursor
	}
	rank := *w.RelRank
	return &store.Cursor{Rank: &rank, Name: w.Name, ID: w.ID}, nil
}

func (s *Server) cursor(w http.ResponseWriter, r *http.Request) (*store.Cursor, bool) {
	return s.readCursor(w, r, decodeCursor)
}

func (s *Server) hostCursor(w http.ResponseWriter, r *http.Request) (*store.Cursor, bool) {
	return s.readCursor(w, r, decodeHostCursor)
}

func (s *Server) readCursor(w http.ResponseWriter, r *http.Request, decode func(string) (*store.Cursor, error)) (*store.Cursor, bool) {
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		return nil, true
	}
	c, err := decode(raw)
	if err != nil {
		writeCode(w, "bad_request", "invalid cursor")
		return nil, false
	}
	return c, true
}

func parseTime(raw string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}
