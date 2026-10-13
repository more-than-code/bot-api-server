package api

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.8:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 198.51.100.10")
	if got := s.clientIP(req); got != "203.0.113.8" {
		t.Fatalf("untrusted %q", got)
	}
	s.TrustedProxy = "203.0.113.8"
	if got := s.clientIP(req); got != "198.51.100.10" {
		t.Fatalf("trusted rightmost %q", got)
	}
	s.TrustedProxy = "198.51.100.1"
	if got := s.clientIP(req); got != "203.0.113.8" {
		t.Fatalf("other proxy %q", got)
	}
	s.TrustedProxy = "203.0.113.8"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := s.clientIP(req); got != "203.0.113.8" {
		t.Fatalf("bad forwarded %q", got)
	}
}
