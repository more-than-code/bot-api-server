package ingest

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// Agent-protocol v1.0.3. URL userinfo runs first, then keywords.
// Both patterns are RE2 (Go regexp).
const (
	urlUserinfoPattern = `(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]*:)[^\s/]*@`
	keywordPattern     = `(?i)([A-Za-z0-9_.-]*(?:authorization|api[_-]?key|password|passwd|token|secret|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*|\s+)(bearer\s+)?("[^"]*"|'[^']*'|\S+)`
)

var (
	cmdlineURLUserinfo = regexp.MustCompile(urlUserinfoPattern)
	cmdlineKeyword     = regexp.MustCompile(keywordPattern)
)

// RedactCmdline replaces URL userinfo, then secret assignments. The keyword is kept.
func RedactCmdline(s string) string {
	s = cmdlineURLUserinfo.ReplaceAllString(s, "$1[REDACTED]@")
	return cmdlineKeyword.ReplaceAllString(s, "$1=[REDACTED]")
}

// RedactPayload rewrites every JSON string whose key is "cmdline".
// Numbers stay numbers. A payload that is not JSON is returned unchanged.
func RedactPayload(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return append(json.RawMessage(nil), raw...)
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return append(json.RawMessage(nil), raw...)
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if k == "cmdline" {
				if s, ok := child.(string); ok {
					t[k] = RedactCmdline(s)
					continue
				}
			}
			t[k] = redactValue(child)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
		return t
	default:
		return v
	}
}
