package db

import (
	"strings"
	"testing"
)

func TestLikeContains(t *testing.T) {
	if got := likeContains("plain"); got != "%plain%" {
		t.Fatalf("plain %q", got)
	}
	if got := likeContains("100%"); got != `%100\%%` {
		t.Fatalf("percent %q", got)
	}
	if got := likeContains("a_b"); got != `%a\_b%` {
		t.Fatalf("underscore %q", got)
	}
	if got := likeContains(`a\b`); got != `%a\\b%` {
		t.Fatalf("backslash %q", got)
	}
}

func TestProjectServiceOrder(t *testing.T) {
	cases := []struct {
		sort, dir, want string
	}{
		{"name", "asc", `lower(coalesce(s.display_name, s.name)) COLLATE "C" ASC NULLS LAST, s.id ASC`},
		{"name", "desc", `lower(coalesce(s.display_name, s.name)) COLLATE "C" DESC NULLS LAST, s.id ASC`},
		{"host", "asc", `h.name COLLATE "C" ASC NULLS LAST, s.id ASC`},
		{"host", "desc", `h.name COLLATE "C" DESC NULLS LAST, s.id ASC`},
		{"kind", "desc", `s.kind COLLATE "C" DESC NULLS LAST, s.id ASC`},
		{"last_seen", "asc", "s.last_seen_at ASC NULLS LAST, s.id ASC"},
		{"last_seen", "desc", "s.last_seen_at DESC NULLS LAST, s.id ASC"},
		{"status", "asc", `(s.gone_at IS NOT NULL) ASC, health_rank ASC NULLS LAST, lower(coalesce(s.display_name, s.name)) COLLATE "C" ASC NULLS LAST, s.id ASC`},
		{"status", "desc", `(s.gone_at IS NOT NULL) ASC, health_rank DESC NULLS LAST, lower(coalesce(s.display_name, s.name)) COLLATE "C" DESC NULLS LAST, s.id ASC`},
		{"nope", "asc", `lower(coalesce(s.display_name, s.name)) COLLATE "C" ASC NULLS LAST, s.id ASC`},
		{"name", "sideways", `lower(coalesce(s.display_name, s.name)) COLLATE "C" ASC NULLS LAST, s.id ASC`},
	}
	for _, tc := range cases {
		got := projectServiceOrder(tc.sort, tc.dir)
		if got != tc.want || !strings.Contains(got, "NULLS LAST") || !strings.HasSuffix(got, "s.id ASC") {
			t.Fatalf("%s %s: %q", tc.sort, tc.dir, got)
		}
	}
}
