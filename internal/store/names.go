package store

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Slug derives a project slug: lowercase, [a-z0-9-], dashes collapsed.
// An empty result becomes "project". The slug does not change when the
// project is renamed.
func Slug(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	prevDash := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "project"
	}
	if len(s) > 80 {
		s = strings.Trim(s[:80], "-")
	}
	if s == "" {
		s = "project"
	}
	return s
}

// WithSuffix appends -n to base, trimming base so the result is at most max
// bytes and still matches the host-name character set. n < 2 returns base,
// trimmed to max.
func WithSuffix(base string, n, max int) string {
	if max < 1 {
		max = 1
	}
	if n < 2 {
		if len(base) > max {
			base = strings.TrimRight(base[:max], "-")
		}
		if base == "" {
			return "x"
		}
		return base
	}
	suf := "-" + strconv.Itoa(n)
	room := max - len(suf)
	if room < 1 {
		room = 1
	}
	b := base
	if len(b) > room {
		b = b[:room]
	}
	b = strings.TrimRight(b, "-")
	if b == "" {
		b = "x"
	}
	if len(b)+len(suf) > max && len(b) > 1 {
		b = strings.TrimRight(b[:len(b)-1], "-")
		if b == "" {
			b = "x"
		}
	}
	return b + suf
}

// Unique returns base, or base-2, base-3, … until taken reports free.
// max is the length cap passed to WithSuffix.
func Unique(base string, max int, taken func(string) bool) (string, error) {
	if !taken(base) && len(base) <= max {
		return base, nil
	}
	for n := 2; n < 1000; n++ {
		candidate := WithSuffix(base, n, max)
		if !taken(candidate) {
			return candidate, nil
		}
	}
	return "", ErrConflict
}

// ValidName reports whether name is 1–80 runes and contains no control
// characters. Callers trim first.
func ValidName(name string) bool {
	n := utf8.RuneCountInString(name)
	if n < 1 || n > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
