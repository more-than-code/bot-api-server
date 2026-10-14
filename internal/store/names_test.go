package store

import (
	"strings"
	"testing"
)

func TestNormalizeOwnerUser(t *testing.T) {
	keep := func(in string) {
		t.Helper()
		got := NormalizeOwnerUser(&in)
		if got == nil || *got != in {
			t.Fatalf("NormalizeOwnerUser(%q) = %v", in, got)
		}
		in = "changed"
		if *got == "changed" {
			t.Fatal("owner_user aliases the caller")
		}
	}
	drop := func(in *string) {
		t.Helper()
		if got := NormalizeOwnerUser(in); got != nil {
			t.Fatalf("NormalizeOwnerUser(%v) = %q", in, *got)
		}
	}
	drop(nil)
	drop(strPtr(""))
	keep("root")
	keep(" www-data ")
	keep("café")
	keep(strings.Repeat("é", 32))
	drop(strPtr(strings.Repeat("é", 33)))
	keep(strings.Repeat("a", MaxOwnerUserBytes))
	drop(strPtr(strings.Repeat("a", MaxOwnerUserBytes+1)))
	drop(strPtr("a\nb"))
	drop(strPtr("a\tb"))
	drop(strPtr("a\x00b"))
	drop(strPtr("bad\xff"))
}

func strPtr(s string) *string { return &s }
