package store

import (
	"bytes"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ServiceOrder is the sort key for one project-services row.
// NameKey is lower(coalesce(display_name, name)). A true *Null flag
// sorts after every non-null value in both directions.
type ServiceOrder struct {
	ID         uuid.UUID
	NameKey    string
	NameNull   bool
	Host       string
	HostNull   bool
	Kind       string
	KindNull   bool
	StatusRank int
	LastSeen   time.Time
	LastNull   bool
}

// ServiceBefore reports whether a sorts before b.
// sortKey is name, host, kind, status, or last_seen. dir is asc or desc.
// Text keys use strings.Compare, which is byte order. NameKey is already
// strings.ToLower of the label. Host and Kind are the stored text, not
// lowercased. status breaks remaining ties by name in the same direction.
// Equal keys break ties by id ascending in both directions.
func ServiceBefore(a, b ServiceOrder, sortKey, dir string) bool {
	if dir != "desc" {
		dir = "asc"
	}
	cmp := compareServiceKey(a, b, sortKey, dir)
	if cmp == 0 && sortKey == "status" {
		cmp = compareServiceKey(a, b, "name", dir)
	}
	if cmp == 0 {
		return bytes.Compare(a.ID[:], b.ID[:]) < 0
	}
	return cmp < 0
}

func compareServiceKey(a, b ServiceOrder, key, dir string) int {
	switch key {
	case "host":
		return compareOptional(a.Host, a.HostNull, b.Host, b.HostNull, dir, strings.Compare)
	case "kind":
		return compareOptional(a.Kind, a.KindNull, b.Kind, b.KindNull, dir, strings.Compare)
	case "status":
		return compareInt(a.StatusRank, b.StatusRank, dir)
	case "last_seen":
		return compareTime(a.LastSeen, a.LastNull, b.LastSeen, b.LastNull, dir)
	default:
		return compareOptional(a.NameKey, a.NameNull, b.NameKey, b.NameNull, dir, strings.Compare)
	}
}

func compareOptional(a string, aNull bool, b string, bNull bool, dir string, cmp func(string, string) int) int {
	if aNull || bNull {
		if aNull && bNull {
			return 0
		}
		if aNull {
			return 1
		}
		return -1
	}
	c := cmp(a, b)
	if dir == "desc" {
		return -c
	}
	return c
}

func compareInt(a, b int, dir string) int {
	c := 0
	if a < b {
		c = -1
	} else if a > b {
		c = 1
	}
	if dir == "desc" {
		return -c
	}
	return c
}

func compareTime(a time.Time, aNull bool, b time.Time, bNull bool, dir string) int {
	if aNull || bNull {
		if aNull && bNull {
			return 0
		}
		if aNull {
			return 1
		}
		return -1
	}
	c := 0
	if a.Before(b) {
		c = -1
	} else if a.After(b) {
		c = 1
	}
	if dir == "desc" {
		return -c
	}
	return c
}
