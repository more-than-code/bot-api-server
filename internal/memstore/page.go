package memstore

import (
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func pageBy[T any](items []T, limit int, cursor *store.Cursor, at func(T) time.Time, id func(T) string, desc bool) ([]T, *store.Cursor) {
	if limit <= 0 {
		limit = 50
	}
	filtered := make([]T, 0, len(items))
	for _, it := range items {
		if !acceptsCursor(at(it), id(it), cursor, desc) {
			continue
		}
		filtered = append(filtered, it)
	}
	sort.Slice(filtered, func(i, j int) bool {
		ai, aj := at(filtered[i]), at(filtered[j])
		ii, ij := id(filtered[i]), id(filtered[j])
		if ai.Equal(aj) {
			if desc {
				return ii > ij
			}
			return ii < ij
		}
		if desc {
			return ai.After(aj)
		}
		return ai.Before(aj)
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
		last := filtered[len(filtered)-1]
		c := store.Cursor{At: at(last), ID: id(last)}
		return filtered, &c
	}
	if filtered == nil {
		filtered = []T{}
	}
	return filtered, nil
}

func acceptsCursor(at time.Time, id string, cursor *store.Cursor, desc bool) bool {
	if cursor == nil {
		return true
	}
	if desc {
		if at.Before(cursor.At) {
			return true
		}
		if at.After(cursor.At) {
			return false
		}
		return id < cursor.ID
	}
	if at.After(cursor.At) {
		return true
	}
	if at.Before(cursor.At) {
		return false
	}
	return id > cursor.ID
}

func sortUUIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}
