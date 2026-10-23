package registry

import (
	"regexp"
	"sort"
	"strconv"

	"github.com/more-than-code/bot-api-server/internal/catalog"
)

// MaxItems is the most tags one response returns.
const MaxItems = 200

var (
	semverRe = regexp.MustCompile(`^v?(?P<major>[0-9]{1,9})(?:\.(?P<minor>[0-9]{1,9}))?(?:\.(?P<patch>[0-9]{1,9}))?(?:[-+.](?P<suffix>[0-9A-Za-z._-]*))?$`)
	numGroup = [3]int{semverRe.SubexpIndex("major"), semverRe.SubexpIndex("minor"), semverRe.SubexpIndex("patch")}
	sufGroup = semverRe.SubexpIndex("suffix")
)

// Order drops tags outside the tag grammar and duplicates, sorts the rest,
// and keeps the first 200. truncated is true when tags were cut here or
// more was left in the registry.
//
// Order: semver-like tags descending, then latest, then the rest in reverse
// lexical order. Registries list tags lexically and give no dates.
func Order(list TagList) (tags []string, truncated bool) {
	seen := map[string]bool{}
	kept := make([]string, 0, len(list.Tags))
	for _, t := range list.Tags {
		if !catalog.ValidTag(t) || seen[t] {
			continue
		}
		seen[t] = true
		kept = append(kept, t)
	}
	keys := make(map[string]tagKey, len(kept))
	for _, t := range kept {
		keys[t] = keyOf(t)
	}
	sort.Slice(kept, func(i, j int) bool { return keys[kept[i]].before(keys[kept[j]]) })
	truncated = list.More
	if len(kept) > MaxItems {
		kept = kept[:MaxItems]
		truncated = true
	}
	return kept, truncated
}

const (
	groupSemver = iota
	groupLatest
	groupOther
)

type tagKey struct {
	group  int
	nums   [3]int
	suffix string
	hasSuf bool
	raw    string
}

func keyOf(tag string) tagKey {
	if tag == "latest" {
		return tagKey{group: groupLatest, raw: tag}
	}
	m := semverRe.FindStringSubmatchIndex(tag)
	if m == nil {
		return tagKey{group: groupOther, raw: tag}
	}
	k := tagKey{group: groupSemver, raw: tag, nums: [3]int{-1, -1, -1}}
	for i, g := range numGroup {
		if m[2*g] >= 0 {
			k.nums[i], _ = strconv.Atoi(tag[m[2*g]:m[2*g+1]])
		}
	}
	if m[2*sufGroup] >= 0 {
		k.hasSuf = true
		k.suffix = tag[m[2*sufGroup]:m[2*sufGroup+1]]
	}
	return k
}

// before reports whether a sorts ahead of b. Within semver: higher numbers
// first (a missing part counts below 0), a plain release before a suffixed
// one, then suffix and raw text in reverse lexical order.
func (a tagKey) before(b tagKey) bool {
	if a.group != b.group {
		return a.group < b.group
	}
	if a.group == groupSemver {
		for i := 0; i < 3; i++ {
			if a.nums[i] != b.nums[i] {
				return a.nums[i] > b.nums[i]
			}
		}
		if a.hasSuf != b.hasSuf {
			return !a.hasSuf
		}
		if a.suffix != b.suffix {
			return a.suffix > b.suffix
		}
	}
	return a.raw > b.raw
}
