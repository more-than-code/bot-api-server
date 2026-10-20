package catalog

import "unicode/utf8"

// SecretPreview is the v1.13 preview of one secret value.
// Sixteen or more runes show the first four runes and an ellipsis (U+2026).
// Fewer runes show four bullets (U+2022). The value itself is never returned.
func SecretPreview(v string) string {
	if utf8.RuneCountInString(v) >= 16 {
		return string([]rune(v)[:4]) + "…"
	}
	return "••••"
}
