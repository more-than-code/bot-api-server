package catalog

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxFileBytes is the largest project-file body, in bytes.
const MaxFileBytes = 65536

// fileNameRe is the project-file name rule. It is not the catalog name rule.
var fileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidFileName reports the v1.9 file name rule. "." and ".." fail it.
func ValidFileName(name string) bool {
	return fileNameRe.MatchString(name)
}

// ValidFileContent reports the v1.9 content rule: UTF-8, 1–65536 bytes, no NUL.
func ValidFileContent(content string) bool {
	if len(content) < 1 || len(content) > MaxFileBytes {
		return false
	}
	if strings.ContainsRune(content, 0) || !utf8.ValidString(content) {
		return false
	}
	return true
}
