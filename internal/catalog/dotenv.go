package catalog

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maxDotenvBytes = 256 * 1024
	maxDotenvKeys  = 256
	maxEnvValue    = 4096
)

// EnvPair is one dotenv assignment. Value is the unquoted plaintext.
type EnvPair struct {
	Key   string
	Value string
}

// ParseDotenv applies the v1.8 dotenv grammar.
// Errors name the line and the key when the key parsed, and never a value.
func ParseDotenv(in []byte) ([]EnvPair, error) {
	if len(in) > maxDotenvBytes {
		return nil, fieldErr("dotenv is too large")
	}
	if !utf8.Valid(in) {
		return nil, fieldErr("invalid dotenv")
	}
	text := strings.ReplaceAll(string(in), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	// A trailing newline does not add a pair.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	out := make([]EnvPair, 0)
	seen := map[string]bool{}
	for i, line := range lines {
		n := i + 1
		if strings.ContainsRune(line, 0) {
			return nil, fieldErr(fmt.Sprintf("line %d: malformed", n))
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		body := strings.TrimLeft(line, " \t")
		if rest, ok := strings.CutPrefix(body, "export"); ok && len(rest) > 0 && isSpace(rest[0]) {
			body = strings.TrimLeft(rest, " \t")
		}
		key, value, ok := strings.Cut(body, "=")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return nil, fieldErr(fmt.Sprintf("line %d: malformed", n))
		}
		if !envKeyRe.MatchString(key) {
			return nil, fieldErr(fmt.Sprintf("line %d: malformed", n))
		}
		if key == "PATH" || key == "HOME" {
			return nil, fieldErr(fmt.Sprintf("line %d: %s is reserved", n, key))
		}
		if changesWhatRuns(key) {
			return nil, fieldErr(fmt.Sprintf("line %d: %s this variable changes what the program runs", n, key))
		}
		if strings.ContainsRune(value, 0) || strings.ContainsAny(value, "\\$") {
			return nil, fieldErr(fmt.Sprintf("line %d: %s invalid env value", n, key))
		}
		if len(value) >= 2 {
			q := value[0]
			if (q == '"' || q == '\'') && value[len(value)-1] == q {
				value = value[1 : len(value)-1]
			} else if q == '"' || q == '\'' {
				return nil, fieldErr(fmt.Sprintf("line %d: %s malformed", n, key))
			}
		} else if len(value) == 1 && (value[0] == '"' || value[0] == '\'') {
			return nil, fieldErr(fmt.Sprintf("line %d: %s malformed", n, key))
		}
		if err := dotenvValue(n, key, value); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fieldErr(fmt.Sprintf("line %d: %s duplicate", n, key))
		}
		seen[key] = true
		if len(out) >= maxDotenvKeys {
			return nil, fieldErr("too many env keys")
		}
		out = append(out, EnvPair{Key: key, Value: value})
	}
	return out, nil
}

func dotenvValue(n int, key, value string) error {
	if strings.ContainsRune(value, 0) || strings.ContainsAny(value, "\\$") || len(value) > maxEnvValue {
		return fieldErr(fmt.Sprintf("line %d: %s invalid env value", n, key))
	}
	return nil
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t'
}
