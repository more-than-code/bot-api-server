// Package catalog splits program command lines and checks program specs.
// The rules are api-v1 v1.6. Nothing in this package talks to a host.
package catalog

import (
	"strings"
	"unicode/utf8"
)

// SplitResult is the argv a program entry stores.
// Env holds only the leading KEY=value words. Display is the argv joined
// with POSIX quoting, or the raw line when Shell is true.
type SplitResult struct {
	Exec    string
	Args    []string
	Env     map[string]string
	Display string
	Shell   bool
}

// Split breaks one command line into argv.
// shell false honours single quotes, double quotes, and backslash escapes,
// and refuses every other shell feature. shell true stores the line for
// /bin/sh -c and does not split it.
func Split(line string, shell bool) (SplitResult, error) {
	if line == "" {
		return SplitResult{}, fieldErr("command is empty")
	}
	if len(line) > 4096 {
		return SplitResult{}, fieldErr("command is too long")
	}
	if strings.ContainsAny(line, "\n\r") {
		return SplitResult{}, fieldErr("newline is not allowed")
	}
	if strings.ContainsRune(line, 0) {
		return SplitResult{}, fieldErr("invalid command")
	}
	if !utf8.ValidString(line) {
		return SplitResult{}, fieldErr("command is not utf-8")
	}
	if shell {
		return SplitResult{
			Exec:    "/bin/sh",
			Args:    []string{"-c", line},
			Env:     map[string]string{},
			Display: line,
			Shell:   true,
		}, nil
	}
	words, err := posixWords(line)
	if err != nil {
		return SplitResult{}, err
	}
	env, rest, err := hoistEnv(words)
	if err != nil {
		return SplitResult{}, err
	}
	if len(rest) == 0 {
		return SplitResult{}, fieldErr("command is empty")
	}
	if rest[0] == "cd" {
		return SplitResult{}, fieldErr("use the working directory field")
	}
	args := rest[1:]
	if args == nil {
		args = []string{}
	}
	return SplitResult{
		Exec:    rest[0],
		Args:    args,
		Env:     env,
		Display: quoteJoin(rest),
		Shell:   false,
	}, nil
}

// posixWords splits line into words. An unquoted shell metacharacter is an error.
func posixWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if !inWord {
			return
		}
		words = append(words, cur.String())
		cur.Reset()
		inWord = false
	}
	for i := 0; i < len(line); {
		c := line[i]
		switch c {
		case ' ', '\t':
			flush()
			i++
			continue
		case '\'':
			inWord = true
			j, err := singleQuote(line, i+1, &cur)
			if err != nil {
				return nil, err
			}
			i = j
			continue
		case '"':
			inWord = true
			j, err := doubleQuote(line, i+1, &cur)
			if err != nil {
				return nil, err
			}
			i = j
			continue
		case '\\':
			if i+1 >= len(line) {
				return nil, fieldErr("trailing backslash")
			}
			inWord = true
			cur.WriteByte(line[i+1])
			i += 2
			continue
		}
		if name, ok := bareFeature(c, !inWord); ok {
			return nil, fieldErr(name + " is not allowed")
		}
		inWord = true
		cur.WriteByte(c)
		i++
	}
	flush()
	return words, nil
}

func singleQuote(line string, i int, cur *strings.Builder) (int, error) {
	for i < len(line) {
		if line[i] == '\'' {
			return i + 1, nil
		}
		cur.WriteByte(line[i])
		i++
	}
	return 0, fieldErr("unclosed quote")
}

func doubleQuote(line string, i int, cur *strings.Builder) (int, error) {
	for i < len(line) {
		c := line[i]
		if c == '"' {
			return i + 1, nil
		}
		if c == '\\' {
			if i+1 >= len(line) {
				return 0, fieldErr("trailing backslash")
			}
			n := line[i+1]
			switch n {
			case '\\', '$', '"', '`':
				cur.WriteByte(n)
			default:
				cur.WriteByte('\\')
				cur.WriteByte(n)
			}
			i += 2
			continue
		}
		cur.WriteByte(c)
		i++
	}
	return 0, fieldErr("unclosed quote")
}

// bareFeature reports the refused feature for an unquoted byte.
// tilde is only refused at the start of a word.
func bareFeature(c byte, wordStart bool) (string, bool) {
	switch c {
	case '|':
		return "pipe", true
	case '&':
		return "operator &", true
	case ';':
		return "operator ;", true
	case '<', '>':
		return "redirect", true
	case '$':
		return "variable expansion", true
	case '`':
		return "command substitution", true
	case '*', '?', '[':
		return "glob", true
	case '(', ')':
		return "parenthesis", true
	case '{', '}':
		return "brace expansion", true
	case '~':
		if wordStart {
			return "tilde expansion", true
		}
	}
	return "", false
}

func hoistEnv(words []string) (map[string]string, []string, error) {
	env := map[string]string{}
	i := 0
	for i < len(words) {
		key, val, ok := envAssignment(words[i])
		if !ok {
			break
		}
		if _, exists := env[key]; exists {
			return nil, nil, fieldErr("duplicate env " + key)
		}
		env[key] = val
		i++
	}
	return env, words[i:], nil
}

func envAssignment(word string) (string, string, bool) {
	i := strings.IndexByte(word, '=')
	if i <= 0 {
		return "", "", false
	}
	key := word[:i]
	if !envKeyRe.MatchString(key) {
		return "", "", false
	}
	return key, word[i+1:], true
}

func quoteJoin(words []string) string {
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = quoteWord(w)
	}
	return strings.Join(parts, " ")
}

func quoteWord(w string) string {
	if w != "" && safeWord.MatchString(w) {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}
