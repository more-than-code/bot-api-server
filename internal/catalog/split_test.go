package catalog

import (
	"strings"
	"testing"
)

func TestSplitTable(t *testing.T) {
	maxArg := strings.Repeat("a", 4091)
	tooLong := strings.Repeat("a", 4097)
	tests := []struct {
		name    string
		line    string
		shell   bool
		exec    string
		args    []string
		env     map[string]string
		display string
		err     string
	}{
		{name: "npm run dev", line: "npm run dev", exec: "npm", args: []string{"run", "dev"}, display: "npm run dev"},
		{name: "npm with port", line: "npm run dev -- --port 3031", exec: "npm", args: []string{"run", "dev", "--", "--port", "3031"}, display: "npm run dev -- --port 3031"},
		{name: "single word", line: "pnpm", exec: "pnpm", args: []string{}, display: "pnpm"},
		{name: "absolute exec", line: "/usr/bin/npm start", exec: "/usr/bin/npm", args: []string{"start"}, display: "/usr/bin/npm start"},
		{name: "single quotes", line: "echo 'hello world'", exec: "echo", args: []string{"hello world"}, display: "echo 'hello world'"},
		{name: "double quotes", line: `echo "hello world"`, exec: "echo", args: []string{"hello world"}, display: "echo 'hello world'"},
		{name: "escaped space", line: `echo hello\ world`, exec: "echo", args: []string{"hello world"}, display: "echo 'hello world'"},
		{name: "escaped quote", line: `echo \"hi\"`, exec: "echo", args: []string{`"hi"`}, display: `echo '"hi"'`},
		{name: "pipe inside single quotes", line: "echo 'a|b'", exec: "echo", args: []string{"a|b"}, display: "echo 'a|b'"},
		{name: "pipe inside double quotes", line: `echo "a|b"`, exec: "echo", args: []string{"a|b"}, display: "echo 'a|b'"},
		{name: "empty quoted arg", line: "echo ''", exec: "echo", args: []string{""}, display: "echo ''"},
		{name: "adjacent single quotes", line: "echo 'a''b'", exec: "echo", args: []string{"ab"}, display: "echo ab"},
		{name: "mixed quotes", line: `echo "a"'b'`, exec: "echo", args: []string{"ab"}, display: "echo ab"},
		{name: "double quote escape", line: `echo "a\"b"`, exec: "echo", args: []string{`a"b`}, display: `echo 'a"b'`},
		{name: "escaped dollar", line: `echo \$HOME`, exec: "echo", args: []string{"$HOME"}, display: "echo '$HOME'"},
		{name: "dollar inside double quotes", line: `echo "$HOME"`, exec: "echo", args: []string{"$HOME"}, display: "echo '$HOME'"},
		{name: "backtick inside single quotes", line: "echo 'a`b'", exec: "echo", args: []string{"a`b"}, display: "echo 'a`b'"},
		{name: "glob inside quotes", line: "echo '*'", exec: "echo", args: []string{"*"}, display: "echo '*'"},
		{name: "tilde mid word", line: "echo a~b", exec: "echo", args: []string{"a~b"}, display: "echo 'a~b'"},
		{name: "escaped tilde", line: `\~foo`, err: "invalid exec"},
		{name: "escaped pipe", line: `echo \|`, exec: "echo", args: []string{"|"}, display: "echo '|'"},
		{name: "tabs split", line: "npm\trun\tdev", exec: "npm", args: []string{"run", "dev"}, display: "npm run dev"},
		{name: "repeated spaces", line: "npm   run", exec: "npm", args: []string{"run"}, display: "npm run"},
		{name: "hoisted env", line: "FOO=bar npm run dev", exec: "npm", args: []string{"run", "dev"}, env: map[string]string{"FOO": "bar"}, display: "npm run dev"},
		{name: "two hoisted", line: "FOO=bar BAZ=qux npm start", exec: "npm", args: []string{"start"}, env: map[string]string{"FOO": "bar", "BAZ": "qux"}, display: "npm start"},
		{name: "empty hoist value", line: "FOO= npm start", exec: "npm", args: []string{"start"}, env: map[string]string{"FOO": ""}, display: "npm start"},
		{name: "hoist value with equals", line: "FOO=a=b npm start", exec: "npm", args: []string{"start"}, env: map[string]string{"FOO": "a=b"}, display: "npm start"},
		{name: "quoted hoist value", line: `FOO="a b" npm start`, exec: "npm", args: []string{"start"}, env: map[string]string{"FOO": "a b"}, display: "npm start"},
		{name: "lowercase assignment is not hoist", line: "foo=bar", err: "invalid exec"},
		{name: "max length", line: "echo " + maxArg, exec: "echo", args: []string{maxArg}, display: "echo " + maxArg},
		{name: "shell keeps pipe", line: "npm run dev | tee log", shell: true, exec: "/bin/sh", args: []string{"-c", "npm run dev | tee log"}, display: "npm run dev | tee log"},
		{name: "shell keeps cd", line: "cd /tmp && npm start", shell: true, exec: "/bin/sh", args: []string{"-c", "cd /tmp && npm start"}, display: "cd /tmp && npm start"},
		{name: "shell keeps expansion", line: "echo $HOME `date` > out", shell: true, exec: "/bin/sh", args: []string{"-c", "echo $HOME `date` > out"}, display: "echo $HOME `date` > out"},
		{name: "closing bracket is literal", line: "echo a]", exec: "echo", args: []string{"a]"}, display: "echo 'a]'"},
		{name: "refuse pipe", line: "npm run dev | cat", err: "pipe is not allowed"},
		{name: "refuse and", line: "npm run dev && echo hi", err: "operator & is not allowed"},
		{name: "refuse or", line: "npm run a || npm run b", err: "pipe is not allowed"},
		{name: "refuse semicolon", line: "npm run a; npm run b", err: "operator ; is not allowed"},
		{name: "refuse redirect out", line: "npm run dev > out", err: "redirect is not allowed"},
		{name: "refuse redirect in", line: "npm start < in", err: "redirect is not allowed"},
		{name: "refuse dollar", line: "echo $HOME", err: "variable expansion is not allowed"},
		{name: "refuse substitution", line: "echo $(date)", err: "variable expansion is not allowed"},
		{name: "refuse backtick", line: "echo `date`", err: "command substitution is not allowed"},
		{name: "refuse glob star", line: "echo *", err: "glob is not allowed"},
		{name: "refuse glob question", line: "echo file?", err: "glob is not allowed"},
		{name: "refuse glob bracket", line: "echo file[a]", err: "glob is not allowed"},
		{name: "refuse parenthesis", line: "echo (hi)", err: "parenthesis is not allowed"},
		{name: "refuse close paren", line: "echo )", err: "parenthesis is not allowed"},
		{name: "refuse brace", line: "echo {a,b}", err: "brace expansion is not allowed"},
		{name: "refuse close brace", line: "echo }", err: "brace expansion is not allowed"},
		{name: "refuse tilde", line: "~/bin/npm", err: "tilde expansion is not allowed"},
		{name: "refuse cd", line: "cd /tmp", err: "use the working directory field"},
		{name: "refuse cd after env", line: "FOO=1 cd /tmp", err: "use the working directory field"},
		{name: "refuse newline", line: "npm\nrun", err: "newline is not allowed"},
		{name: "refuse empty", line: "", err: "command is empty"},
		{name: "refuse too long", line: tooLong, err: "command is too long"},
		{name: "refuse unclosed quote", line: "echo 'hi", err: "unclosed quote"},
		{name: "refuse unclosed double", line: `echo "hi`, err: "unclosed quote"},
		{name: "refuse trailing backslash", line: `echo \`, err: "trailing backslash"},
		{name: "refuse duplicate hoist", line: "FOO=1 FOO=2 npm start", err: "duplicate env FOO"},
		{name: "refuse only env", line: "FOO=1", err: "command is empty"},
		{name: "shell empty", line: "", shell: true, err: "command is empty"},
		{name: "shell newline", line: "echo\nhi", shell: true, err: "newline is not allowed"},
	}
	if len(tests) < 40 {
		t.Fatalf("table has %d rows", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Preview(tc.line, tc.shell)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err %v want %s", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Exec != tc.exec || strings.Join(got.Args, "\x00") != strings.Join(tc.args, "\x00") {
				t.Fatalf("argv %s %q", got.Exec, got.Args)
			}
			if got.Display != tc.display {
				t.Fatalf("display %q want %q", got.Display, tc.display)
			}
			if len(got.Env) != len(tc.env) {
				t.Fatalf("env %#v", got.Env)
			}
			for k, v := range tc.env {
				if got.Env[k] != v {
					t.Fatalf("env %s=%q want %q", k, got.Env[k], v)
				}
			}
		})
	}
}
