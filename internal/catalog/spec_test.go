package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSpecHashStable(t *testing.T) {
	port := 3031
	first := Program{
		Dir: "/home/joe/app", Exec: "npm", Args: []string{"run", "dev"},
		Shell: false, RunAs: "joe", Env: map[string]string{"B": "2", "A": "1"},
		Port: &port, Restart: "on-failure",
	}
	second := first
	second.Env = map[string]string{"A": "1", "B": "2"}
	second.Args = []string{"run", "dev"}
	canon := `{"kind":"program","spec":{"args":["run","dev"],"dir":"/home/joe/app","env":{"A":"1","B":"2"},"exec":"npm","port":3031,"restart":"on-failure","run_as":"joe","shell":false}}`
	if Canonical(first) != canon || Canonical(second) != canon {
		t.Fatalf("canonical %s", Canonical(first))
	}
	sum := sha256.Sum256([]byte(canon))
	want := hex.EncodeToString(sum[:])
	if SpecHash(first) != want || SpecHash(second) != want {
		t.Fatalf("hash %s want %s", SpecHash(first), want)
	}
	other := first
	other.Port = nil
	if SpecHash(other) == want {
		t.Fatal("null port hashed the same")
	}
	if !strings.Contains(Canonical(other), `"port":null`) {
		t.Fatalf("null port %s", Canonical(other))
	}
	shell := first
	shell.Shell = true
	shell.Exec = "/bin/sh"
	shell.Args = []string{"-c", "npm run dev"}
	if SpecHash(shell) == want || !strings.Contains(Canonical(shell), `"shell":true`) {
		t.Fatal("shell hash did not change")
	}
}

func TestProgramFieldRules(t *testing.T) {
	ok := ProgramInput{
		Command: "npm run dev", Dir: "/home/joe/app", RunAs: "joe",
		Env: map[string]string{"NODE_ENV": "dev"},
	}
	port := 1
	high := 65535
	zero := 0
	huge := 65536
	longDir := "/" + strings.Repeat("a", 255)
	tests := []struct {
		name string
		in   ProgramInput
		err  string
	}{
		{name: "accepted", in: ok},
		{name: "port low", in: withPort(ok, &port)},
		{name: "port high", in: withPort(ok, &high)},
		{name: "port null", in: withPort(ok, nil)},
		{name: "restart default", in: ok},
		{name: "restart no", in: withRestart(ok, "no")},
		{name: "restart on-failure", in: withRestart(ok, "on-failure")},
		{name: "shell mode", in: withCommand(ok, "npm run dev | cat", true)},
		{name: "empty command", in: withCommand(ok, "", false), err: "command is empty"},
		{name: "command too long", in: withCommand(ok, strings.Repeat("a", 4097), false), err: "command is too long"},
		{name: "newline", in: withCommand(ok, "npm\nrun", false), err: "newline is not allowed"},
		{name: "pipe", in: withCommand(ok, "npm | cat", false), err: "pipe is not allowed"},
		{name: "and", in: withCommand(ok, "npm && cat", false), err: "operator & is not allowed"},
		{name: "semicolon", in: withCommand(ok, "npm; cat", false), err: "operator ; is not allowed"},
		{name: "redirect", in: withCommand(ok, "npm > out", false), err: "redirect is not allowed"},
		{name: "dollar", in: withCommand(ok, "echo $X", false), err: "variable expansion is not allowed"},
		{name: "backtick", in: withCommand(ok, "echo `x`", false), err: "command substitution is not allowed"},
		{name: "glob", in: withCommand(ok, "echo *", false), err: "glob is not allowed"},
		{name: "paren", in: withCommand(ok, "echo (x)", false), err: "parenthesis is not allowed"},
		{name: "brace", in: withCommand(ok, "echo {a}", false), err: "brace expansion is not allowed"},
		{name: "tilde", in: withCommand(ok, "~/npm", false), err: "tilde expansion is not allowed"},
		{name: "cd", in: withCommand(ok, "cd /tmp", false), err: "use the working directory field"},
		{name: "exec relative", in: withCommand(ok, "bin/npm", false), err: "invalid exec"},
		{name: "exec dotdot", in: withCommand(ok, "/usr/bin/../../tmp/x run", false), err: "invalid exec"},
		{name: "exec bad char", in: withCommand(ok, "/usr/bin/npm space", false)},
		{name: "exec with space", in: withCommand(ok, "'my npm'", false), err: "invalid exec"},
		{name: "too many args", in: withCommand(ok, "npm "+strings.Repeat("a ", 33), false), err: "too many args"},
		{name: "arg at limit", in: withCommand(ok, "npm "+strings.Repeat("a", 4091), false)},
		{name: "dir relative", in: withDir(ok, "home/joe"), err: "invalid dir"},
		{name: "dir empty", in: withDir(ok, ""), err: "invalid dir"},
		{name: "dir too long", in: withDir(ok, longDir), err: "invalid dir"},
		{name: "dir dotdot", in: withDir(ok, "/tmp/../etc"), err: "invalid dir"},
		{name: "dir nul", in: withDir(ok, "/tmp/\x00"), err: "invalid dir"},
		{name: "run_as root", in: withRunAs(ok, "root"), err: "invalid run_as"},
		{name: "run_as empty", in: withRunAs(ok, ""), err: "invalid run_as"},
		{name: "run_as upper", in: withRunAs(ok, "Joe"), err: "invalid run_as"},
		{name: "run_as ok underscore", in: withRunAs(ok, "_joe")},
		{name: "env secret", in: withEnv(ok, "API_KEY", "x"), err: "use secret_env"},
		{name: "env password", in: withEnv(ok, "PASSWORD", "x"), err: "use secret_env"},
		{name: "env token", in: withEnv(ok, "TOKEN", "x"), err: "use secret_env"},
		{name: "env passwd", in: withEnv(ok, "PASSWD", "x"), err: "use secret_env"},
		{name: "env secret word", in: withEnv(ok, "SECRET", "x"), err: "use secret_env"},
		{name: "env credential", in: withEnv(ok, "CREDENTIAL", "x"), err: "use secret_env"},
		{name: "env private key", in: withEnv(ok, "PRIVATE_KEY", "x"), err: "use secret_env"},
		{name: "env apikey", in: withEnv(ok, "APIKEY", "x"), err: "use secret_env"},
		{name: "env aws secret", in: withEnv(ok, "AWS_SECRET_ACCESS_KEY", "x"), err: "use secret_env"},
		{name: "env ld preload", in: withEnv(ok, "LD_PRELOAD", "/x"), err: "this variable changes what the program runs"},
		{name: "env dyld", in: withEnv(ok, "DYLD_INSERT_LIBRARIES", "/x"), err: "this variable changes what the program runs"},
		{name: "env node options", in: withEnv(ok, "NODE_OPTIONS", "--require /x"), err: "this variable changes what the program runs"},
		{name: "env node path", in: withEnv(ok, "NODE_PATH", "/x"), err: "this variable changes what the program runs"},
		{name: "env bash env", in: withEnv(ok, "BASH_ENV", "/x"), err: "this variable changes what the program runs"},
		{name: "env ENV", in: withEnv(ok, "ENV", "/x"), err: "this variable changes what the program runs"},
		{name: "env IFS", in: withEnv(ok, "IFS", " "), err: "this variable changes what the program runs"},
		{name: "env pythonpath", in: withEnv(ok, "PYTHONPATH", "/x"), err: "this variable changes what the program runs"},
		{name: "env pythonstartup", in: withEnv(ok, "PYTHONSTARTUP", "/x"), err: "this variable changes what the program runs"},
		{name: "env perl5opt", in: withEnv(ok, "PERL5OPT", "-m"), err: "this variable changes what the program runs"},
		{name: "env perl5lib", in: withEnv(ok, "PERL5LIB", "/x"), err: "this variable changes what the program runs"},
		{name: "env rubyopt", in: withEnv(ok, "RUBYOPT", "-r"), err: "this variable changes what the program runs"},
		{name: "env rubylib", in: withEnv(ok, "RUBYLIB", "/x"), err: "this variable changes what the program runs"},
		{name: "hoisted ld", in: withCommand(ok, "LD_PRELOAD=/tmp/x.so npm start", false), err: "this variable changes what the program runs"},
		{name: "env path", in: withEnv(ok, "PATH", "/bin"), err: "PATH is reserved"},
		{name: "env home", in: withEnv(ok, "HOME", "/home/joe"), err: "HOME is reserved"},
		{name: "env bad key", in: withEnv(ok, "node", "1"), err: "invalid env key"},
		{name: "env value newline", in: withEnv(ok, "FOO", "a\nb"), err: "invalid env value"},
		{name: "env value long", in: withEnv(ok, "FOO", strings.Repeat("a", 4097)), err: "invalid env value"},
		{name: "too many env", in: manyEnv(ok), err: "too many env keys"},
		{name: "duplicate hoist and body", in: withCommandEnv(ok, "FOO=1 npm start", "FOO", "2"), err: "duplicate env FOO"},
		{name: "port zero", in: withPort(ok, &zero), err: "invalid port"},
		{name: "port high out", in: withPort(ok, &huge), err: "invalid port"},
		{name: "restart bad", in: withRestart(ok, "always"), err: "invalid restart"},
		{name: "bare exec", in: withCommand(ok, "pnpm install", false)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildProgram(tc.in)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err %v want %s", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Restart == "" || (tc.in.Restart == "" && got.Restart != "on-failure") {
				t.Fatalf("restart %s", got.Restart)
			}
			if got.Env == nil || got.Args == nil {
				t.Fatal("nil slice or map")
			}
			if tc.name == "accepted" && got.Env["NODE_ENV"] != "dev" {
				t.Fatalf("env %#v", got.Env)
			}
		})
	}
	if err := RejectKind("image", false); err != nil {
		t.Fatalf("image %v", err)
	}
	if err := RejectKind("file", false); err == nil || err.(*FieldError).Code != CodeNotImplemented {
		t.Fatalf("file %v", err)
	}
	if err := RejectKind("program", true); err == nil || err.(*FieldError).Code != CodeNotImplemented {
		t.Fatalf("secret_env %v", err)
	}
	if err := RejectKind("program", false); err != nil {
		t.Fatal(err)
	}
	if !ValidName("tra-backend") || ValidName("Tra") || ValidName("") || ValidName(strings.Repeat("a", 49)) {
		t.Fatal("name rule")
	}
	if !ValidIdempotencyKey("abc.DEF_1:2-3") || ValidIdempotencyKey("") || ValidIdempotencyKey("has space") {
		t.Fatal("idempotency key")
	}
	if err := validateArgs([]string{strings.Repeat("x", 4097)}); err == nil || err.Error() != "arg is too long" {
		t.Fatalf("long arg %v", err)
	}
	if err := validateArgs([]string{"a\nb"}); err == nil || err.Error() != "invalid arg" {
		t.Fatalf("newline arg %v", err)
	}
	if err := validateArgs([]string{"a\x00b"}); err == nil || err.Error() != "invalid arg" {
		t.Fatalf("nul arg %v", err)
	}
}

func withCommand(in ProgramInput, command string, shell bool) ProgramInput {
	in.Command = command
	in.Shell = shell
	return in
}

func withDir(in ProgramInput, dir string) ProgramInput {
	in.Dir = dir
	return in
}

func withRunAs(in ProgramInput, user string) ProgramInput {
	in.RunAs = user
	return in
}

func withEnv(in ProgramInput, k, v string) ProgramInput {
	in.Env = map[string]string{k: v}
	return in
}

func withCommandEnv(in ProgramInput, command, k, v string) ProgramInput {
	in.Command = command
	in.Env = map[string]string{k: v}
	return in
}

func withPort(in ProgramInput, port *int) ProgramInput {
	in.Port = port
	return in
}

func withRestart(in ProgramInput, restart string) ProgramInput {
	in.Restart = restart
	return in
}

func manyEnv(in ProgramInput) ProgramInput {
	env := map[string]string{}
	for i := 0; i < 65; i++ {
		env["K"+pad(i)] = "1"
	}
	in.Env = env
	return in
}

func pad(i int) string {
	const digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return digits[i/26:i/26+1] + digits[i%26:i%26+1]
}
