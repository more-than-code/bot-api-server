package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	CodeBadRequest     = "bad_request"
	CodeNotImplemented = "not_implemented"
	restartOnFailure   = "on-failure"
	restartNo          = "no"
)

var (
	envKeyRe   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	bareExecRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,128}$`)
	absExecRe  = regexp.MustCompile(`^/[A-Za-z0-9._+/-]{1,255}$`)
	runAsRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	secretKey  = regexp.MustCompile(`(?i)(password|passwd|token|secret|credential|api[_-]?key|private[_-]?key)`)
	safeWord   = regexp.MustCompile(`^[A-Za-z0-9._@%+=:,/-]+$`)
	idemKeyRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// FieldError is one v1.6 validation failure. Code is an envelope code.
type FieldError struct {
	Code string
	Msg  string
}

func (e *FieldError) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

func fieldErr(msg string) error {
	return &FieldError{Code: CodeBadRequest, Msg: msg}
}

func notImplemented(msg string) error {
	return &FieldError{Code: CodeNotImplemented, Msg: msg}
}

// Program is a normalized program spec.
type Program struct {
	Dir     string
	Exec    string
	Args    []string
	Shell   bool
	RunAs   string
	Env     map[string]string
	Port    *int
	Restart string
	Display string
}

// ProgramInput is the create and replace body after the command is split.
type ProgramInput struct {
	Command string
	Shell   bool
	Dir     string
	RunAs   string
	Env     map[string]string
	Port    *int
	Restart string // empty means the default
}

// BuildProgram applies v1.6 rules 1–9 and returns the stored spec.
// secret_env and a non-program kind are refused by the caller (rule 10).
func BuildProgram(in ProgramInput) (Program, error) {
	split, err := Split(in.Command, in.Shell)
	if err != nil {
		return Program{}, err
	}
	env, err := mergeEnv(in.Env, split.Env)
	if err != nil {
		return Program{}, err
	}
	if err := validateExec(split.Exec); err != nil {
		return Program{}, err
	}
	if err := validateArgs(split.Args); err != nil {
		return Program{}, err
	}
	if err := validateDir(in.Dir); err != nil {
		return Program{}, err
	}
	if err := validateRunAs(in.RunAs); err != nil {
		return Program{}, err
	}
	if err := validateEnv(env); err != nil {
		return Program{}, err
	}
	if in.Port != nil && (*in.Port < 1 || *in.Port > 65535) {
		return Program{}, fieldErr("invalid port")
	}
	restart := in.Restart
	if restart == "" {
		restart = restartOnFailure
	}
	if restart != restartOnFailure && restart != restartNo {
		return Program{}, fieldErr("invalid restart")
	}
	if split.Args == nil {
		split.Args = []string{}
	}
	return Program{
		Dir:     in.Dir,
		Exec:    split.Exec,
		Args:    split.Args,
		Shell:   split.Shell,
		RunAs:   in.RunAs,
		Env:     env,
		Port:    in.Port,
		Restart: restart,
		Display: split.Display,
	}, nil
}

// Preview applies rules 1–5 and returns the form preview.
func Preview(command string, shell bool) (SplitResult, error) {
	split, err := Split(command, shell)
	if err != nil {
		return SplitResult{}, err
	}
	if err := validateExec(split.Exec); err != nil {
		return SplitResult{}, err
	}
	if err := validateArgs(split.Args); err != nil {
		return SplitResult{}, err
	}
	return split, nil
}

func mergeEnv(body, hoisted map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range body {
		out[k] = v
	}
	for k, v := range hoisted {
		if _, exists := out[k]; exists {
			return nil, fieldErr("duplicate env " + k)
		}
		out[k] = v
	}
	return out, nil
}

func validateExec(exec string) error {
	if strings.HasPrefix(exec, "/") {
		if !absExecRe.MatchString(exec) || hasDotDot(exec) {
			return fieldErr("invalid exec")
		}
		return nil
	}
	if !bareExecRe.MatchString(exec) {
		return fieldErr("invalid exec")
	}
	return nil
}

func validateArgs(args []string) error {
	if len(args) > 32 {
		return fieldErr("too many args")
	}
	for _, a := range args {
		if len(a) > 4096 {
			return fieldErr("arg is too long")
		}
		if strings.ContainsAny(a, "\n\r") || strings.ContainsRune(a, 0) {
			return fieldErr("invalid arg")
		}
	}
	return nil
}

func validateDir(dir string) error {
	if dir == "" || len(dir) > 255 || !strings.HasPrefix(dir, "/") {
		return fieldErr("invalid dir")
	}
	if strings.ContainsRune(dir, 0) || strings.ContainsAny(dir, "\n\r") || hasDotDot(dir) {
		return fieldErr("invalid dir")
	}
	return nil
}

func hasDotDot(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func validateRunAs(user string) error {
	if user == "root" || !runAsRe.MatchString(user) {
		return fieldErr("invalid run_as")
	}
	return nil
}

func validateEnv(env map[string]string) error {
	if len(env) > 64 {
		return fieldErr("too many env keys")
	}
	for k, v := range env {
		if !envKeyRe.MatchString(k) {
			return fieldErr("invalid env key")
		}
		if k == "PATH" || k == "HOME" {
			return fieldErr(k + " is reserved")
		}
		if secretKey.MatchString(k) {
			return fieldErr("use secret_env")
		}
		if changesWhatRuns(k) {
			return fieldErr("this variable changes what the program runs")
		}
		if len(v) > 4096 || strings.ContainsAny(v, "\n\r") || strings.ContainsRune(v, 0) {
			return fieldErr("invalid env value")
		}
	}
	return nil
}

// changesWhatRuns is api-v1 v1.6.1 item 2. The same keys are refused when
// they arrive as hoisted KEY=value words, because those words are merged
// into env before this check.
func changesWhatRuns(key string) bool {
	if strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DYLD_") {
		return true
	}
	switch key {
	case "NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "IFS",
		"PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB":
		return true
	default:
		return false
	}
}

// ValidName reports whether name is a catalog entry name.
func ValidName(name string) bool {
	return nameRe.MatchString(name)
}

// ValidIdempotencyKey reports whether key matches the v1.6 key rule.
func ValidIdempotencyKey(key string) bool {
	return idemKeyRe.MatchString(key)
}

// Canonical is the spec_hash input: {"kind","spec"} with sorted keys and no whitespace.
func Canonical(p Program) string {
	envKeys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	var env strings.Builder
	env.WriteByte('{')
	for i, k := range envKeys {
		if i > 0 {
			env.WriteByte(',')
		}
		env.WriteString(jsonString(k))
		env.WriteByte(':')
		env.WriteString(jsonString(p.Env[k]))
	}
	env.WriteByte('}')
	var args strings.Builder
	args.WriteByte('[')
	for i, a := range p.Args {
		if i > 0 {
			args.WriteByte(',')
		}
		args.WriteString(jsonString(a))
	}
	args.WriteByte(']')
	port := "null"
	if p.Port != nil {
		port = strconv.Itoa(*p.Port)
	}
	shell := "false"
	if p.Shell {
		shell = "true"
	}
	return `{"kind":"program","spec":{"args":` + args.String() +
		`,"dir":` + jsonString(p.Dir) +
		`,"env":` + env.String() +
		`,"exec":` + jsonString(p.Exec) +
		`,"port":` + port +
		`,"restart":` + jsonString(p.Restart) +
		`,"run_as":` + jsonString(p.RunAs) +
		`,"shell":` + shell + `}}`
}

// SpecHash is the lowercase hex SHA-256 of Canonical.
func SpecHash(p Program) string {
	sum := sha256.Sum256([]byte(Canonical(p)))
	return hex.EncodeToString(sum[:])
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// RejectKind reports rule 10. A missing kind is not this error.
// kind image is accepted. A program body that carries top-level secret_env
// is still not implemented. Image files are a spec field, not a kind.
func RejectKind(kind string, secretEnv bool) error {
	if secretEnv || (kind != "" && kind != "program" && kind != "image") {
		return notImplemented("not implemented")
	}
	return nil
}
