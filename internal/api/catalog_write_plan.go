package api

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/more-than-code/bot-api-server/internal/catalog"
)

// planToken is the v1.12 plain-token exception. Anything else is Go-quoted
// so a project name, target, or argument cannot insert a clause, a line
// break, or a bidi override into the sentence the user approves.
var planToken = regexp.MustCompile(`^[A-Za-z0-9._:/@+=-]+$`)

// catalogCreatePlan is the v1.12 create sentence. Empty groups are omitted.
// Inline env values are shown. Env-set values, secret_env values, and file
// contents are not. Entrypoint is listed when set. Restart is listed when
// it is not the kind's default.
func catalogCreatePlan(project, name string, img catalog.Image) string {
	head := "will create image entry " + planText(name) + " in " + planText(project) + ": " + planText(img.Image) + ", " + img.Kind
	var parts []string
	if len(img.Ports) > 0 {
		parts = append(parts, "ports "+portsPhrase(img.Ports))
	}
	if len(img.EnvSets) > 0 {
		parts = append(parts, "env sets "+listPhrase(img.EnvSets))
	}
	if len(img.Env) > 0 {
		parts = append(parts, "env "+envValuePhrase(img.Env))
	}
	if len(img.SecretEnv) > 0 {
		parts = append(parts, "secret_env "+secretEnvPhrase(img.SecretEnv))
	}
	if len(img.Volumes) > 0 {
		parts = append(parts, "volumes "+volumePhrase(img.Volumes))
	}
	if len(img.Files) > 0 {
		parts = append(parts, "files "+filePhrase(img.Files))
	}
	if len(img.Command) > 0 {
		parts = append(parts, "command "+argvPhrase(img.Command))
	}
	if len(img.Entrypoint) > 0 {
		parts = append(parts, "entrypoint "+argvPhrase(img.Entrypoint))
	}
	if img.Restart != defaultRestart(img.Kind) {
		parts = append(parts, "restart "+planText(img.Restart))
	}
	if img.User != "" {
		parts = append(parts, "user "+planText(img.User))
	}
	if img.MemoryMB != nil {
		parts = append(parts, "memory "+memoryPhrase(img.MemoryMB))
	}
	if len(parts) == 0 {
		return head
	}
	return head + "; " + strings.Join(parts, "; ")
}

// catalogUpdatePlan lists only the fields whose phrases differ, then the
// number of host approvals the write will void. A changed inline env key
// shows the old value and the new value.
func catalogUpdatePlan(name string, old, next catalog.Image, voids int) string {
	var parts []string
	add := func(field, before, after string) {
		if before == after {
			return
		}
		parts = append(parts, field+": "+before+" → "+after)
	}
	add("image", planText(old.Image), planText(next.Image))
	add("kind", old.Kind, next.Kind)
	add("ports", portsOrNone(old.Ports), portsOrNone(next.Ports))
	add("env sets", listOrNone(old.EnvSets), listOrNone(next.EnvSets))
	if phrase := envChangePhrase(old.Env, next.Env); phrase != "" {
		parts = append(parts, "env "+phrase)
	}
	add("secret_env", secretOrNone(old.SecretEnv), secretOrNone(next.SecretEnv))
	add("volumes", volumeOrNone(old.Volumes), volumeOrNone(next.Volumes))
	add("files", fileOrNone(old.Files), fileOrNone(next.Files))
	add("command", argvOrNone(old.Command), argvOrNone(next.Command))
	add("entrypoint", argvOrNone(old.Entrypoint), argvOrNone(next.Entrypoint))
	add("restart", textOrNone(old.Restart), textOrNone(next.Restart))
	add("user", textOrNone(old.User), textOrNone(next.User))
	add("healthy_after_sec", strconv.Itoa(old.HealthyAfterSec), strconv.Itoa(next.HealthyAfterSec))
	add("memory", memoryPhrase(old.MemoryMB), memoryPhrase(next.MemoryMB))
	add("timeout_sec", strconv.Itoa(old.TimeoutSec), strconv.Itoa(next.TimeoutSec))
	head := "will update image entry " + planText(name) + ":"
	tail := "voids " + hostApprovals(voids)
	if len(parts) == 0 {
		return head + " " + tail
	}
	return head + " " + strings.Join(parts, "; ") + "; " + tail
}

func catalogDeletePlan(name string, approvals int) string {
	return "will delete image entry " + planText(name) + "; " + hostApprovals(approvals) + " and its grants are removed; running containers are not stopped"
}

func defaultRestart(kind string) string {
	if kind == "job" {
		return "no"
	}
	return "unless-stopped"
}

func hostApprovals(n int) string {
	if n == 1 {
		return "1 host approval"
	}
	return strconv.Itoa(n) + " host approvals"
}

func planText(s string) string {
	if planToken.MatchString(s) {
		return s
	}
	return strconv.Quote(s)
}

func portsPhrase(ports []catalog.Port) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		arrow := strconv.Itoa(p.Host) + "→" + strconv.Itoa(p.Container)
		if p.Public {
			parts[i] = "public " + arrow
		} else {
			parts[i] = "127.0.0.1:" + arrow
		}
	}
	return strings.Join(parts, ", ")
}

func portsOrNone(ports []catalog.Port) string {
	if len(ports) == 0 {
		return "none"
	}
	return portsPhrase(ports)
}

func listPhrase(items []string) string {
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = planText(item)
	}
	return strings.Join(parts, ", ")
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return listPhrase(items)
}

func envValuePhrase(env map[string]string) string {
	keys := envKeys(env)
	parts := make([]string, len(keys))
	for i, key := range keys {
		parts[i] = planText(key) + "=" + planText(env[key])
	}
	return strings.Join(parts, ", ")
}

func envChangePhrase(old, next map[string]string) string {
	seen := map[string]struct{}{}
	for key := range old {
		seen[key] = struct{}{}
	}
	for key := range next {
		seen[key] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		before, oldOK := old[key]
		after, nextOK := next[key]
		if oldOK && nextOK && before == after {
			continue
		}
		left, right := "none", "none"
		if oldOK {
			left = planText(before)
		}
		if nextOK {
			right = planText(after)
		}
		parts = append(parts, planText(key)+": "+left+" → "+right)
	}
	return strings.Join(parts, ", ")
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func secretEnvPhrase(env map[string]string) string {
	keys := envKeys(env)
	parts := make([]string, len(keys))
	for i, key := range keys {
		parts[i] = planText(key) + "←" + planText(env[key])
	}
	return strings.Join(parts, ", ")
}

func secretOrNone(env map[string]string) string {
	if len(env) == 0 {
		return "none"
	}
	return secretEnvPhrase(env)
}

func volumePhrase(volumes []catalog.Volume) string {
	parts := make([]string, len(volumes))
	for i, v := range volumes {
		item := planText(v.Name) + "→" + planText(v.Target)
		if v.ReadOnly {
			item += " (ro)"
		}
		parts[i] = item
	}
	return strings.Join(parts, ", ")
}

func volumeOrNone(volumes []catalog.Volume) string {
	if len(volumes) == 0 {
		return "none"
	}
	return volumePhrase(volumes)
}

func filePhrase(files []catalog.FileMount) string {
	parts := make([]string, len(files))
	for i, f := range files {
		parts[i] = planText(f.File) + "→" + planText(f.Target)
	}
	return strings.Join(parts, ", ")
}

func fileOrNone(files []catalog.FileMount) string {
	if len(files) == 0 {
		return "none"
	}
	return filePhrase(files)
}

func argvPhrase(args []string) string {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = planText(arg)
	}
	return strings.Join(parts, " ")
}

func argvOrNone(args []string) string {
	if len(args) == 0 {
		return "none"
	}
	return argvPhrase(args)
}

func textOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return planText(s)
}

func memoryPhrase(mb *int) string {
	if mb == nil {
		return "none"
	}
	return strconv.Itoa(*mb) + " MB"
}
