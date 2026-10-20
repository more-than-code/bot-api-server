# Spec: Project catalog and agent-run programs (phase 2b, D37)

**Tier:** 3. It adds a new agent capability with host privileges, a new API and console surface, a DB migration, and a contract change in the API and agent protocol.
**Status:** Approved 2026-10-14 (Joe: "yes, approve both specs"). **Amended 2026-10-15** (Joe chose "Socket-activated helper"): the helper is a root socket-activated systemd service reached over `/run/bot-agent-runner.sock` (root:bot-agent 0660, SO_PEERCRED check) instead of sudo + a sudoers line, because the agent's sandbox (NoNewPrivileges, empty capability set) makes a sudo child powerless; see agent-protocol v1.3.1. **Implementation is sequenced after the MCP OAuth wave, together with phase 2** (Joe).
**Requested by:** Joe, 2026-10-14:
- "What if we allow the agent to run the program, e.g. npm run …"
- "It's project's responsibility to run program safely. The owner can control what program, image to run per member."
- AskUserQuestion answers: run as allowlisted accounts per host; the host owner also approves on shared hosts; placed after MCP OAuth, with phase 2.

**Builds on:** phase 2 containers (§5.2 deploy, §5.3 redeploy, §5.4 secrets, D16, D17, D25, D30, D31), shared hosts (D34), D35 (token scope), and the MCP OAuth wave (which ends D36).

## 1. Goal

1. A project owner curates a **catalog** of named things members may run: programs (a command in a directory, run as an allowed account) and images (container image patterns).
2. The owner decides, per entry, which roles or members may run, stop, restart and read logs.
3. bot-agent runs catalog entries on hosts that allow it. **Free-form commands are never accepted.**
4. Anything started through Deploybot appears as a service with its **exact name**, without CAP_SYS_PTRACE.

## 2. Threat model (what the design must hold)

| Threat | Control |
|---|---|
| A project member runs something the owner did not approve | Members pick entries; they cannot edit them. The server checks the entry permissions on every action. |
| A sharing project runs programs on a host it does not own | A one-time approval per (entry, host) by an admin of the **host's owning project**. Approval is bound to a hash of the entry and is voided when the entry changes. |
| **bot-api-server or its DB is compromised** and rewrites catalogs | A **root-owned local host policy** (`/etc/bot-agent/runner.toml`) limits what can ever run on that host: whether programs are enabled at all, the allowed run-as accounts (never root or uid < 1000), allowed directories, allowed executables, and allowed image registries. The API cannot change it. |
| **bot-agent is compromised**, e.g. via a parser bug | bot-agent stays unprivileged. The only privileged step is a small **root-owned helper** reached through one exact `sudoers` line. The helper re-validates every request against the local policy, so a compromised agent can do no more than the policy allows. Polkit alone is not enough: it can restrict unit *names* but not what a unit runs, so an agent allowed to start `deploybot-*` transient units could start one as root. |
| An AI agent acts in one step | The D25 two-step confirmation for every MCP run, stop, restart and redeploy. |
| Secrets leak through program environment or logs | Secrets use D31 `secret_env` references. The helper writes them to a root-owned 0600 credentials file read by systemd. Log redaction applies to program logs as to container logs (D19). |

## 3. Design

### 3.1 Catalog (bot-api-server)

- `app.catalog_entries`: id, project_id, name (1–48, `[a-z0-9-]`, unique per project), kind `program | image`, spec (JSON, closed schema below), spec_hash, created_by, updated_at.
- **Program spec:**
  - `dir` (absolute path), `exec` (absolute path, or a command name resolved inside `dir`'s `node_modules/.bin` or from the policy's `exec_allow`), `args` (≤ 32 strings, no shell);
  - `run_as` (a username), `env` (plain; refused when a key matches the secret regex), `secret_env` (references, D31);
  - `port` (expected listener), `restart` (`on-failure` | `no`).
  - **No shell, no `sh -c`, no pipes.** `npm run dev` is `exec: "npm", args: ["run","dev"]`.
- **Image spec:** identical to the phase 2 deploy spec (§5.2) apart from `container_name`, which is derived as `<project-slug>-<entry>`.
- **Permissions:** `app.catalog_permissions` (entry_id, subject = a role `viewer|admin|owner` or a user_id, actions ⊆ {run, stop, restart, logs, redeploy}). The default for a new entry is owner and admin all actions, viewer `logs`.
- **Who edits:**
  - the catalog and its permissions: **project owner** only;
  - host approvals on shared hosts: an **admin+ of the host's owning project**, in `app.catalog_host_approvals` (entry_id, host_id, spec_hash, approved_by, approved_at).

### 3.1a Creating a service (console), amendment 2026-10-14

Joe: "support create service for project, where user can type raw cmds like npm run xxx, form based docker run".

The project **Catalog** tab has **New service** (owner), with two kinds.

**Program: a typed command line.**
- Fields: name; host(s); working directory; **command** (one text line, e.g. `npm run dev -- --port 3031`); run as (a select from that host's policy `run_as`); expected port; environment (key/value rows); secret environment (D31 refs); restart.
- The command line is split **on the server** into argv with POSIX shell-word rules: quotes and backslash escapes are honoured, and nothing else is.
- The stored entry is `exec` + `args`, and the form shows the parsed argv back to the user before saving ("will run: `npm` `run` `dev` `--` `--port` `3031`").
- **Shell features are refused** with a clear message:
  - pipes `|`, `&&`, `||`, `;`
  - redirects `>` `<`
  - `$VAR` / `$(…)` / backticks
  - globs
  - `cd …`, which belongs in the working directory field.

  Leading `KEY=value` words are moved into the environment rows.
- **Optional shell mode:** a "Run through a shell" checkbox stores `shell: true` and runs `/bin/sh -c '<line>'`. It is allowed **only** if the host policy sets `allow_shell = true` (default `false`). The console shows it as a risk ("anything in this line runs as <run_as>"), it is audited, and the helper refuses it on hosts without `allow_shell`.
- The helper re-checks everything as before: `exec` is resolved in `dir` (`node_modules/.bin`) or in `exec_allow`, `dir` sits under `dirs`, and `run_as` is in `run_as`.

**Container: a form-based docker run.**
- The fields map 1:1 to the phase 2 image spec (§5.2):
  - image (with a tag or digest);
  - ports as rows of host port → container port, with bind `127.0.0.1` by default and `0.0.0.0` only if the policy allows;
  - environment, secret environment;
  - named volumes as rows of volume name → target;
  - restart policy (`no`, `on-failure`, `unless-stopped`).
- The container name is derived as `<project-slug>-<name>`.
- **Paste a `docker run` command** to prefill the form. The server parses `-p`, `-e`, `--env-file` (refused), `-v`/`--mount` (named volumes only; bind mounts refused), `--name` (ignored, derived), `--restart` and the image. Anything else is listed back as "not supported" rather than silently dropped. Refused outright, as in the closed spec: `--privileged`, `--cap-add`, `--device`, `--network host`, `--pid host`, `-u 0` / root.
- A live preview shows the equivalent `docker run …` line built from the form, read-only.
- The image must match the host policy's `images` patterns. The form warns early, and the agent enforces it.

**Both kinds:**
- After saving, the owner sets who may run, stop, restart and read logs (§3.1 permissions).
- **Save & run** on a chosen host goes through the normal action path: permission, then shared-host approval, then policy, then MCP confirmation where relevant.
- Validation happens in the API. The console only previews.
- Tests cover the command-line splitter with a table of accepted and refused lines, and the `docker run` parser with a table of flags.

### 3.2 Host policy (`/etc/bot-agent/runner.toml`, root:root 0644)

```toml
enabled = true                        # false: the host refuses every program and image task
run_as = ["joe"]                      # never root, never uid < 1000
dirs = ["/home/joe/workspace"]        # realpath of the program dir must be under one of these (symlinks resolved)
exec_allow = ["/usr/bin/node", "/usr/bin/npm", "/usr/local/bin/pnpm"]  # plus <dir>/node_modules/.bin/*
images = ["ghcr.io/joe/*"]            # image entries; empty = images not allowed
max_programs = 20
allow_shell = false                   # true: catalog entries may use shell mode (/bin/sh -c); default false
```

The policy is reported in `hello` capabilities, as a hash plus the `enabled` flag only, so the console can show "this host does not allow programs" without exposing paths.

### 3.3 Execution (bot-agent and the helper)

- **Helper** `/usr/local/libexec/bot-agent-runner`:
  - Go, from the bot-agent repo, root-owned 0755, invoked as `sudo -n /usr/local/libexec/bot-agent-runner <verb>` with JSON on stdin. One sudoers line, NOPASSWD, for that exact path.
  - Verbs: `start`, `stop`, `restart`, `status`, `logs`, `sockets`, `list`.
  - Every verb validates against `runner.toml` and acts only on units named `deploybot-<project-slug>-<entry>.service`.
- **start:**
  1. Validate `run_as`, `dir` (realpath, inside `dirs`), `exec` and `args`.
  2. Write `/run/systemd/system/deploybot-…service` (root 0644) with `User=<run_as>`, `WorkingDirectory=`, `ExecStart=` (argv, no shell), `Restart=`, `EnvironmentFile=/run/bot-agent/creds/<unit>.env` (root 0600), and hardening: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=full`, `ProtectHome=read-only` plus `ReadWritePaths=<dir>`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`.
  3. `systemctl daemon-reload`, then `start`.
- **logs:** `journalctl -u <unit>` with the same limits and redaction as container logs (64 KiB cap).
- **sockets:** root lists the listening sockets of processes in that unit's cgroup. This gives the exact port ↔ unit mapping, so owned programs need no CAP_SYS_PTRACE and no guessing.
- **Images:** they use the phase 2 container path (Docker proxy, §5.2–5.4), checked against the policy's `images` patterns.
- **Discovery:** owned programs and images appear as `source='owned'`, with `name` = the catalog entry name (exact). This extends `Discovered` additively with `owner: {"kind":"program"|"image","entry":"<name>"}`.

### 3.4 Actions and API (phase 2 surface)

- `GET|POST|PUT|DELETE /v1/projects/{id}/catalog[/{entry}]` (owner) and `…/{entry}/permissions` (owner).
- `POST /v1/hosts/{id}/catalog-approvals` (owning-project admin+).
- `POST /v1/projects/{id}/catalog/{entry}/run` with `{host_id}`, plus `stop`, `restart`, `logs`.
- Each action checks, in order:
  1. entry permission for the caller;
  2. host relation (owner, or a `deploy` share with a valid approval);
  3. host policy compatibility (`hello` capabilities);
  4. MCP confirmation (D25).

  Each check is audited (`catalog.*`, `program.run|stop|restart`), and every action requires an idempotency key.
- **MCP tools** (after OAuth): `list_catalog`, `run_entry`, `stop_entry`, `restart_entry`, `entry_logs`. The mutating ones use the two-step confirm.
- **Console:**
  - a project **Catalog** tab (owner edits; members see what they may run);
  - Run, Stop and Restart as icon-only row actions;
  - a host approval queue for owning-project admins.

## 4. Contract diff (summary; full text is frozen at implementation time)

- **api-v1 v2.0 (phase 2):** the catalog, permission, approval and action routes above; new audit actions; `Service.owner` for owned programs and images.
- **agent-protocol v2.0:**
  - task kinds `program_start`, `program_stop`, `program_restart`, `program_logs`, `program_status`;
  - capability `programs` with `policy_hash` and `enabled`;
  - `Discovered.owner`.
- The agent refuses program tasks when the policy is missing or disabled (`forbidden`).

## 5. Acceptance criteria

1. With no `runner.toml`, or `enabled=false`, every program task is refused (`forbidden`) and the console says why.
2. The helper refuses each of these even if the API asks:
   - run_as root or uid < 1000;
   - a dir outside `dirs`, including through a symlink;
   - an exec not allowed;
   - a shell metacharacter used as a command;
   - a unit name outside the prefix.

   A table test covers these, plus a pi1 live check.
3. A member without `run` on an entry gets `forbidden`, and a viewer can read logs only if granted.
4. A sharing project's entry cannot run on a shared host until approved. Editing the entry voids the approval.
5. Running `tra-backend` from the catalog on pi1:
   - starts `deploybot-<slug>-tra-backend.service` as `joe`;
   - the service appears as **tra-backend** with port 3031, matched through `sockets`;
   - stop and restart work;
   - logs are capped and redacted.
6. MCP mutating tools require the confirm step. Every action is audited.
7. bot-agent itself gains no capability; the only privilege is the single sudoers line for the helper.
8. Gates pass in every repo. Helper tests run as non-root with a fake systemctl.

## 6. Rollback

- Per host: set `enabled=false` (immediate) or remove the sudoers line. Running units keep running until they are stopped by hand: `systemctl stop 'deploybot-*'`.
- Global: revert the API, agent and console; hand-run the down migration for the catalog tables.

## 7. Decided questions (Joe, 2026-10-14)

1. **Existing systemd units are not adopted.** pi1's `tra-backend`, `tra-webapp` and the other user units are **re-created as catalog entries**. The old user units are stopped and disabled by hand once each entry runs; there is no `adoptable_units` in the policy.
2. **Code updates stay out of scope.** A `git pull` / build step for programs is not part of phase 2b. Programs run whatever is in `dir`.
3. **No unprivileged naming guess.** Services not started through Deploybot keep the `port <n> · <user>` default and can be renamed (v1.2). Exact names come from catalog entries.

## 7a. Sequencing (Joe, 2026-10-14)

**Programs first.**
- **Wave 1:** program entries end to end:
  - the catalog, entry permissions and shared-host approvals;
  - `runner.toml` and the root helper;
  - the `program_*` task kinds;
  - run, stop, restart and logs in the console and MCP;
  - the D25 two-step confirm for MCP mutating tools;
  - audit;
  - owned-program discovery with exact names.
- **Wave 2:** image entries, built with the rest of phase 2 (custom Docker proxy, deploy and adopt, redeploy with rollback, encrypted `secret_env`).
- Until wave 2 lands, image entries are refused at creation with `not_implemented`, and the console hides the container form.

## 8. Delegation

After the MCP OAuth wave:
- Grok workers per repo:
  - agent and helper (bot-agent);
  - API (catalog, approvals, actions);
  - console (Catalog tab, approvals);
  - MCP (tools).
- Two security review passes on the helper and the agent.
- A live check on pi1 with Joe's `runner.toml`.
