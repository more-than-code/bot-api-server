# Agent protocol v1 (bot-agent ↔ bot-api-server), phase 1 contract

**Status:** Frozen for wave 1 (2026-10-13), v1.0.1 (redaction regex fix, tag-type clarification). Source of truth: umbrella `docs/contracts/agent-protocol-v1.md`. Copies in each repo's `docs/contracts/` must not be edited. Report problems in `NOTES.md`.
**Design:** umbrella `docs/design-bot-agent-deploy.md` §3.2 and §4.

## Transport

- The agent dials `BOT_AGENT_SERVER_URL` (must start with `wss://`; `ws://` is accepted only when `BOT_AGENT_INSECURE_DEV=1` is set and the host is `127.0.0.1` or `localhost`, for tests).
- Before enrollment the upgrade has no `Authorization` header. After enrollment it sends `Authorization: Bearer <credential>`.
- Text frames, one JSON object each, UTF-8, at most 1 MiB (the receiver closes on oversize). Every object has `"v": 1` and `"type"`. Unknown `type` values are logged by type only and ignored.
- Server path: `/agent/v1/ws`.
- Heartbeat: the agent sends `{"v":1,"type":"ping","ts"}` every `heartbeat_sec` (20) and the server answers `pong`. The server marks the host offline after 60 s with no ping, measured by arrival time at the server.
- Agent reconnect backoff: 1 s, doubling, capped at 30 s, ±20 % jitter. It resets after a `hello_ok`.

## Enrollment

Agent → server, first frame on an unauthenticated connection:

```json
{"v":1,"type":"enroll","join_token":"<plaintext>","hostname":"pi4","agent_version":"0.1.0",
 "os":"linux","arch":"arm64","always_on":true}
```

Server → agent:

```json
{"v":1,"type":"enrolled","host_id":"<uuid>","credential_id":"<uuid>","credential":"<plaintext>"}
```

Then the server closes the socket (normal close 1000). The agent atomically rewrites its env file (removing `BOT_AGENT_JOIN_TOKEN`, adding `BOT_AGENT_HOST_ID`, `BOT_AGENT_CREDENTIAL_ID`, and `BOT_AGENT_CREDENTIAL`) and reconnects with Bearer.

- `hostname` is 1–63 characters `[a-z0-9-]`. If the project already has a host with that name, the server appends `-2`, `-3`, ….
- The join token must be unexpired, unused, and unrevoked. On success the server marks it used in the same transaction that creates the host and the credential. Credential: 32 random bytes as base64url (43 characters); only its SHA-256 is stored.
- A bad token gets `{"v":1,"type":"error","error_code":"unauthenticated","message":"..."}` and then a close.

## Hello

Agent → server, first frame on a Bearer connection:

```json
{"v":1,"type":"hello","host_id":"<uuid>","credential_id":"<uuid>","agent_version":"0.1.0",
 "os":"linux","arch":"arm64","capabilities":["metrics","probe"],"services":[Discovered, ...]}
```

`Discovered` = `{"name","kind","ports":[int],"systemd_unit":string|null,"systemd_scope":"system"|"user"|null,"container_name":null,"process_name","pid"}`
- `kind` is `systemd` (a unit found from `/proc/<pid>/cgroup`) or `process`. `container` is phase 2.
- `name` is the unit name without `.service` for systemd services, otherwise `process_name`. It must match `^[a-z0-9][a-z0-9._-]{0,62}$`; the agent lowercases it and replaces invalid characters with `-`.
- Only processes with a listening TCP socket (`0.0.0.0`, `::`, or `127.0.0.1`, any port) are reported. Several processes in one unit merge into one entry with the union of their ports.

Server → agent:

```json
{"v":1,"type":"hello_ok","host_id":"<uuid>","heartbeat_sec":20,"server_time":"<RFC3339>","config":Config}
```

`Config` = `{"metrics_interval_sec":10,"process_interval_sec":60,"health_checks":[{"id","service","protocol":"http|tcp","port","path","interval_sec","expect_status_min","expect_status_max"}]}`

- The server may send `{"v":1,"type":"config_update","config":Config}` at any time. The agent replaces its config.
- The agent clamps `metrics_interval_sec` to 5–60, `process_interval_sec` to 30–300, and each check's `interval_sec` to 30–300. It caps the list at 50 checks and drops any check whose `port` is not currently in that service's discovered `ports` (it logs the check id).
- The agent sends `{"v":1,"type":"services","services":[Discovered,...]}` whenever its discovered set changes (checked every 60 s). The server upserts these as `source='discovered'` (and never downgrades a `declared` row) and updates `last_seen_at`.
- Errors before `hello_ok`: `error_code` `unauthenticated` (bad credential), or `forbidden` (credential revoked, or `host_id` does not match the credential). Then the socket closes. On `forbidden` the agent does not retry until it restarts. On `unauthenticated` it backs off to 30 s and keeps retrying.

## Metrics ingest

Agent → server:

```json
{"v":1,"type":"metrics","batch_id":"<uuid>","samples":[{"m":"cpu","t":"<RFC3339>","tags":{...},"f":{...}}]}
```

Server → agent: `{"v":1,"type":"metrics_ack","batch_id":"<uuid>"}`. It is sent only after the samples are committed, and also for a replayed `batch_id` (which is not inserted twice). A batch holds at most 5000 samples. The agent sends a batch every `metrics_interval_sec`.

| `m` | tags (allowlist) | fields (allowlist, types) |
|---|---|---|
| `cpu` | `cpu` (only `cpu-total`) | `usage_user`, `usage_system`, `usage_idle`, `usage_iowait` (float %) |
| `mem` | — | `total`, `available`, `used` (int bytes), `used_percent` (float) |
| `disk` | `path`, `fstype` | `total`, `used`, `free` (int bytes), `used_percent` (float) |
| `diskio` | `name` (whole disks only: `mmcblkN`, `nvmeXnY`, `sdX`, `vdX`) | `read_bytes`, `write_bytes` (int, cumulative) |
| `net` | `interface` (not `lo`) | `bytes_recv`, `bytes_sent` (int, cumulative) |
| `system` | — | `load1`, `load5`, `load15` (float), `uptime` (int s), `n_cpus` (int) |
| `temp` | `sensor` | `celsius` (float) |
| `process` | `pid`, `process_name`, `user`, `cmdline` (≤ 1024 characters, raw), `service` (optional Discovered name) | `cpu_usage` (float, irix: 100 = one core), `memory_rss` (int bytes), `memory_usage` (float %), `num_threads` (int), `started_at` (RFC3339 string) |
| `health` | `service`, `check_id`, `protocol`, `port` | `result` (`success`, `status_mismatch`, `timeout`, `connection_refused`, `error`), `http_status` (int or null), `latency_ms` (float) |

- **Tag values are always JSON strings** (e.g. health `port` is `"8080"`); field types are as in the table. *(v1.0.1 clarification.)*
- The server rejects (logs, and does not ack) a batch containing an unknown `m`, tag, or field, or a wrong type. It ignores `host_id` claims inside samples; the host always comes from the connection.
- Processes: each `process_interval_sec`, the top 20 by `cpu_usage` plus the top 20 by `memory_rss` (union), plus every process of a discovered service.
- `disk` covers real filesystems only (no tmpfs, overlay, squashfs, proc, sysfs, devtmpfs).

## Tasks (phase 1 kinds)

Server → agent:

```json
{"v":1,"type":"task","task_id":"<uuid>","host_id":"<uuid>","kind":"host_snapshot|probe_health",
 "service":"<name>|null","expires_at":"<RFC3339>","timeout_sec":15,"spec":{...}}
```

The agent checks these in order. The first failure gives `{"v":1,"type":"task_reject","task_id","error_code"}` and nothing runs:
1. `host_id` equals its own (`wrong_host`).
2. Now (corrected by `server_time` − local time at `hello_ok`) is before `expires_at` (`expired`).
3. `kind` is `host_snapshot` or `probe_health` (`forbidden`).
4. `spec` keys are from the kind's closed set (`bad_spec`).
5. For `probe_health`: `service` is discovered locally (`unknown_service`) and `spec.port` is in its current ports (`forbidden`).

Specs:
- `host_snapshot`: `{}`.
- `probe_health`: `{"protocol":"http|tcp","port":int,"path":string|null,"expect_status_min":int,"expect_status_max":int}`. The target is always `127.0.0.1:<port>`. HTTP is a `GET`, does not follow redirects, and reads at most 64 KiB of body (discarded). The timeout is `min(timeout_sec, 10)` s.

Agent → server: `{"v":1,"type":"task_result","task_id","state":"succeeded|failed|timed_out","error_code":null|string,"payload":{...}}`. The agent resends it on reconnect until it gets `{"v":1,"type":"task_ack","task_id"}`. Phase 1 results are kept in memory only.

## Payloads

```jsonc
Snapshot {"sampled_at","cpu_percent","mem":{"total","used","available","used_percent"},
          "disks":[{"path","total","used","used_percent"}],"load":[l1,l5,l15],
          "temp_celsius":number|null,"uptime_sec","top":[{"pid","process_name","user","cmdline","cpu_usage","memory_rss"}]} // top ≤ 20 by cpu
ProbeResult {"service","protocol","port","path","result","http_status":int|null,"latency_ms","checked_at"}
```

## Redaction

The agent never logs a frame body, token, or credential. It truncates `cmdline` to 1024 characters and replaces any match of `(?i)(authorization|api[_-]?key|password|passwd|token|secret|credential)(\s*[=:]\s*|\s+)(bearer\s+)?\S+` with `$1=[REDACTED]` before sending. *(v1.0.1, 2026-10-13: the v1.0 pattern missed `Authorization: Bearer x` and `token: x`.)*

## v1.0.2 amendments (2026-10-14)

These take precedence over the sections above.

1. **Redaction (agent, and server on ingest and snapshots).** Apply in this order:
   - URL userinfo: `(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@` → `$1[REDACTED]@`.
   - Then keywords: `(?i)([A-Za-z0-9_.-]*(?:authorization|api[_-]?key|password|passwd|token|secret|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*|\s+)(bearer\s+)?("[^"]*"|'[^']*'|\S+)` → `$1=[REDACTED]`.

   Required test vectors (input → output):

   | Input | Output |
   |---|---|
   | `Authorization: Bearer abc123` | `Authorization=[REDACTED]` |
   | `AWS_SECRET_ACCESS_KEY=AKIAxyz` | `AWS_SECRET_ACCESS_KEY=[REDACTED]` |
   | `password="two words" next` | `password=[REDACTED] next` |
   | `postgres://app:s3cret@127.0.0.1/db` | `postgres://app:[REDACTED]@127.0.0.1/db` |
   | `redis://localhost:6379` | unchanged |
   | `/usr/bin/node build` | unchanged |
   | `postgres: joe tour_agent 127.0.0.1(5000) idle` | unchanged |

   Over-redaction such as `--token-file=[REDACTED]` is accepted.
2. **`task_reject` code `busy`.** The agent runs host, expiry, kind, and spec checks before queuing. It runs at most 4 tasks and holds at most 16 waiting; beyond that it sends `task_reject` with `busy`. The server maps `busy` to `unavailable` (503).
3. **Outbound frame size.** The agent splits `metrics` batches so that each serialized frame is ≤ 1 MiB, as well as ≤ 5000 samples.
4. **Join token via stdin.** `bot-agent init --server <url> --join-token-stdin` reads the token from stdin (one line, trimmed). The `--join-token <tok>` argv form is removed, because argv is visible in `ps`.

## v1.0.3 amendment (2026-10-14)

The URL-userinfo pattern is replaced by `(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]*:)[^\s/]*@` → `$1[REDACTED]@`. The keyword pattern is unchanged.

Additional required vectors:

| Input | Output |
|---|---|
| `redis://:s3cret@127.0.0.1:6379` | `redis://:[REDACTED]@127.0.0.1:6379` |
| `https://user:p@ss@host/db` | `https://user:[REDACTED]@host/db` |
| `ssh://git@host:22/repo` | unchanged |
| `http://127.0.0.1:3031/health` | unchanged |
| `a://u:p@h/x b://c:d@e/y` | `a://u:[REDACTED]@h/x b://c:[REDACTED]@e/y` |

## v1.1 discovered owner (2026-10-14, additive)

`Discovered` gains `"user": string | null`: the username of the uid that owns the listening socket. Read it from the `uid` column of `/proc/net/tcp{,6}` and resolve it via `/etc/passwd`; use the numeric uid as a string if the name is unknown. No privilege needed. It is sent for mapped and unmapped listeners alike. Servers that predate v1.1 ignore it. Servers that know v1.1 store it as `services.owner_user`.

## v1.2 periodic services (2026-10-14, approved by Joe)

Supersedes the "whenever its discovered set changes (checked every 60 s)" sentence in the session section, additively.

1. The agent sends `services` when its discovered set changes (checked every 60 s), **and also at least every 300 s while connected even if the set is unchanged**. A changed set is sent at once and restarts the 300 s timer.
2. The server treats every `services` message as proof that the listed services are present at that time and updates their `last_seen_at`. A service missing from the message is not changed; its `last_seen_at` stays at the last time it was reported.
3. No new fields. Servers that predate v1.2 already upsert `last_seen_at` on every message.

## v1.3 programs (2026-10-15, approved spec `docs/spec-project-catalog.md`, wave 1; additive)

### Host policy

`/etc/bot-agent/runner.toml`, written by the host's administrator, never by deploybot:

```toml
enabled = true
run_as = ["joe"]                  # never root, never uid < 1000
dirs = ["/home/joe/workspace"]    # realpath of a program dir must be inside one of these
exec_allow = ["/usr/bin/node", "/usr/bin/npm", "/usr/bin/pnpm"]
allow_shell = false
max_programs = 20
```

- Unknown keys, a file not owned by root, or a file writable by group or others → the policy is **invalid** and treated as `enabled = false` (the agent logs why, without the file content).
- The agent reads it at start-up only. A policy change needs an agent restart.
- A `run_as` entry that is `root`, does not exist, or has uid < 1000 is dropped (logged).

### Hello

`capabilities` gains `"programs"` when the policy is valid and `enabled`. `hello` gains `"programs": {"enabled":bool,"run_as":[string],"allow_shell":bool,"policy_hash":"<hex sha256 of the file bytes>"}` whenever the file exists (invalid → `enabled:false`, empty `run_as`); it is absent when there is no file. Paths, `dirs` and `exec_allow` are never sent.

### Task kinds

`kind` may also be `program_start`, `program_stop`, `program_restart`, `program_status`, `program_logs`. `service` is null. Specs (closed key sets):

- `program_start`: `{"project":"<slug>","entry":"<name>","dir","exec","args":[...],"shell":bool,"run_as","env":{...},"restart":"on-failure"|"no"}`
- `program_stop`, `program_restart`, `program_status`: `{"project","entry"}`
- `program_logs`: `{"project","entry","lines":1..1000}`

Additional agent checks, after the v1.0 checks 1–4 (the first failure gives `task_reject` with that code; nothing runs):
5. The policy is valid and `enabled` (`policy_denied`).
6. For `program_start`: the same field rules as api-v1 v1.6 (`bad_spec`); `run_as` is in the policy; `shell=true` only if `allow_shell`; `dir` resolves (realpath, symlinks followed) inside a `dirs` entry; `exec` resolves as below (`policy_denied` for any of these).
7. Starting would exceed `max_programs` running deploybot units (`policy_denied`).

**exec resolution:** a bare name resolves to `<dir>/node_modules/.bin/<name>` if that exists and its realpath is inside `dir`, else to the `exec_allow` entry with that basename. An absolute path must equal an `exec_allow` entry or have a realpath inside `<dir>/node_modules/.bin/`'s target tree within `dir`. Shell mode always uses `/bin/sh`, which must be in `exec_allow`.

**Unit:** `deploybot-<project>-<entry>.service`, a system unit. The agent never edits units itself; it asks the helper.

**Results** (`task_result.payload`):
- start, stop, restart, status → `ProgramStatus {"unit","active_state","sub_state","main_pid","started_at","ports"}`. start and restart succeed once systemd reports the unit `active` (or `activating` after 10 s); a unit that fails within 10 s → `failed`, `error_code` `start_failed`, payload = ProgramStatus plus `"lines"`: the last 50 log lines (redacted). stop of a unit that does not exist succeeds.
- logs → `ProgramLogs {"unit","lines","truncated"}`: newest `lines` journal lines of the unit, each redacted with the v1.0.1 regex and truncated to 2048 chars, total ≤ 64 KiB (`truncated` when cut).
- A helper refusal → `failed` with `error_code` `policy_denied` and no payload detail beyond a fixed reason code.

### Owned services

`Discovered` gains `"owner": {"kind":"program","project":"<slug>","entry":"<name>"} | null`. For each running deploybot unit the agent asks the helper for its listening sockets (by cgroup) and reports one Discovered entry with `name` = the entry, `kind` = `systemd`, `systemd_unit` = the unit name, `systemd_scope` = `system`, the exact `ports`, and `owner` set. Those sockets are not also reported as unmapped listeners. Old servers ignore `owner`.

### Local helper (not on the wire; between bot-agent and root)

`/usr/local/libexec/bot-agent-runner`, root:root 0755, built from the bot-agent repo. The only privilege bot-agent has is one sudoers line:

```
bot-agent ALL=(root) NOPASSWD: /usr/local/libexec/bot-agent-runner
```

- Invoked as `sudo -n /usr/local/libexec/bot-agent-runner <verb>` with one JSON object on stdin (≤ 64 KiB) and one JSON object on stdout. Verbs: `start`, `stop`, `restart`, `status`, `logs`, `sockets`, `list`. Anything else → refusal.
- The helper re-reads and re-validates the policy and **every** field on every call, exactly as checks 5–7 above, independently of the agent. It acts only on units whose name matches `^deploybot-[a-z0-9-]{1,64}-[a-z0-9-]{1,48}\.service$` and that it created (its unit files carry `X-Deploybot-Project=` and `X-Deploybot-Entry=`).
- **start** writes `/run/systemd/system/<unit>` (root 0644) with: `User=<run_as>`, `Group=<run_as's primary group>`, `WorkingDirectory=<realpath dir>`, `ExecStart=` the resolved exec and args, each argument quoted for systemd (`%` doubled, `$` doubled, quotes and backslashes escaped), `Environment=HOME=<run_as home>` and `Environment=PATH=<dir>/node_modules/.bin:/usr/local/bin:/usr/bin:/bin`, `EnvironmentFile=/run/bot-agent/env/<unit>.env` (root 0600, the plain env), `Restart=`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=full`, `ProtectHome=read-only`, `ReadWritePaths=<realpath dir>`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`; then `systemctl daemon-reload` and `systemctl restart <unit>`. Units are transient across reboot (`/run`).
- **stop** stops the unit and removes its unit and env files. **logs** runs `journalctl -u <unit> -n <lines> -o cat --no-pager`. **sockets** reads the unit's cgroup (`/sys/fs/cgroup/system.slice/<unit>/cgroup.procs`) and maps its pids' socket inodes to `/proc/net/tcp{,6}` listeners. **list** returns the deploybot units with their project and entry.
- The helper never runs a shell except `/bin/sh -c <line>` for an entry in shell mode on a policy with `allow_shell = true`, and never logs env values.

### v1.3.1 amendments (2026-10-15, from the wave 1 review; helper transport approved by Joe)

1. **Helper transport (replaces sudo and the sudoers line).** The agent's own unit (`NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`) makes a sudo child powerless, and that sandbox stays. The helper is a root **socket-activated** service instead:
   - `bot-agent-runner.socket`: `ListenStream=/run/bot-agent-runner.sock`, `SocketUser=root`, `SocketGroup=bot-agent`, `SocketMode=0660`, `Accept=yes`.
   - `bot-agent-runner@.service`: `User=root`, `StandardInput=socket`, `StandardOutput=socket`, `ExecStart=/usr/local/libexec/bot-agent-runner serve-conn`, `RuntimeMaxSec=60`.
   - One request per connection: `{"verb":"start|stop|restart|status|logs|sockets|list","request":{...}}` (≤ 64 KiB, newline-terminated), one JSON response, then close.
   - The helper checks the peer with `SO_PEERCRED`: the uid must be the `bot-agent` account's uid, else a refusal. The socket mode also limits callers to root and group `bot-agent`.
   - There is **no sudoers line**. Rollback: `systemctl disable --now bot-agent-runner.socket`, or `enabled = false`.
2. **Who checks paths.** The agent cannot see `/home`, so it performs only the policy and lexical checks (5, 7, and the non-filesystem parts of 6: field rules, `run_as` listed, shell gate, exec name syntax). The **helper** performs every filesystem check (realpath of `dir`, exec resolution) and refuses with `policy_denied`; the agent returns that as `task_result` `failed` / `policy_denied`.
3. **Environment denylist:** the agent and the helper both refuse the api-v1 v1.6.1 item 2 keys (`bad_spec` in the agent, `policy_denied` in the helper).
4. **Program unit hardening adds** `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`.
5. **start/restart truth:** a non-zero `systemctl` exit is a failure (`start_failed`), and success needs the unit's `ActiveEnterTimestampMonotonic` to be newer than before the call.

### v1.3.2 note (2026-10-15, approved spec `docs/spec-services-view.md`)

1. A `services` frame (and `hello.services`) is sent only from a complete discovery: the process scan succeeded and, when the program policy is enabled, the owned-program lookup through the helper succeeded. If either fails, the agent sends no `services` frame for that cycle and keeps its previous canonical set and send time, so the next successful cycle compares against the last set actually sent. The server treats every received set as the full set (api-v1 v1.7 item 2).
2. At start, `hello.services` comes from the first discovery; if that discovery is incomplete, `hello.services` is an empty list **and** the server must not apply presence to it. To make that explicit, `hello` gains `"services_complete": bool` (absent = `true` for older agents). The server applies api-v1 v1.7 item 2 to `hello.services` only when it is `true`.

## v1.4 images (2026-10-15, approved spec `docs/spec-catalog-images.md` rev 3, wave 2a; additive)

### Host policy additions

```toml
images = ["ghcr.io/joe-and-his-friends/*"]  # reference patterns; empty or absent = no image entries
projects = ["mohiguide"]                     # project slugs this host may run containers for
max_containers = 20                          # 1..200, default 20
allow_public_ports = false
```

- Pattern match: the reference is parsed and normalised (registry host lowercase, `docker.io` and `library/` made explicit). A pattern is `<host>/<path>` where `*` matches exactly one path component; the host is matched literally; there is no other wildcard.
- `projects` entries: `^[a-z0-9][a-z0-9-]{0,63}$`. Invalid key or value → the whole policy is invalid (as v1.3).

### Hello

`hello.programs` gains `"images": bool` (policy valid, `enabled`, `images` and `projects` non-empty) and `"docker": bool` (the helper answered `container_list` at start-up). Patterns and project lists are not sent.

### Task kinds

`image_deploy`, `image_rollback`, `image_remove`, `image_start`, `image_stop`, `image_restart`, `image_status`, `image_logs`. `service` is null. Specs (closed key sets):

- `image_deploy`: `{"project","entry","spec":ImageSpec (api-v1 v1.8, as stored: inline env as written, env_sets and secret_env as references — v1.4.1),"env":{KEY:value} (the resolved, merged environment; the only place resolved values travel),"registry_auth":{"host","username","token"}|null,"force":bool,"spec_hash"}`
- `image_rollback`: as `image_deploy`, plus `"digest":"sha256:<64 hex>"` (the image is pulled by that digest).
- `image_remove`, `image_start`, `image_stop`, `image_restart`, `image_status`: `{"project","entry"}`
- `image_logs`: `{"project","entry","lines":1..2000}`

`env` values and `registry_auth.token` are secrets: the agent never logs them, never stores them beyond the task, and adds every value (raw, base64 std/url, and JSON-escaped forms, for values ≥ 6 bytes) to the redaction set for that task's logs and results, in addition to the v1.0.1 regex. Task records keep `env` key names only.

Agent checks after v1.0 checks 1–4: policy valid and `images` (`policy_denied`); `project` in `projects` (`policy_denied`); ImageSpec field rules as api-v1 v1.8 (`bad_spec`); image matches a pattern (`policy_denied`).

### Sequences and results

`task_result.payload` = `{"outcome":Outcome,"digest":string|null,"exit_code":int|null,"status":ImageStatus,"lines":[string]}` for deploy/rollback (lines = last ≤ 50 redacted log lines), `{"status":ImageStatus}` for start/stop/restart/status/remove, `{"container","lines","truncated"}` for logs (same caps as program logs). `status` = `succeeded` for outcomes `succeeded|unchanged`, `failed` otherwise with `error_code` = the outcome.

**Service deploy:** `image_pull` → if the current container (labels match) runs this digest with this `spec_hash` and not `force` → `unchanged` → else `container_deploy` → wait healthy (the service's configured health checks, else state `running` with `restart_count` 0 for `healthy_after_sec`, polled every 2 s) → `succeeded`; unhealthy → `container_rollback` → `rolled_back` (or `rollback_failed`).
**Job deploy:** `image_pull` → `container_remove` of the job container if present → `container_deploy` (restart `no`) → poll `container_status` every 2 s until `exited` or `timeout_sec` → exit 0 `succeeded`, else `failed` with `exit_code`; timeout → `container_stop` → `timeout`.
**Rollback:** the service sequence with `ref = <repo>@<digest>`.

### Discovery

Each discovery cycle calls `container_list`. A container with all four `dev.deploybot.*` labels whose `host` equals this host and `project` is in `projects` → `Discovered {"name":<entry>,"kind":"container","container_name","ports","image_digest","owner":{"kind":"image","project","entry"}}`. Every other container → `Discovered {"name":<container name without leading "/">,"kind":"container","container_name","ports","image_digest":null,"owner":null}`; its published host ports are not also reported as unmapped listeners. `kind` gains the value `container`. If `container_list` fails while `images` is true, discovery is incomplete (v1.3.2).

### Local helper: image verbs (same socket and framing as v1.3.1)

`RuntimeMaxSec` of `bot-agent-runner@.service` becomes **900**; `ReadWritePaths=` gains `/var/run/docker.sock`. Program verbs keep the helper-wide flock; image verbs take `flock` on `/run/bot-agent/image-<project>-<entry>.lock` for the whole verb. The helper talks to Docker Engine API `/v1.47` over `/var/run/docker.sock` with its own client; **nothing from the request is forwarded as raw HTTP**.

Request validation in the helper, before any Docker call (refusal = `{"error":"policy_denied"|"bad_spec"|"conflict"|"docker_unavailable"}`): `project` ∈ `projects`; `entry` `^[a-z0-9][a-z0-9-]{0,47}$`, not ending `-` or `-prev`; volume names `^[a-z0-9][a-z0-9-]{0,47}$`; every ImageSpec rule of api-v1 v1.8; `registry_auth` fields without CR/LF/NUL; Engine URL path segments built with path escaping; containers addressed by the full id from the helper's own lookup.

| Verb | Request | Response |
|---|---|---|
| `image_pull` | `{"project","ref","registry_auth"?}` | `{"digest","image_id"}` |
| `container_deploy` | `{"project","entry","spec","env","digest","spec_hash"}` | `{"container_id"}` |
| `container_rollback` | `{"project","entry"}` | `{"container_id"}` |
| `container_remove`, `container_start`, `container_stop`, `container_restart` | `{"project","entry"}` | `{"status":ImageStatus}` |
| `container_status` | `{"project","entry"}` | `{"status":ImageStatus,"spec_hash"}` |
| `container_logs` | `{"project","entry","lines"}` | `{"container","lines","truncated"}` |
| `container_list` | `{}` | `{"items":[{"id","name","state","ports":[{"host_ip","host_port","container_port"}],"digest","labels":{dev.deploybot.* only}}]}` |

Rules (normative; spec rev 3 §4.1 and §12 in full):
1. **Pull:** parse `ref`; must match `images`; Engine call `POST /images/create` with exactly `fromImage=<name>&tag=<non-empty tag>` or `fromImage=<name>@sha256:<digest>`; header `X-Registry-Auth` (base64url JSON `{"username","password","serveraddress"}`) only when `registry_auth.host` equals the parsed registry host. Response digest = the repo digest for that registry.
2. **Labels:** the helper sets `dev.deploybot.owner=bot-agent`, `dev.deploybot.host=<first 16 hex of sha256(/etc/machine-id)>` (the helper does not read the agent's credential file), `dev.deploybot.project`, `dev.deploybot.entry`, and `dev.deploybot.spec_hash`. Any verb that mutates or reads logs/status of `<project>-<entry>` or `<project>-<entry>-prev` first resolves each name; a container under either name whose owner/host/project/entry labels differ → `conflict`, nothing touched.
3. **Create body** contains exactly: `Image` (`<repo>@sha256:<64 hex>`, repo re-matched against `images`), `Cmd`, `Entrypoint`, `Env`, `Labels`, `ExposedPorts`, `User` (if set, rules as api-v1 v1.8 item 10), `HostConfig.{PortBindings (HostIp "127.0.0.1", or "0.0.0.0" only when allow_public_ports and the port is public), Mounts, RestartPolicy, NetworkMode "deploybot-<project>", CgroupnsMode "private", PidsLimit 1024, Memory and MemorySwap (= memory_mb MiB) when set}`, `NetworkingConfig.EndpointsConfig{"deploybot-<project>":{"Aliases":[<entry>]}}`. Nothing else, including no empty values of other fields.
4. **Volumes:** `Mounts[i] = {"Type":"volume","Source":"<project>-<name>","Target","ReadOnly"}` only. Before create: inspect each; missing → `POST /volumes/create` with driver `local`, no options, labels owner/host/project; then (whether created or existing) require driver `local`, empty options and label `project=<project>` → else `bad_spec`/`conflict`.
5. **Network:** inspect `deploybot-<project>`; missing → create with driver `bridge`, no options, default IPAM, labels owner/host/project; then require driver `bridge` and those labels → else `conflict`.
6. **Deploy order (service):** under the entry lock: check labels (rule 2) → remove `-prev` (stop if running, `DELETE ?v=1`) → stop current, rename to `-prev` → ensure network and volumes → create → start. **Rollback:** remove the current (`v=1`), rename `-prev` back, start. **Job:** remove the existing job container, create, start. `max_containers` counts deploybot-labelled containers on the host (including `-prev` and jobs); a create beyond it → `policy_denied`.
7. **Projections:** responses never contain env, command, entrypoint, mounts, host config, graph-driver data, log config or labels other than `dev.deploybot.*`. There is no image-inspect or container-inspect verb.
8. Logs: `GET /containers/{id}/logs?stdout=1&stderr=1&tail=<lines>&timestamps=0` (never `follow`), demultiplexed, each line redacted (v1.0.1 regex) and cut to 2048 chars, total ≤ 64 KiB.

### v1.4.1 amendment (2026-10-16, Joe approved; from the wave 2a round-2 security review)

1. In `image_deploy` and `image_rollback`, `spec` is the entry's ImageSpec **as stored**: inline `env` as the owner wrote it, `env_sets` and `secret_env` as references (`<set>.<KEY>`). Resolved values travel **only** in the top-level `env`, so each secret value appears once per frame. The helper refuses resolved values in `spec.secret_env` (`bad_spec`).
2. The API computes the marshalled task frame size before sending. A frame over the agent frame limit is never sent: the request fails with `bad_request` "the resolved environment is too large for one task", and the agent connection stays open. Neither side closes a connection because of an oversized frame the API built.

### v1.4.2 amendment (2026-10-16, Joe approved; from the wave 2a agent security reviews)

1. `container_logs` request: `{"project","entry","lines","redact"?:[string]}`. `redact` is optional, ≤ 64 values, each 6–4096 bytes, no NUL. The helper removes every value in raw, base64 std, base64 url (padded and raw) and JSON-escaped form from each raw log line **before** the v1.0.1 regex and the 2048-char cut, and never logs or returns the list.
2. The agent sends the task's exact set (env values and the registry token) in `redact` for the log tail it puts in `image_deploy` / `image_rollback` results. `image_logs` tasks carry no values, so their `container_logs` call has no `redact`.

## v1.5 managed files (2026-10-16, approved spec `docs/spec-catalog-files.md` rev 1, wave 2b; additive)

### Task specs

- `image_deploy` and `image_rollback` gain a top-level `"files":[{"name","target","content","secret":bool}]` (default `[]`), in the order of `spec.files`. `spec.files` stays as stored (`[{"file","target"}]`, api-v1 v1.9). Resolved content travels **only** in the top-level `files`. The agent refuses a task whose `files` names and targets do not equal `spec.files` one for one, or that breaks api-v1 v1.9 rules 1–2 and 13, with `task_reject` `bad_spec`, as for every other ImageSpec rule failure (v1.4).
- Task records and logs keep `name` and `target` only, never content.

### Exact-value redaction

For every **secret** file of the task, the agent adds to that task's exact set:
1. the whole content, when it is 6–4096 bytes;
2. every line of the content, trimmed of surrounding whitespace, of 16–4096 bytes;
3. when the content parses as JSON: every string value of 16–4096 bytes, and every trimmed line of 16–4096 bytes inside a string value (so the lines of a PEM key held in a JSON field are covered).

Plain files add nothing. The set applies as in v1.4.2 (results, log lines, and the `redact` list of `container_logs`).

**Only secret values (Joe 2026-10-16, from the pi3 mirror):** `image_deploy` and `image_rollback` gain `"secret_keys":[KEY]`: the keys of the top-level `env` whose resolved value comes from an env-set key with `is_secret: true` (through `env_sets` or `secret_env`, after the v1.8 item 12 precedence; a key overridden by inline `env` is not secret). The exact set is: the `env` values of `secret_keys`, the registry token, and the secret-file items above. Inline `env`, plain env-set keys and plain files are not redacted. The API sends `secret_keys` (possibly `[]`) **only to a host whose `hello.programs.files` is true**; to an older agent it omits the key, because a v1.4 agent refuses unknown keys. When `secret_keys` is absent, every `env` value joins the set, as in v1.4.

**Structured fields are never redacted:** in `task_result` payloads the exact set and the v1.0.1 regex apply only to free text: `lines`, log `lines`, and error messages. `outcome`, `digest`, `exit_code` and every `status` field (`container`, `state`, `exit_code`, `restart_count`, `started_at`, `finished_at`, `digest`, `ports`) are passed as the helper returned them. The helper builds them from labels, names and the Engine, never from env values.

`container_logs` `redact` limits become: ≤ **2048** values, each 6–4096 bytes, total ≤ **512 KiB**, no NUL.

### Hello

`hello.programs` gains `"files":bool`: true when this agent and its helper support v1.5 files. The API refuses a deploy of an entry with non-empty `files` to a host whose `files` is not true (`bad_request` "this host's agent does not support files"), before any task is sent.

### Local helper

1. **Request size:** image verbs accept requests up to **2 MiB**; program verbs keep 64 KiB.
2. **Units (host security files, Joe reviews before install):** `bot-agent-runner@.service` gains `StateDirectory=bot-agent-runner` and `StateDirectoryMode=0700`. `bot-agent.service` `InaccessiblePaths=` gains `-/var/lib/bot-agent-runner`.
3. **`container_deploy`** request gains `"files":[{"name","target","content"}]` (default `[]`); `container_status` response gains `"files_hash":string` (`""` when the container has none).
4. **Store:** `/var/lib/bot-agent-runner/files/`. One **slot** directory per container: `<project>-<entry>`, `<project>-<entry>-prev`, and the transient `<project>-<entry>.new`. Each file is `<slot>/<name>`.
5. **Writes:** the helper opens the store with `O_DIRECTORY|O_NOFOLLOW` and works only with `openat`/`mkdirat`/`renameat`/`unlinkat` relative to directory handles, never through a path string. Slot directories are created mode 0700, owner 0:0. Each file is created `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY`, written, `fsync`ed, set to mode 0444, owner 0:0. Then the slot directory is `fsync`ed.
6. **Checks before every use** (`fstatat` with `AT_SYMLINK_NOFOLLOW`): the store and each slot are directories owned by 0:0 with mode 0700 exactly; each file is a regular file owned by 0:0, mode 0444, link count 1; nothing else is in a slot. Any mismatch → `bad_spec`, and the deploy stops before any container is touched.
7. **Mounts:** for each file, `HostConfig.Mounts` gains `{"Type":"bind","Source":"/var/lib/bot-agent-runner/files/<slot>/<name>","Target","ReadOnly":true}`. No `BindOptions`, no other bind mounts. `Source` is built by the helper only.
8. **Label:** when `files` is non-empty, the container gets `dev.deploybot.files_hash` = hex SHA-256 of the lines `<name>:<hex sha256 of content>\n`, sorted by name. With no files the label is absent.
9. **Service deploy order** (extends v1.4 rule 6, under the entry lock): remove a leftover `.new` slot and any slot whose container no longer exists → write the `.new` slot (when `files` is non-empty) → check labels → remove `-prev` and its slot → stop the current container, rename it to `-prev` and its slot to `-prev` → rename `.new` to the current slot → ensure network and volumes → create → start.
10. **Rollback:** remove the current container and its slot, rename `-prev` and its slot back, start. **Job:** remove the existing job container and its slot, write the slot, create, start. **`container_remove`:** removes the container and its slot.
11. **Unchanged:** the agent reports `unchanged` only when digest, `spec_hash` and `files_hash` all match (the agent computes the expected `files_hash` from the task's `files` by rule 8; `""` when none).
12. Projections (v1.4 rule 7) never contain file content, slot paths or mounts.


## v1.5.1 persistent program units (2026-10-17, approved spec `docs/spec-program-persistence.md` rev 1; helper behaviour only, no wire change)

Replaces the v1.3 "Units are transient across reboot (`/run`)" rule. Frames, verbs, reasons and `hello` are unchanged.

1. **Paths:** **start** writes the unit to `/etc/systemd/system/<unit>` (root 0644), the env file to `/var/lib/bot-agent-runner/programs/<unit>.env` (root 0600) and the spec to `/var/lib/bot-agent-runner/programs/<unit>.json` (root 0600). The `programs` directory is root 0700. The unit's `EnvironmentFile=` is `/var/lib/bot-agent-runner/programs/<unit>.env`.
2. **`[Install]`:** the unit ends with `[Install]` and `WantedBy=multi-user.target`.
3. **start / restart:** write the files, `systemctl daemon-reload`, `systemctl enable <unit>`, `systemctl restart <unit>`. A restart of a unit already in `/etc/systemd/system` does not rewrite it: the stored spec is rechecked against the policy, then `daemon-reload`, `enable`, `restart`. Every value rendered into a unit (start, and the restart that moves a unit from `/run`) is refused when it contains CR, LF or NUL (and `dir`, `exec` and the run_as home also when they contain `\`, a systemd line continuation), before any write. A unit with a drop-in directory (`/etc/systemd/system/<unit>.d` or `/run/systemd/system/<unit>.d`) is refused (`io_error`) before `enable`; the helper never creates or removes drop-ins. A failed start leaves no file behind. A failed restart of an `/etc` unit keeps it enabled (reply `start_failed`, `fresh:false`).
4. **stop:** `systemctl disable <unit>`, `systemctl stop <unit>`, remove the unit, env and spec files, `systemctl daemon-reload`. A stopped program leaves no file behind. If a file cannot be removed (a symlink or non-regular file is never unlinked), the helper still removes every other file and reloads, then replies `io_error`.
5. **Ownership:** unchanged rules (`unitNameRE`, the `X-Deploybot-*` markers, `O_NOFOLLOW`, atomic writes). A unit in `/etc/systemd/system` with our name but without our markers is never written, enabled, disabled or removed (reason `not_created`, unchanged).
6. **Upgrade from `/run`:** when start, restart or stop finds our unit (markers checked) in `/run/systemd/system`, the helper writes the `/etc` copy first (start, restart) and then removes the `/run` unit and its `/run/bot-agent/env/<unit>.{env,json}` in the same verb. The move completes only once `enable` succeeded: if `daemon-reload` or `enable` fails on a restart, the helper removes the `/etc` copy it wrote and keeps the `/run` files (the program keeps running). `/etc/systemd/system` wins over `/run/systemd/system`, as in systemd's unit search path: with our unit in `/etc`, a foreign same-name file in `/run` is left untouched and does not block the verb; a foreign file in `/etc` always refuses (`not_created`). `status`, `logs`, `sockets` and `list` look in `/etc/systemd/system` first, then `/run/systemd/system`; `max_programs` counts every owned unit once.
7. **Units (host security file, Joe reviews before install):** `bot-agent-runner@.service` `ReadWritePaths=` gains `/etc/systemd/system`. `bot-agent.service` is unchanged (v1.5 already hides `/var/lib/bot-agent-runner`).

## v1.5.2 rollback to the kept container (2026-10-17, Joe: "Swap with -prev", from the pi3 wave 2b live check)

A content-only change could not be rolled back: `image_rollback` redeployed the target digest with the current spec and files, so it reported `unchanged`. Additive.

1. **`container_status`** response gains `"prev":{"digest":string|null,"spec_hash":string,"files_hash":string}|null`: the labels of the entry's `-prev` container, `null` when there is none. No other `-prev` data is returned.
2. **`image_rollback`, service:** when `prev` is not null and `prev.digest` equals the task's `digest`, the agent does not pull or deploy. It calls `container_rollback` (v1.5 rule 10: the current container and its slot are removed, `-prev` and its slot are renamed back and started), then waits healthy exactly as a rollback deploy does (the entry's health checks, else `healthy_after_sec`, 30 s when that is 0). Healthy → `succeeded`; not healthy → `failed` (there is no further generation to return to). The result `digest` is `prev.digest`. The previous spec and file content come back with that container.
3. Otherwise `image_rollback` is unchanged (v1.4/v1.5: pull by digest, deploy with the task's spec and current `files`). If the first `container_status` is refused, the refusal is the result (rule 4); if it fails in transport, the outcome is `failed` and nothing is pulled.
4. **Refusal codes:** a helper refusal for a bad file slot or store (v1.5 rule 6) is `bad_spec`, and the `max_containers` cap is `policy_denied`; the agent maps both to outcome `forbidden_spec` (`task_result.error_code` = `forbidden_spec`). They are never reported as a bare `failed`.
5. **Diagnostics:** the helper writes one line per refusal to the journal (`bot-agent-runner: refuse <verb> <reason>`; `StandardError=journal` in its unit, because stdout is the socket), and the agent logs a failed helper call as task kind, verb and reason or `transport`. Neither logs request data.
6. **Overlapping projects (Joe 2026-10-17, from the wave 2b files review):** container and slot names are `<project>-<entry>`, which is ambiguous when one listed project is another plus `-` (`acme` and `acme-web`). The policy is then not valid for images: `images:false` in `hello.programs`, every image verb is refused `policy_denied`, and the helper logs `bot-agent-runner: policy: overlapping projects <a> <b>` once per connection. Program verbs are unaffected.

## v1.7 secret previews in task output (2026-10-20, approved spec `docs/spec-env-editing.md` rev 1; no wire change)

1. In image task output (log tails, error text) the agent replaces an env secret value from the task (raw, base64 and JSON-escaped forms, values of at least 6 bytes as before) with `preview(v)`: the first 4 runes followed by `…` when `v` has at least 16 runes, otherwise `••••`.
2. Secret-file pieces keep `[REDACTED]`. The keyword rule is unchanged.
3. The task frame is unchanged. An agent before v1.7 keeps writing `[REDACTED]`; the API accepts both.
