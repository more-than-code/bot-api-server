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
