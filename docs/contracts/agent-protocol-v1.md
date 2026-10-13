# Agent protocol v1 (bot-agent ↔ bot-api-server), phase 1 contract

**Status:** Frozen for wave 1 (2026-10-13). Source of truth: umbrella `docs/contracts/agent-protocol-v1.md`. Copies in each repo's `docs/contracts/` must not be edited. Report problems in `NOTES.md`.
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

The agent never logs a frame body, token, or credential. It truncates `cmdline` to 1024 characters and replaces any match of `(?i)(authorization|api[_-]?key|password|passwd|token|secret|credential)[=: ]\S+` with `$1=[REDACTED]` before sending.
