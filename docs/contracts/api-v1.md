# bot-api-server REST API v1 (phase 1 contract)

**Status:** Frozen for wave 1 (2026-10-13). Source of truth: umbrella `docs/contracts/api-v1.md`. Each repo gets a copy at `docs/contracts/api-v1.md`, and copies must not be edited. Report a contract problem in `NOTES.md` instead of changing it.
**Design:** umbrella `docs/design-bot-agent-deploy.md` (§2 permissions, §3 auth, §6 server).
**Consumers:** bot-console (BFF server routes), bot-mcp-server, the `deploybot login` CLI.

## Conventions

- Base path `/v1`. JSON in and out (UTF-8). All times are RFC3339 UTC strings. All ids are UUID strings.
- Envelope on every response: `{"code": "<string>", "msg": "<human text>", "payload": <object|null>}`.

| `code` | HTTP |
|---|---|
| `ok` | 200 (201 on create) |
| `bad_request` | 400 |
| `unauthorized` | 401 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `conflict` | 409 |
| `unavailable` | 503 (host offline or asleep) |
| `timeout` | 504 (agent did not answer within 30 s) |
| `error` | 500 |

  The device token endpoint also uses `authorization_pending`, `slow_down`, `expired_token`, and `access_denied`, all with HTTP 400.
- **Auth:** `Authorization: Bearer <session token>` on every route except those marked public. A missing, expired, or unknown token, or a disabled user, gives `unauthorized`.
- **Permission failures:** `forbidden` when the user is a member but the role is too low. `not_found` when the user is not a member of the project that owns the resource, so the server does not reveal that it exists.
- **Lists:** `payload = {"items": [...], "next_cursor": "<opaque>|null"}`. Optional query `limit` (1–200, default 50) and `cursor`.
- `GET /health` (public, no `/v1`) → `{"status": "ok"}`, no envelope.
- **Roles:** `owner` > `admin` > `viewer`. "viewer+" means any member.

## Objects

```jsonc
User      {"id","email","name","avatar_url"}
Project   {"id","name","slug","role","created_at"}          // role = caller's role
Member    {"user_id","email","name","role","created_at"}
JoinToken {"id","host_name_hint","created_by","created_at","expires_at","used_at","used_by_host_id","revoked_at"}
Host      {"id","project_id","name","node_type","os","arch","always_on","agent_version",
           "status","last_seen_at","enrolled_at","revoked_at"}
           // status: "online" | "offline" | "asleep" (offline + always_on=false) | "revoked"
Service   {"id","host_id","name","source","kind","ports","systemd_unit","systemd_scope",
           "container_name","process_name","first_seen_at","last_seen_at","health"}
           // source: discovered|declared|owned ; kind: container|systemd|process
           // health: {"status":"up|down|unknown","last_checked_at","latency_ms"} (unknown when no check or stale > 2 min)
HealthCheck {"id","service_id","protocol","port","path","interval_sec",
             "expect_status_min","expect_status_max","enabled"}
             // protocol http|tcp; path required for http (starts with "/"), null for tcp
             // interval_sec 30..300 (default 60); expect 200..399 default
AuditEntry {"id","at","actor_user_id","via","project_id","host_id","service_id",
            "action","decision","task_id","result","error_code","detail"}
```

## Auth (public unless noted)

| Method | Path | Body / query | Payload |
|---|---|---|---|
| GET | `/v1/auth/google/start` | query `redirect_uri` (must be in server allowlist `BOT_API_OAUTH_REDIRECT_URIS`) | `{"authorize_url","state"}` |
| POST | `/v1/auth/google/callback` | `{"code","state","redirect_uri"}` | `{"token","expires_at","user":User}`. The session kind is `console`. |
| POST | `/v1/auth/signout` | — (session) | `null` (deletes this session) |
| GET | `/v1/me` | — (session) | `{"user":User,"identities":[{"provider","email"}],"projects":[Project]}` |
| POST | `/v1/auth/device/code` | `{"client_name"}` (1–100 chars) | `{"device_code","user_code","verification_uri","verification_uri_complete","expires_in":600,"interval":5}` |
| POST | `/v1/auth/device/token` | `{"device_code"}` | `{"token","expires_at"}` (session kind `mcp`, 30 days), or one of the four device codes |
| GET | `/v1/auth/device/{user_code}` | — (session) | `{"user_code","client_name","expires_at","status":"pending|approved|denied|expired"}` |
| POST | `/v1/auth/device/{user_code}/approve` | — (session) | `null` |
| POST | `/v1/auth/device/{user_code}/deny` | — (session) | `null` |

- `user_code`: 8 characters from `BCDFGHJKLMNPQRSTVWXZ`, shown as `XXXX-XXXX`. Input is case-insensitive and the hyphen is optional.
- `verification_uri` = `BOT_API_DEVICE_VERIFICATION_URI` (the console `/device` page). `verification_uri_complete` = that URI plus `?code=XXXX-XXXX`.
- Polling faster than `interval` returns `slow_down` and adds 5 s to that device code's interval.
- `state` and the PKCE verifier are kept server-side for 10 minutes and are single use. Only Google `email_verified=true` is accepted (`forbidden` otherwise).

## Projects and members

| Method | Path | Role | Body | Payload |
|---|---|---|---|---|
| POST | `/v1/projects` | session | `{"name"}` (1–80) | Project (creator = owner), 201 |
| GET | `/v1/projects` | session | — | list of Project the caller belongs to |
| GET | `/v1/projects/{id}` | viewer+ | — | Project |
| PATCH | `/v1/projects/{id}` | owner | `{"name"}` | Project |
| DELETE | `/v1/projects/{id}` | owner | — | `null` (soft delete; its hosts' credentials are revoked) |
| GET | `/v1/projects/{id}/members` | viewer+ | — | list of Member |
| POST | `/v1/projects/{id}/members` | admin+ | `{"email","role":"admin|viewer"}` | Member, 201. `not_found` if no user has that email yet; `conflict` if already a member. |
| PATCH | `/v1/projects/{id}/members/{user_id}` | admin+ | `{"role":"admin|viewer"}` | Member. The owner's role cannot be changed here (`forbidden`). |
| DELETE | `/v1/projects/{id}/members/{user_id}` | admin+, or self | — | `null`. The owner cannot be removed. |
| POST | `/v1/projects/{id}/transfer-ownership` | owner | `{"user_id"}` (an existing member) | `null`. The old owner becomes admin. |

`slug` is derived from the name (lowercase, `[a-z0-9-]`, unique; a `-2`, `-3`, … suffix is added on collision) and does not change on rename.

## Join tokens and hosts

| Method | Path | Role | Body | Payload |
|---|---|---|---|---|
| POST | `/v1/projects/{id}/join-tokens` | admin+ | `{"host_name_hint"?: string, "expires_in_sec"?: 300..604800 (default 86400)}` | `JoinToken` + `"token"` (plaintext, **only here**) + `"install_command"`, 201 |
| GET | `/v1/projects/{id}/join-tokens` | admin+ | — | list of JoinToken (never the token) |
| DELETE | `/v1/projects/{id}/join-tokens/{token_id}` | admin+ | — | `null` (sets `revoked_at`) |
| GET | `/v1/projects/{id}/hosts` | viewer+ | — | list of Host |
| GET | `/v1/hosts/{id}` | viewer+ | — | Host |
| DELETE | `/v1/hosts/{id}/credential` | admin+ | — | `null` (revokes all credentials; the agent connection is closed with `forbidden`) |

`install_command` is exactly `sudo -u bot-agent bot-agent init --server '<BOT_API_AGENT_WS_URL>' --join-token '<token>'`.

## Services, health, metrics

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/v1/hosts/{id}/services` | viewer+ | list of Service (not paginated; at most 500) |
| GET | `/v1/services/{id}` | viewer+ | Service + `"health_checks":[HealthCheck]` |
| PUT | `/v1/services/{id}/health-checks` | admin+ | Body `{"checks":[HealthCheck without id/service_id]}`. Replaces the whole set (max 10). Each `port` must be in `Service.ports`, otherwise `bad_request`. Pushed to the agent as `config_update`. |
| GET | `/v1/hosts/{id}/metrics` | viewer+ | Query `m` ∈ `cpu,mem,disk,diskio,net,system,temp`; `from`, `to` (RFC3339; default last 1 h; span ≤ 31 days); `step` (seconds, 10–3600; default chosen so there are ≤ 500 points). Payload `{"m","from","to","step","series":[{"name","unit","points":[["<t>", <number|null>], ...]}]}`. |
| GET | `/v1/hosts/{id}/processes` | viewer+ | Latest process sample (≤ 90 s old): `{"sampled_at","items":[{"pid","process_name","user","cmdline","service_id","cpu_usage","memory_rss","memory_usage","num_threads","started_at"}]}`. Query `sort=cpu|memory` (default cpu), `limit` ≤ 200. |
| GET | `/v1/services/{id}/health` | viewer+ | Query `from`, `to`. `{"items":[{"t","check_id","result","http_status","latency_ms"}]}`. Newest first, ≤ 1000. |

Series names per `m`:

| `m` | Series (`unit`) |
|---|---|
| `cpu` | `usage_percent` (%) = 100 − `usage_idle` |
| `mem` | `used_percent` (%), `used` (bytes), `total` (bytes) |
| `disk` | `used_percent` (%) for path `/` |
| `diskio` | `read_bps`, `write_bps` (bytes/s; counter deltas; negative deltas dropped) |
| `net` | `rx_bps`, `tx_bps` (bytes/s; all interfaces except `lo`; negative deltas dropped) |
| `system` | `load1`, `load5`, `load15` (`""`), `uptime` (s) |
| `temp` | `celsius` (°C) |

## Live calls (phase 1)

| Method | Path | Role | Body | Payload |
|---|---|---|---|---|
| POST | `/v1/hosts/{id}/snapshot` | viewer+ | — | Snapshot (agent protocol §Payloads) |
| POST | `/v1/services/{id}/probe` | viewer+ | `{"check_id"}`, or `{"protocol","port","path"}` (same validation as HealthCheck) | ProbeResult (agent protocol §Payloads) |

The server waits up to 30 s for the agent. An offline or asleep host gives `unavailable` immediately; no task is queued. Every live call is written to `audit_log` (`via` = `console` or `mcp`, taken from the session kind).

## Audit

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/v1/projects/{id}/audit` | admin+ | list of AuditEntry, newest first |
