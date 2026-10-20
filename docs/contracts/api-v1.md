# bot-api-server REST API v1 (phase 1 contract)

**Status:** Frozen for wave 1 (2026-10-13), v1.0.1 (clarifications at the end). Source of truth: umbrella `docs/contracts/api-v1.md`. Each repo gets a copy at `docs/contracts/api-v1.md`, and copies must not be edited. Report a contract problem in `NOTES.md` instead of changing it.
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
| `rate_limited` | 429 (v1.5) |
| `not_implemented` | 501 (v1.6) |

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
| POST | `/v1/auth/device/token` | `{"device_code"}` | `{"token","expires_at"}` (session kind `mcp`, 30 days; **since v1.4** kind `mcp_access`, see oauth-v1 §9), or one of the four device codes |
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

## v1.0.1 clarifications (2026-10-13)

Raised by the wave 1 workers and decided by the orchestrator. They take precedence over anything above that conflicts.

1. **Audit ids:** `AuditEntry.id` is a decimal string (from `bigserial`), not a UUID. All other ids are UUIDs.
2. **Services list:** `GET /v1/hosts/{id}/services` uses the list envelope `{"items":[...],"next_cursor":null}`. It never paginates (≤ 500 items).
3. **Health history:** `GET /v1/services/{id}/health` returns `{"items":[...]}` with no cursor.
4. **One-sided windows:** `from` only → `to` = now. `to` only → `from` = `to` − 1 h. `from` ≥ `to` → `bad_request`.
5. **Live call outcomes:**
   - The agent answered with `succeeded` → `ok` with the payload. A probe whose `result` is not `success` is still `ok`: the probe ran.
   - The agent answered `failed` → `error` (HTTP 500), with the agent's payload if present.
   - The agent answered `timed_out` → `timeout` (504).
   - `task_reject`: `forbidden` → `forbidden`; `unknown_service` → `not_found`; `bad_spec` → `bad_request`; `wrong_host`/`expired` → `error`.
6. **Token formats:** session tokens, join tokens, device codes, and host credentials are 43-character unpadded base64url. OAuth `state` is 43-character base64url. `user_code` is as stated above.
7. **Probe/health-check `path`:** must start with `/`, must not start with `//`, ≤ 512 bytes, and contain no `@ \ ? #`, spaces, or control characters.
8. **Server-side redaction:** the server applies the agent-protocol redaction regex again to `cmdline` on ingest and on snapshot payloads (defense in depth).

## v1.0.2 amendments (2026-10-14)

1. **`install_command`** is now exactly `printf '%s' '<token>' | sudo -u bot-agent bot-agent init --server '<BOT_API_AGENT_WS_URL>' --join-token-stdin`. `printf` is a shell builtin, so the token never appears in any process argv.
2. Agent `task_reject` `busy` → `unavailable` (503).
3. Server-side redaction uses the agent-protocol v1.0.2 patterns.

## v1.1 shared hosts (2026-10-14, approved spec `docs/spec-shared-hosts.md`)

These take precedence over earlier sections. Permission matrix: spec §4.

1. **Host** gains `"relation": "owner" | "shared"` and `"share_level": "metrics" | "deploy" | null` (null when `relation` = owner). `project_id` stays the owning project.
2. **Service** gains `"project_id"` (the project the service belongs to; defaults to the host's owning project).
3. **`GET /v1/projects/{id}/hosts`** returns hosts owned by project `id` **and** hosts shared with it. Owned hosts come first, then shared ones, each sorted by name.
4. **Filtering:**
   - Owner-project members see everything.
   - A `metrics` share: host, status, and metrics are allowed; services, processes, snapshot, probe, and health history are `forbidden` (403).
   - A `deploy` share: services and processes are filtered to the sharing project's own services (processes whose `service_id` belongs to those services); probe, health history, and (admin+) health-check edits apply only to its own services (`forbidden` otherwise); snapshot is `forbidden`.
   - No relation: `not_found` (404).
   - A user in both the owner and a sharing project gets the owner relation.
5. **New endpoints:**
   - `GET /v1/hosts/{id}/shares` (owner admin+) → `{"items":[{"project_id","project_name","level","created_by","created_at"}]}` (not paginated).
   - `PUT /v1/hosts/{id}/shares/{project_id}` (owner admin+), body `{"level":"metrics"|"deploy"}`: creates or updates the share; 200 with the share object. The caller must also be a member (any role) of `project_id`, otherwise `not_found`. Sharing with the owning project itself → `bad_request`.
   - `DELETE /v1/hosts/{id}/shares/{project_id}` (owner admin+, or admin+ of `project_id`) → 200 `null`. `conflict` (409) if that project still has services on the host, unless the query has `reassign=owner`, which moves those services to the owning project in the same transaction.
6. **Audit actions:** `host.share`, `host.share_update`, `host.unshare` (with `detail` naming the project and level).
7. **Project deletion** cascades its shares. Services of a deleted sharing project on others' hosts move to the owner. Deleting the owning project revokes its hosts' credentials (unchanged), and their shares go too.


## v1.1.1 host-level visibility (2026-10-14, Joe: "processes per host should be visible to all members")

Supersedes v1.1 item 4 for processes and snapshot only.

1. **`GET /v1/hosts/{id}/processes`** returns the full, unfiltered latest sample to every user with any relation to the host: owner-project members (any role) and members of any sharing project (any share level, any role). No `service_id` filtering. No relation: `not_found` (404), unchanged.
2. **`POST /v1/hosts/{id}/snapshot`** is allowed for the same set of users.
3. Unchanged: services list, service get, probe, health history and health-check edits follow v1.1 item 4 (a `metrics` share gets 403; a `deploy` share is limited to its own project's services). `service_id` on a process row may name a service the caller cannot open; clients must treat a 403/404 on that service as normal.

## v1.2 service names (2026-10-14, Joe: "service name is meaningless")

1. **Service** gains `"display_name": string | null` (set by people; 1–64 printable characters, trimmed) and `"owner_user": string | null` (the account owning the listening socket, as reported by the agent).
2. **`PATCH /v1/services/{id}`**, body `{"display_name": "<name>" | null}`, sets or clears the name; returns the updated Service. Permission = the *edit* capability of spec-shared-hosts §4 (owner admin+, or a `deploy`-share admin for its own services). Audit action `service.rename` (detail: old → new). `display_name` is unique per host, case-insensitive; a duplicate is `conflict`.
3. The name survives rediscovery: services stay keyed by (host_id, discovered `name`), and `display_name` is never overwritten by the agent.
4. Suggested label for clients: `display_name` → else the discovered `name` unless it is `port-<n>` → else `port <n> · <owner_user>` (or `port <n>` when `owner_user` is null).

## v1.3 project services (2026-10-14, approved spec `docs/spec-project-services.md`)

These take precedence over earlier sections for the routes they name. v1.2 is implemented in the same release.

1. **`GET /v1/projects/{id}/services`**: the caller must be a member (any role) of project `id`; otherwise `not_found`.
   - **Rows:** every service on hosts owned by `id` (whatever the service's `project_id`), plus services with `project_id = id` on hosts shared with `id` at level `deploy`. Services with `project_id = id` on a host shared with `id` at level `metrics` are not returned.
   - **Row:** `Service` (with the v1.1 and v1.2 fields) plus `"host_name"`, `"host_status"`, and `"project_name"` (the name of the service's project).
   - **Query:**
     - `q`: case-insensitive substring over `display_name`, `name`, `kind`, `host_name`, `owner_user`, and ports as decimal text. Trimmed; empty means no filter; more than 100 characters → `bad_request`. `%`, `_` and `\` match literally.
     - `host_id`: a UUID of a host that the row rules reach for this project; otherwise `bad_request`.
     - `sort` ∈ `name` (by `lower(coalesce(display_name, name))`), `host` (host name), `kind`, `status` (`health.status`: up, down, unknown; then name), `last_seen` (`last_seen_at`). Default `name`.
     - `dir` ∈ `asc`, `desc`. Default `asc`; for `sort=last_seen` the default is `desc`.
     - `limit` 1–200, default 50.
     - `cursor` (opaque).
     - Any other value → `bad_request`.
   - **Ordering:** ties are broken by `id` ascending. `NULL`s sort last in both directions.
   - **Payload:** `{"items":[...], "next_cursor": "<opaque>"|null, "prev_cursor": "<opaque>"|null, "total": <int>}`. `total` counts every matching row and is recomputed per request.
   - **Cursors:** a cursor is bound to the `q`, `host_id`, `sort`, and `dir` it was issued for. Reusing it with different values → `bad_request` "cursor does not match query". Cursors are offset-based: a row inserted or deleted between pages may be skipped or repeated.
2. `GET /v1/hosts/{id}/services` is unchanged apart from the v1.2 fields on each row.
3. Every row returned by (1) is a service the caller may read with `GET /v1/services/{id}`; (1) never widens access.

## v1.4 OAuth for MCP (2026-10-14, approved spec `docs/spec-mcp-oauth.md`)

The full contract is `docs/contracts/oauth-v1.md` (frozen). Changes to this API:

1. **Audience rule:** on every `/v1/*` route, a token of session kind `mcp_access` or `mcp_refresh` → 401 `invalid_token` (oauth-v1 §8). `api_delegated` tokens act as their user; audit rows they cause carry `via='mcp'`.
2. **New console-only routes** (they need a `console` session; other kinds → 401):
   - `GET /v1/oauth/requests/{id}`, `POST /v1/oauth/requests/{id}/approve`, `POST /v1/oauth/requests/{id}/deny` (oauth-v1 §3.1);
   - `GET /v1/me/grants`, `DELETE /v1/me/grants/{id}` (oauth-v1 §11).
3. **Device flow:** `POST /v1/auth/device/token` issues an MCP-audience `mcp_access` token (oauth-v1 §9).
4. **Audit actions:** `oauth.client_register`, `oauth.authorize`, `oauth.token_revoke`, `oauth.refresh_reuse`.
5. **Cut-over:** legacy `mcp` sessions are revoked by migration 0005.
6. **v1.4.1:** the device-approval routes (`GET /v1/auth/device/{user_code}`, `/approve`, `/deny`) need a `console` session; other kinds → 401. Other v1.4.1 changes are in oauth-v1 "v1.4.1 amendments".

## v1.5 project invite links (2026-10-14, approved spec `docs/spec-project-invites.md`)

Types: `Invite {"id","role","created_by","created_at","expires_at","max_uses","uses","revoked_at"}`. An invite is **usable** when `revoked_at` is null, `expires_at` > now, and `uses` < `max_uses`.

| Method | Path | Who | Body | Result |
|---|---|---|---|---|
| POST | `/v1/projects/{id}/invites` | admin+ | `{"role":"admin"\|"viewer","expires_in_sec"?:3600..2592000 (default 604800),"max_uses"?:1..50 (default 1)}` | `Invite` + `"token"` + `"url"`, 201. Both appear **only here**. |
| GET | `/v1/projects/{id}/invites` | admin+ | — | list of `Invite`, newest first, never the token. Includes unusable invites. |
| DELETE | `/v1/projects/{id}/invites/{invite_id}` | admin+ | — | `null`; sets `revoked_at` (idempotent). An invite of another project → `not_found`. |
| POST | `/v1/invites/lookup` | any signed-in console user | `{"token"}` | `{"project_id","project_name","role","already_member":bool}` |
| POST | `/v1/invites/accept` | any signed-in console user | `{"token"}` | `{"project_id","role"}`, 200 |

1. **Token:** 43-character unpadded base64url (256 bits), stored as SHA-256 and compared by hash. `url` is exactly `<BOT_API_CONSOLE_ORIGIN>/invite/<token>`. The token is only ever sent in request bodies to the API.
2. **Validation:** `role` `owner` or any other value → `bad_request`. Values out of range → `bad_request`. Viewer → `forbidden`; non-member → `not_found` (general rule).
3. **Lookup and accept:** a token that is unknown, malformed, expired, revoked, or used up → `not_found` with one identical body for all of them. Lookup never changes state.
4. **Accept** runs in one transaction that locks the invite row (`SELECT … FOR UPDATE`):
   - if the caller is already a member → 200 with their current role; `uses` is unchanged and the role is never changed;
   - otherwise it inserts the membership with the invite's role and increments `uses`.
   Concurrent accepts never exceed `max_uses`.
5. **Session kinds:** lookup and accept need a `console` session; other kinds → 401.
6. **Rate limit:** lookup and accept together: 30/min per user and 60/min per source IP, in memory → new envelope error code `rate_limited` with HTTP 429 (added to the error table by this version).
7. **Audit:** `invite.create` (role, max_uses, expires_at), `invite.revoke`, `invite.accept` (invite id, user id). No audit row contains the token.
8. **Deletion:** deleting a project deletes its invites.
9. **Unchanged:** `POST /v1/projects/{id}/members` by email, and every other route.

## v1.6 project catalog, programs (2026-10-15, approved spec `docs/spec-project-catalog.md`, wave 1)

Additive. Container (`image`) entries, `secret_env` and the `docker run` form are wave 2: until then they are refused with the new envelope code **`not_implemented` (HTTP 501)**.

### Objects

```jsonc
CatalogEntry {"id","project_id","name","kind":"program","spec":ProgramSpec,"spec_hash","command_display",
              "created_by","created_at","updated_at","my_actions":["run","stop","restart","logs","status"]}
ProgramSpec  {"dir","exec","args":[string],"shell":bool,"run_as","env":{KEY:value},"port":int|null,
              "restart":"on-failure"|"no"}
CatalogGrant {"subject":"role:viewer"|"role:admin"|"user:<uuid>","actions":[Action]}   // Action ∈ run|stop|restart|logs
Approval     {"entry_id","entry_name","project_id","project_name","host_id","spec_hash","command_display",
              "dir","run_as","shell","status":"pending"|"approved","requested_by","requested_at",
              "approved_by","approved_at"}
ProgramStatus {"unit","active_state","sub_state","main_pid":int|null,"started_at":string|null,"ports":[int]}
ProgramLogs  {"unit","lines":[string],"truncated":bool}
HostPrograms {"enabled":bool,"run_as":[string],"allow_shell":bool,"policy_hash":string}   // from the agent's hello; null when the agent reports none
```

- `name`: `^[a-z0-9][a-z0-9-]{0,47}$`, unique per project, immutable (rename = delete + create).
- `my_actions` is what the caller may do on that entry. `status` is included whenever any action is.
- `command_display` is the argv re-joined with POSIX quoting (or the raw line in shell mode). Display only.
- `spec_hash` is lowercase hex SHA-256 of the canonical JSON of `{"kind","spec"}` (keys sorted, no whitespace).
- `Host` gains `"programs": HostPrograms|null`. `Service` gains `"catalog_entry": string|null` (the entry name when `source='owned'`).

### Writing a program entry

Create and replace take `{"name","kind":"program","command":string,"shell":bool,"dir","run_as","env"?,"port"?,"restart"?}` (`name` only on create).
1. **`command`** (1–4096 bytes, one line) is split into argv on the server with POSIX shell-word rules: single quotes, double quotes and backslash escapes are honoured; nothing else is interpreted.
2. With `shell=false`, the line is refused with `bad_request` and a message naming the feature if it contains, outside quotes: `|`, `&`, `;`, `<`, `>`, `$`, a backquote, `*`, `?`, `[`, `(`, `)`, `{`, `}`, `~` at word start, or a newline. A first word `cd` is refused ("use the working directory field").
3. Leading words of the form `KEY=value` (KEY matching the env key rule) are moved into `env`; a duplicate key is `bad_request`. The next word is `exec`; the rest are `args`.
4. With `shell=true`, nothing is split: `exec` = `/bin/sh`, `args` = `["-c", <line>]`.
5. **`exec`** is an absolute path or a bare name matching `^[A-Za-z0-9._+-]{1,128}$`; absolute paths match `^/[A-Za-z0-9._+/-]{1,255}$` with no `..` segment. `args`: ≤ 32, each ≤ 4096 bytes, no NUL or newline.
6. **`dir`**: absolute, ≤ 255 bytes, no `..` segment, no NUL, no newline.
7. **`run_as`**: `^[a-z_][a-z0-9_-]{0,31}$`, not `root`.
8. **`env`**: ≤ 64 keys; key `^[A-Z_][A-Z0-9_]{0,63}$`; value ≤ 4096 bytes, no NUL or newline. A key matching `(?i)(password|passwd|token|secret|credential|api[_-]?key|private[_-]?key)` is `bad_request` ("use secret_env", which is wave 2). `PATH` and `HOME` are reserved (`bad_request`).
9. `port` 1–65535 or null; `restart` default `on-failure`.
10. `secret_env` present, or `kind` other than `program` → `not_implemented`.

The API does not check host paths or accounts; the host policy and helper do (agent-protocol v1.3).

### Routes

| Method | Path | Who | Body | Result |
|---|---|---|---|---|
| GET | `/v1/projects/{id}/catalog` | viewer+ | — | `{"items":[CatalogEntry]}`; viewers see only entries where `my_actions` is non-empty |
| POST | `/v1/projects/{id}/catalog/parse` | owner | `{"command","shell"}` | `{"exec","args","env","command_display"}` or `bad_request` (rules 1–5; the preview for the form) |
| POST | `/v1/projects/{id}/catalog` | owner | create body | CatalogEntry, 201; `conflict` if the name exists |
| GET | `/v1/projects/{id}/catalog/{name}` | viewer+ with any action | — | CatalogEntry |
| PUT | `/v1/projects/{id}/catalog/{name}` | owner | replace body | CatalogEntry. A changed `spec_hash` voids every host approval of the entry. |
| DELETE | `/v1/projects/{id}/catalog/{name}` | owner | — | `null`. Running units are not stopped (stop first); approvals and grants are deleted. |
| GET | `/v1/projects/{id}/catalog/{name}/permissions` | owner | — | `{"grants":[CatalogGrant]}` |
| PUT | `/v1/projects/{id}/catalog/{name}/permissions` | owner | `{"grants":[CatalogGrant]}` | the stored grants. A `user:` subject must be a current member (else `bad_request`); ≤ 100 grants. |
| GET | `/v1/hosts/{id}/catalog-approvals` | admin+ of the host's owning project | — | `{"items":[Approval]}` (pending and approved; voided ones are gone) |
| POST | `/v1/hosts/{id}/catalog-approvals` | admin+ of the host's owning project | `{"entry_id","spec_hash"}` | Approval; `conflict` if `spec_hash` is no longer the entry's current hash |
| DELETE | `/v1/hosts/{id}/catalog-approvals/{entry_id}` | admin+ of the host's owning project | — | `null` |
| POST | `/v1/projects/{id}/catalog/{name}/run` · `/stop` · `/restart` | grant for that action | `{"host_id","idempotency_key"}` | ProgramStatus, or 202 PendingConfirmation (below) |
| POST | `/v1/projects/{id}/catalog/{name}/logs` | grant `logs` | `{"host_id","lines"?:1..1000 (default 200)}` | ProgramLogs |
| POST | `/v1/projects/{id}/catalog/{name}/status` | any grant | `{"host_id"}` | ProgramStatus |
| POST | `/v1/confirmations/{confirmation_id}` | the same user | `{}` | the result the original call would have returned |

**Default grants** of a new entry: `role:admin` → run, stop, restart, logs; `role:viewer` → logs. The owner always has every action and cannot be listed as a subject.

**Action checks, in order** (the first failure answers):
1. The caller is a member of project `{id}` (`not_found`) with a grant for the action (`forbidden`).
2. Host relation: the host is owned by `{id}`; or it is shared with `{id}` at level `deploy` **and** has an approval for (entry, host) with the entry's current `spec_hash`. Otherwise `not_found` if the host is not visible to the project at all, `forbidden` for a `metrics` share, and for a `deploy` share without a valid approval: `forbidden` with message "waiting for the host owner's approval" — this upserts a pending Approval (requested_by = caller) for the current `spec_hash`.
3. Host policy: `Host.programs` is non-null, `enabled`, lists `run_as`, and allows shell when `shell=true` — otherwise `forbidden` with the reason. Host offline → `unavailable`.
4. **Confirmation (D25):** if the caller's session kind is `api_delegated` (a call through MCP), run/stop/restart do nothing and answer **202** `{"confirmation_id","plan","expires_at"}`. `plan` is a sentence such as "will restart program tra-backend (pnpm run dev, as joe) on pi1". The id is 43-char base64url, stored hashed, single use, valid 5 min, bound to the user, route, entry `spec_hash` and body. `POST /v1/confirmations/{id}` re-runs checks 1–3 and then acts; an unknown, used, expired or foreign id → `not_found`; a changed `spec_hash` → `conflict`. Console sessions skip this step. logs and status never need it.
5. **Idempotency:** run/stop/restart (and the confirm call) require `idempotency_key` (1–128 chars `[A-Za-z0-9._:-]`). The server stores (user, key) → request hash and response for 24 h. The same key with the same request returns the stored response without acting; with a different request → `conflict`.
6. The task goes to the agent (agent-protocol v1.3) and waits up to 30 s; outcomes map as in v1.0.1 item 5, plus `task_reject` `policy_denied` → `forbidden` and agent `error_code` `policy_denied` → `forbidden`.

**Audit:** `catalog.create`, `catalog.update` (old and new `spec_hash`), `catalog.delete`, `catalog.permissions`, `catalog.approve`, `catalog.approval_revoke`, `program.run`, `program.stop`, `program.restart` (host, entry, outcome; `via='mcp'` from delegated tokens), `program.confirmation_issued`. Reads (logs, status) are not audited.

**Owned services:** a `services` report entry with `owner` (agent-protocol v1.3) is stored with `source='owned'`, `name` = the entry name, `catalog_entry` = the entry name, and `project_id` = the project whose slug the agent reports. If no such project/entry exists, the item is stored as `discovered` with its unit name.

**Migration** 0007 adds the catalog, grants, approvals, confirmations and idempotency tables, `hosts.programs` (jsonb), and `services.catalog_entry`, with `deploybot_api` grants in the house style and a hand-run down script.

### v1.6.1 amendments (2026-10-15, from the wave 1 review)

1. **Confirm body:** `POST /v1/confirmations/{confirmation_id}` takes `{"idempotency_key"}` (rule 5 already required it; the table's `{}` was wrong).
2. **Environment that changes what runs is refused** (`bad_request`, "this variable changes what the program runs"): keys starting `LD_` or `DYLD_`, and `NODE_OPTIONS`, `NODE_PATH`, `BASH_ENV`, `ENV`, `IFS`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`. This applies to hoisted `KEY=value` words too.
3. **Approvals show the environment:** `Approval` gains `"env":{KEY:value}` and `"exec","args"`, so the host owner sees everything that will run.
4. **Idempotency is reserved before acting:** the server inserts the (user, key, request hash) row first; a second request with the same key while the first is still running → `conflict` ("request in progress"); after the outcome the stored response is filled in. A failed dispatch stores its error response too, so a retry with the same key replays it.

## v1.7 service presence and views (2026-10-15, approved spec `docs/spec-services-view.md`; additive)

1. **`Service` gains `"gone_at"`**: RFC 3339 time or `null`. `null` means the service was in its host's latest services report (`hello.services` or a `services` frame).
2. **Ingest:** every services report from a host is that host's full set. In the same transaction as the upsert, the server sets `gone_at = <report time>` on that host's rows that are not in the report and still have `gone_at = null`, and sets `gone_at = null` on every reported row. Rows of other hosts are never touched. A host that sends no report changes nothing. `display_name`, health checks and ids are unaffected.
3. **`GET /v1/projects/{id}/services`** gains the query parameter `view`:
   - `all` (default): every row, as in v1.3.
   - `deploybot`: rows with `source` in (`owned`, `declared`), gone or not.
   - `deploybot_and_discovered`: the `deploybot` rows plus rows with `source = 'discovered'` and `gone_at IS NULL`.
   - Any other value → `bad_request`.
   - `q`, `host_id`, `sort`, `dir`, `limit`, `cursor` and `total` apply within the view. A cursor carries its view; using it with a different `view` → `bad_request`.
   - `sort=status`: rows with `gone_at` set come after all rows with `gone_at = null`, for both values of `dir`; within each group the v1.3 order applies.
4. Other routes are unchanged; `GET /v1/hosts/{id}/services` and `GET /v1/services/{id}` simply include `gone_at`.
5. Migration `0008_service_gone.sql` backfills: for each host, rows whose `last_seen_at` is earlier than that host's greatest `last_seen_at` get `gone_at = last_seen_at`.

## v1.8 catalog images (2026-10-15, approved spec `docs/spec-catalog-images.md` rev 3, wave 2a; additive)

`kind:"image"` entries are now accepted. `not_implemented` remains only for managed files (wave 2b). The `docker run` paste prefill is console-side; the API has no parse route for it.

### Objects

```jsonc
CatalogEntry   // kind "program" unchanged; for kind "image": "spec":ImageSpec, "command_display" = the image reference
ImageSpec {"kind":"service"|"job","image":string,"command":[string]|null,"entrypoint":[string]|null,
           "ports":[{"host":int,"container":int,"public":bool}],"env":{KEY:value},"env_sets":[string],
           "secret_env":{KEY:"<set>.<KEY>"},"volumes":[{"name":string,"target":string,"read_only":bool}],
           "restart":"no"|"on-failure"|"unless-stopped","user":string,"healthy_after_sec":int,
           "memory_mb":int|null,"timeout_sec":int}
ImageDeploy {"id","entry_id","host_id","digest","spec_hash","outcome","exit_code":int|null,
             "started_at","finished_at","by":"<user uuid>","via":"console"|"mcp"}
ImageStatus {"container":string|null,"state":"running"|"exited"|"created"|"paused"|"restarting"|"dead"|"missing",
             "exit_code":int|null,"restart_count":int,"started_at":string|null,"finished_at":string|null,
             "digest":string|null,"ports":[int]}
EnvSet      {"name","keys":[{"key","is_secret":bool,"value":string|null}],"updated_at","updated_by"}   // value only when !is_secret
Registry    {"host","username","updated_at","updated_by"}
Outcome     ∈ succeeded|unchanged|failed|timeout|rolled_back|rollback_failed|image_unavailable|forbidden_spec|conflict
```

- `HostPrograms` gains `"images":bool,"docker":bool` (from the agent's hello).
- `Service` gains `"container_name":string|null` and `"image_digest":string|null`; owned image services have `catalog_entry` set and `kind:"container"`.
- `CatalogGrant` actions gain **`deploy`** (deploy, redeploy, job run, rollback, remove). New image entries default to owner/admin `[run,stop,restart,logs,deploy]`, viewer `[logs]`. `my_actions` may include `deploy`.

### Writing an image entry

Create/replace take `{"name","kind":"image","spec":ImageSpec}` (`name` on create only). Validation (`bad_request` with the field named, never echoing a value):
1. `name` as v1.6, and additionally must not end with `-` or `-prev`.
2. `image`: a Docker reference (`[registry/]path[:tag][@sha256:<64 hex>]`), ≤ 255 bytes, lowercase path; a reference with neither tag nor digest is stored with `:latest` appended.
3. `command`, `entrypoint`: null or ≤ 32 strings, each ≤ 4096 bytes, no NUL/newline.
4. `ports`: ≤ 16; host/container 1–65535; host ports unique within the entry.
5. `env`: the v1.6 item 8 rules (including the secret-looking-key refusal) and the v1.6.1 denylist.
6. `env_sets`: ≤ 8 names of sets in the **same project** (`^[a-z0-9][a-z0-9-]{0,47}$`); unknown → `bad_request`.
7. `secret_env`: ≤ 64; key as env; value `<set>.<KEY>`, split at the first `.`, set in the same project and in `env_sets` or not (either is allowed), KEY present in that set; unknown → `bad_request`.
8. `volumes`: ≤ 8; `name` `^[a-z0-9][a-z0-9-]{0,47}$` (the host volume is `<project-slug>-<name>`); `target` absolute, ≤ 255 bytes, no `.`/`..` segment; targets unique.
9. `restart`: default `unless-stopped` for services; forced `no` for jobs.
10. `user`: empty, a name `^[a-z_][a-z0-9_-]{0,31}$`, a positive uid, or `name|uid:name|gid`; uid/gid 0, `root` in either position and leading-zero numbers are refused.
11. `healthy_after_sec` 5–600 (default 30, service only); `timeout_sec` 10–3600 (default 600, job only); `memory_mb` null or 16–65536.
12. Env precedence when resolving: `env_sets` in order < `secret_env` < `env`.

`spec_hash` for image entries = SHA-256 of canonical `{"kind","spec"}` **plus** `"env_keys": {<set>: sha256(sorted key names joined by "\n")}` for every referenced set, so a key added to or removed from a set changes the hash (and voids shared-host approvals). Values never enter the hash.

### Routes

| Method | Path | Who | Body | Result |
|---|---|---|---|---|
| POST | `/v1/projects/{id}/catalog/{name}/deploy` | grant `deploy` | `{"host_id","force"?:bool,"idempotency_key"}` | `{"deploy":ImageDeploy,"status":ImageStatus,"lines":[string]}` |
| POST | `/v1/projects/{id}/catalog/{name}/rollback` | grant `deploy` | `{"host_id","digest","idempotency_key"}` | same |
| POST | `/v1/projects/{id}/catalog/{name}/remove` | grant `deploy` | `{"host_id","idempotency_key"}` | `{"status":ImageStatus}` |
| GET | `/v1/projects/{id}/catalog/{name}/deploys?host_id=` | any grant | — | `{"items":[ImageDeploy]}` newest first, ≤ 50 |
| GET | `/v1/projects/{id}/env-sets` | admin+ | — | `{"items":[EnvSet]}` |
| GET / PUT / DELETE | `/v1/projects/{id}/env-sets/{set}` | admin+ | PUT `{"dotenv":string}` | EnvSet / EnvSet / `{}` |
| PATCH | `/v1/projects/{id}/env-sets/{set}/keys/{key}` | admin+ | `{"is_secret":bool}` | EnvSet |
| GET | `/v1/projects/{id}/registries` | admin+ | — | `{"items":[Registry]}` |
| PUT / DELETE | `/v1/projects/{id}/registries/{host}` | admin+ | PUT `{"username","token"}` | Registry / `{}` |

- run/stop/restart/logs/status (v1.6 routes) dispatch by kind; for images, status/run/stop/restart return `ImageStatus`, logs return `{"container","lines","truncated"}`.
- Deploy/rollback/remove follow the v1.6 check order (permission → host relation/approval → `HostPrograms.images && docker` else `bad_request` "this host does not run containers" → D25 confirmation for `api_delegated` → idempotency) and additionally: one in-flight deploy/rollback/remove per (host, entry) → `conflict`. `rollback.digest` must be one of the last 3 distinct `succeeded`/`unchanged` digests for (entry, host) → else `bad_request`. Outcomes are in the 200 body (`deploy.outcome`), not HTTP codes; only request-level failures use envelope errors.
- D25 `plan` for deploy/rollback: "will deploy <entry> (<image or digest>) on <host>"; it never contains env values.
- **dotenv grammar** (PUT): UTF-8, ≤ 256 KiB, ≤ 256 keys. Each line is blank, a `#` comment (after optional whitespace), or `[export ]KEY=value`. KEY as env rule and denylist (the secret-looking-key refusal does **not** apply: these are secrets). value is the rest of the line, optionally wrapped in one pair of matching `'` or `"` (removed); no escapes, no interpolation, no NUL; a value ≤ 4096 bytes. Duplicates or malformed lines → `bad_request` listing `"line N"` and the key if parsed, never a value. PUT replaces the set; every key becomes `is_secret:true`. *(v1.9.1, 2026-10-17, Joe: a key that already exists in the set keeps its `is_secret`; only keys new to the set start `is_secret:true`. Keys left out of the PUT are removed as before.)* `DELETE` of a set referenced by any entry → `conflict`.
- Registry `{host}`: a registry hostname[:port], lowercase; `username` ≤ 255, `token` ≤ 4096, no CR/LF/NUL. GET never returns tokens.
- Secret values and tokens are AES-256-GCM encrypted with `BOT_SECRETS_KEY` (key_version), a random 96-bit nonce per ciphertext, associated data `project_id|set|key` (or `project_id|registry|host`); they are decrypted only to build an `image_deploy`/`image_rollback` task for a host of the entry's project (or an approved shared host), and only the registry whose host equals the image reference's registry host is attached.
- No MCP-facing route returns env values; there are no MCP tools for env sets or registries.

**Audit:** `catalog.deploy`, `catalog.rollback`, `catalog.remove` (entry, host, digest, outcome, `via`; *v1.9.1, 2026-10-17: the row's `error_code` is the outcome when it is not `succeeded` or `unchanged`*), `env_set.replace`, `env_set.key_visibility`, `env_set.delete`, `registry.put`, `registry.delete` — key names, set names and registry hosts only.

### v1.8.1 amendment (2026-10-16, Joe approved; from the wave 2a browser smoke)

`ImageStatus.state` gains **`unknown`**: the API did not receive the container's state in time (a deploy or rollback whose task ran past its budget, outcome `timeout`). With `unknown`, `container`, `exit_code`, `started_at`, `finished_at` and `digest` are null, `restart_count` is 0 and `ports` is `[]`. An empty string is never sent. Consumers show it as "unknown".

### v1.8.2 amendment (2026-10-16, Joe approved; from the dev console after the wave 2a cleanup)

`view=deploybot` (and so `deploybot_and_discovered`) no longer lists an **owned** row that is gone **and** whose `catalog_entry` no longer exists in the row's project: nothing can start it again. Such a row stays in the database and in `view=all`, with its `display_name` and health checks. If an entry with the same name is created and deployed, the next report clears `gone_at` and the row is listed again. Declared rows, owned rows with `gone_at = null`, and owned rows with `catalog_entry = null` are unchanged. `total` and cursors follow the narrower set. Before (v1.7): `deploybot` = `source` in (`owned`, `declared`), gone or not.

## v1.9 managed files (2026-10-16, approved spec `docs/spec-catalog-files.md` rev 1, wave 2b; additive)

The v1.8 line "`not_implemented` remains only for managed files" no longer applies: `files` is accepted in ImageSpec.

### Objects

```jsonc
ProjectFile  {"name","is_secret":bool,"size":int,"sha256":string|null,"updated_at","updated_by"}   // sha256 (hex of the content) only when !is_secret
ProjectFileContent {"name","content":string,"size":int,"sha256":string,"updated_at","updated_by"} // plain files only
ImageSpec    gains "files":[{"file":string,"target":string}]   // default []
```

- `HostPrograms` gains `"files":bool` (from the agent's hello, agent-protocol v1.5); absent = false.

### Project files

1. **Name:** `^[a-z0-9][a-z0-9._-]{0,63}$`, not `.` or `..`.
2. **Content:** valid UTF-8, 1–65536 bytes, no NUL. Secret content is stored as AES-256-GCM ciphertext with `key_version` (the env-set key, `BOT_SECRETS_KEY_FILE`); plain content as text. At most **64 files per project** (a new name beyond that → `bad_request`).
3. **Routes** (owner/admin of the project, **console sessions only**: an `api_delegated` token → `forbidden` before any decrypt; `mcp_access` / `mcp_refresh` tokens are already 401 `invalid_token` on every `/v1` route by the audience rule; a non-member → `not_found`):

| Method | Path | Body | Payload |
|---|---|---|---|
| GET | `/v1/projects/{id}/files` | — | `{"items":[ProjectFile]}` sorted by name, not paginated |
| GET | `/v1/projects/{id}/files/{name}` | — | `ProjectFileContent`; a secret file → `forbidden` |
| PUT | `/v1/projects/{id}/files/{name}` | `{"content":string,"secret":bool}` (`secret` omitted = `true`) | `ProjectFile`; creates or replaces content and flag |
| DELETE | `/v1/projects/{id}/files/{name}` | — | `null`; `conflict` listing the entry names while any image entry of the project references it |

   Errors never echo content. An unknown name on GET/DELETE → `not_found`.
4. **Audit:** `file.put` (`name`, `is_secret`, `size`), `file.delete` (`name`). Never content or `sha256` of a secret file.

### Writing an image entry: rule 13

13. `files`: ≤ 16 rows. `file` must name a file of the **same project** (unknown → `bad_request`), and each `file` appears at most once per entry (a slot holds one copy per name). `target`: absolute, ≤ 255 bytes, normalised (no empty, `.` or `..` segment, no trailing `/`), not `/`, not `/proc`, `/sys`, `/dev` or under them; unique among `files` targets and `volumes` targets; not under a volume target, and no volume target under it.

`spec_hash` covers `files` as written (names and targets), as part of `spec`. File content never enters `spec_hash`, so a content change does not void a shared-host approval.

### Deploy and rollback

- The API resolves each `spec.files[i].file` to its current content when it builds an `image_deploy` / `image_rollback` task (agent-protocol v1.5). *(v1.9.1, 2026-10-17: the API still sends the current content on every rollback. When the digest is the entry's kept `-prev` container, the agent restores that container with its own previous files and spec instead (agent-protocol v1.5.2).)* A file deleted since the entry was saved → `bad_request` "file <name> no longer exists", and no task is sent.
- The v1.4.1 frame-size check includes the resolved files: an oversized frame → `bad_request` "the resolved environment and files are too large for one task".
- `GET` of a catalog entry and task records show `files` as names and targets only. MCP `list_catalog` shows file names only (targets are dropped, as for volumes).

### Env-set values and redaction (Joe 2026-10-16, from the pi3 mirror)

1. **dotenv values are literal:** `$` and `\` are allowed and taken as-is (no escapes, no interpolation means nothing is interpreted). NUL is still refused, and the 4096-byte value limit stays. Inline `env` in an ImageSpec keeps the v1.6 item 8 rules.
2. **Image tasks send `secret_keys`** (agent-protocol v1.5), and the API's own redaction of image results and logs uses the same secret-only set: secret env-set values after precedence, the registry token, and secret-file items. Structured fields of `ImageStatus`, `ImageDeploy`, `outcome`, `digest` and `exit_code` are never redacted. Only free-text `lines` are. *(v1.9.1: the API's own exact-value pass uses the agent's marker `[REDACTED]`; a refused file delete is audited as `file.delete` (`name`, `outcome`:`"conflict"`); a completed one adds `outcome`:`"deleted"`.)*

### Migration

`0010_project_files.sql` (+ hand-run `.down.sql`): table `app.project_files` (`project_id` uuid FK → projects ON DELETE CASCADE, `name`, `is_secret`, `content_plain` text NULL, `nonce` bytea NULL, `content_cipher` bytea NULL, `key_version` int NULL (the env-set sealing scheme: a fresh 12-byte nonce per write, AAD `project_id|file|name`), `sha256` text, `size` int, `updated_by` uuid, `updated_at` timestamptz; PK `(project_id, name)`; CHECK exactly one of `content_plain` / `content_cipher` per `is_secret`). Grants to `deploybot_api` as for `app.env_values`.


## v1.10 health-check edits over MCP (2026-10-18, approved spec `docs/spec-health-check-editor.md` rev 1; additive)

1. **Body:** `PUT /v1/services/{id}/health-checks` takes `{"checks":[HealthCheck without id/service_id],"idempotency_key"?}`. `idempotency_key` (v1.6 rule 5 format) is **required** for an `api_delegated` session and ignored for a console session.
2. **Console sessions:** unchanged; the set is replaced at once and pushed as `config_update`.
3. **`api_delegated` sessions (D25):** after the existing checks (permission, share rules, body rules: max 10, port in `Service.ports`, protocol/path/interval/expect), nothing changes and the answer is **202** `{"confirmation_id","plan","expires_at"}`. `plan` lists protocol, port, path and interval only: "will set 2 health checks on <service label> (<host>): tcp 443, http 8080 /health every 60 s", or "will remove all health checks from <service label> (<host>)". When the set has a tcp and an http check on the same port, the plan adds "(tcp <port> is redundant with http <port>)"; the set is still applied as given.
4. **Binding:** the confirmation is bound to the user, the service, a hash of the request body, and a hash of the service's check set at issue time; 5-minute expiry; single use; the id has the same format as catalog confirmations.
5. **Confirm:** `POST /v1/confirmations/{confirmation_id}` (`{"idempotency_key"}`) re-runs permission and share checks; the check set changed since issue → `conflict`; unknown, used, expired or foreign id → `not_found`; otherwise it replaces the set, pushes `config_update`, and returns the same body as the console PUT (`{"checks":[HealthCheck]}` as today).
6. **Audit:** `health_checks.replace` as today (`via='mcp'` for delegated), plus `health_checks.confirmation_issued` (service, host, check count). No path query strings are added; paths are stored as given.
7. **Migration 0011** (+ hand-run `.down.sql`): `app.service_confirmations` (`token_hash` bytea PK, 32 bytes; `user_id` uuid; `project_id` uuid; `service_id` uuid FK → `app.services` ON DELETE CASCADE; `action` text CHECK = `'health_checks'`; `request_hash` bytea 32; `current_hash` bytea 32; `checks` jsonb NOT NULL (an array: the normalized request checks in request order, applied on confirm, never returned); `idempotency_key` text; `created_at`, `expires_at` timestamptz; `used_at` timestamptz NULL). Grants to `deploybot_api` as for `app.catalog_confirmations`. The confirm route looks an id up in `catalog_confirmations` first, then `service_confirmations`.
8. **MCP:** a new mutating tool `set_health_checks` (`service_id`, `checks`, `idempotency_key`, all required) issues the plan through this route; the existing `confirm` tool applies it with the same `idempotency_key`, as for the catalog tools. The tool checks `expect_status_min`/`max` within 200–399 like the API. A read-only tool `get_health_checks` (`service_id`) returns the service's current checks from `GET /v1/services/{id}` (Joe 2026-10-18), so a client reads the set before proposing a replacement.
9. **Amendment (Joe 2026-10-18, from the w17 worker notes):** item 7 gains the `checks` column; item 8 takes the caller's `idempotency_key` (rev 1 said the tool generates it, which left the plan unconfirmable) and the 200–399 expect bounds. From the w17 security review: in `plan` the service label and each HTTP path are Go-quoted (`on "swag" (pi3): tcp 443, http 8080 "/health" every 60 s`), and a disabled check ends with ` (disabled)`; confirm's compare, mark-used and replace run in one transaction holding the service row lock.

## v1.10.1 service rows of revoked hosts, and ownership that ends (2026-10-20, approved spec `docs/spec-service-rows.md` rev 1)

1. **Revoke marks rows gone:** every path that sets a host's `revoked_at` (`DELETE /v1/hosts/{id}/credential`, project soft delete) also sets `gone_at = <revoke time>` on that host's service rows whose `gone_at` is null, in the same transaction. Migration `0012_revoked_host_rows.sql` backfills `gone_at = hosts.revoked_at` for rows of hosts revoked earlier (no schema change; the down script is a no-op).
2. **Views:** `view=deploybot` and `view=deploybot_and_discovered` exclude rows whose host is revoked. `view=all` (default) still returns them, now with `gone_at` set. `total` and cursors follow the view.
3. **Ownership ends with the report:** when a services report places an item as `discovered` (no owner, or an owner whose catalog entry no longer exists) and the existing row for that `(host_id, name)` is `owned`, the row becomes `source = discovered`, `catalog_entry = null`, `project_id` = the host's project. Its `id`, `display_name` and health checks are kept. An owned report still upgrades a discovered row to owned; `declared` rows are unchanged by reports. Before: the row stayed `owned` with its old `catalog_entry`.

## v1.11 Docker health status (2026-10-18, approved spec `docs/spec-docker-health.md` rev 1; additive)

1. **Ingest:** accepts the agent-protocol v1.6 docker health sample only from a host whose `hello.programs.docker_health` is true, and stores it in `metrics.health_results` with `protocol='docker'`, `check_id`, `port`, `http_status` and `latency_ms` NULL. No migration.
2. **Config:** `config.docker_health: true` is sent (in `hello_ok` and `config_update`) only to a host that advertised `hello.programs.docker_health: true`.
3. **Precedence (Joe 2026-10-18, "Docker wins"):** `Service.health` derives from the latest docker row when one is at most 2 minutes old; otherwise from the latest non-docker row, as before (`unknown` when none or stale). Docker `success` → `up`, `unhealthy` → `down`.
4. **`Service.health`** gains `"source": "docker"|"check"|null` (the kind of row the status came from; `null` when there is no row). `latency_ms` is null for docker. The project services list sorts by the derived status as before.
5. **Health history** (`GET /v1/services/{id}/health`, MCP `service_health_history`) includes docker rows: `protocol:"docker"`, `check_id`, `port`, `http_status`, `latency_ms` null, `result` `success|unhealthy`.
6. **Console and MCP:** the health badge says the source; the health-check dialog notes that the checks apply only when Docker reports nothing; MCP passes `source` through.
7. **ImageSpec `healthcheck`** *(rev 2, approved 2026-10-20)*: optional `{"test":[argv…],"interval_sec","timeout_sec","retries","start_period_sec"}` on image entries. `test` 1–32 strings, each 1–1024 bytes, no NUL (Docker `CMD` form; no shell form). `interval_sec` 5–300 (default 30), `timeout_sec` 1–60 (default 5, must be < `interval_sec`), `retries` 1–10 (default 3), `start_period_sec` 0–600 (default 0). On a job → `bad_request` (`healthcheck applies to services`). Errors name the field and never echo the argv. Part of `spec_hash`. v1.12 plans show it like `command`.
8. **Gate** *(rev 2)*: deploy or rollback of an entry with `healthcheck` to a host whose `hello.programs.healthcheck` is not true → `bad_request` with message `this host's agent does not support healthcheck`, before confirmation and before any task. An entry without it sends no key.
9. **Deploy wait** *(rev 2)*: for a service with `healthcheck` the outcome is `succeeded` only after Docker reports `healthy` (and any configured checks pass); `unhealthy` or timeout → rollback, outcome as today. MCP `list_catalog` shows `healthcheck: true|false`, not the argv.

## v1.12 catalog writes over MCP (2026-10-20, approved spec `docs/spec-mcp-catalog-writes.md` rev 1)

1. **Delegated writes are planned (D25):** for an `api_delegated` session, `POST /v1/projects/{id}/catalog`, `PUT /v1/projects/{id}/catalog/{name}` and `DELETE /v1/projects/{id}/catalog/{name}` run every existing check (owner, image rules 1–13, name conflict, entry exists), change nothing, and answer **202** `{"confirmation_id","plan","expires_at"}`. Console sessions are unchanged.
2. **Image only:** a delegated create/replace with `kind` ≠ `image`, or an update/delete of a program entry → `forbidden` ("program entries are edited in the console").
3. **Idempotency:** `idempotency_key` (v1.6 rule 5) is required for delegated sessions — in the create/replace body, and as JSON body `{"idempotency_key"}` on DELETE; ignored for console sessions. Same key + same body → the same pending confirmation; same key + different body → `conflict`.
4. **Plan** (never env-set values, `secret_env` values or file contents): create lists image, kind, ports (loopback/public), env set names, inline `env` as `KEY="value"` (non-secret by rule 5), `secret_env` keys with their `<set>.<KEY>` source, volumes, files, command, **entrypoint** (when set), **restart** (when not the kind's default), user, memory; update lists only changed fields (inline env with old and new values) and the number of host approvals it voids; delete states the approvals and grants removed and that running containers are not stopped. Every caller- or user-controlled text in the plan (project name, image, argv elements, user, restart, names, targets, env values) is Go-quoted (`strconv.Quote`) when it is not a plain token, so no `;`, space, U+2028 or U+202E appears raw. *(Amended 2026-10-20 from the w22 reviews.)*
5. **Confirm:** `POST /v1/confirmations/{id}` re-runs the checks and applies the stored normalized body exactly as a console write (same `spec_hash`, approval voiding, audit). Create requires the name still free, update/delete require the entry's current `spec_hash` to equal the plan's, else `conflict`; referenced env sets, files and volumes must still exist, else `bad_request`. Single use, 5 min, bound to user, project, route, entry name and request hash; unknown/used/expired/foreign → `not_found`.
6. **Console-only for delegated sessions:** `PUT /v1/projects/{id}/catalog/{name}/permissions`, host catalog approvals (`POST /v1/hosts/{id}/catalog-approvals`, `DELETE /v1/hosts/{id}/catalog-approvals/{entry_id}`; corrected 2026-10-20, the route table never had `PUT`) and the catalog env routes → `forbidden`.
7. **Migration 0013** (+ hand-run `.down.sql`): `app.catalog_write_confirmations` (`token_hash` bytea PK 32; `user_id`, `project_id` (FK ON DELETE CASCADE); `action` CHECK in (`create`,`update`,`delete`); `entry_name` text; `base_spec_hash` text NULL; `body` jsonb NULL, never returned; `request_hash` bytea 32; `idempotency_key` text; `created_at`, `expires_at`, `used_at`). Grants to `deploybot_api` as for `app.service_confirmations`. The confirm route also looks ids up here. A row is deleted when its write is applied, and expired rows are deleted when a new plan is stored; project delete deletes the project's rows. *(Amended 2026-10-20.)*
8. **Audit:** `catalog.create|update|delete` with `via='mcp'` whenever applied from a confirmation, whatever session confirms it; a delegated call refused by item 6 is audited with `decision=denied`, `via='mcp'`; new `catalog.write_confirmation_issued` (action, entry name).
9. **MCP tools:** `create_catalog_entry(project_id, name, spec, idempotency_key)`, `update_catalog_entry(project_id, name, spec, idempotency_key)` (replace), `delete_catalog_entry(project_id, name, idempotency_key)`; each returns the plan and confirmation id; `confirm` applies it.

## v1.12.1 console-only write routes for delegated sessions (2026-10-20, approved spec `docs/spec-delegated-routes.md` rev 1)

1. **Refused for `api_delegated`:** `POST /v1/projects`; `PATCH` and `DELETE /v1/projects/{id}`; `POST /v1/projects/{id}/members`; `PATCH` and `DELETE /v1/projects/{id}/members/{user_id}`; `POST /v1/projects/{id}/transfer-ownership`; `POST /v1/projects/{id}/join-tokens`; `DELETE /v1/projects/{id}/join-tokens/{token_id}`; `POST /v1/projects/{id}/invites`; `DELETE /v1/projects/{id}/invites/{invite_id}`; `DELETE /v1/hosts/{id}/credential`; `PUT` and `DELETE /v1/hosts/{id}/shares/{project_id}`; `PATCH /v1/services/{id}`. Each → `403 forbidden` (message `forbidden`), nothing written, before membership is checked (a non-member or unknown id gets the same answer).
2. **Audit:** one row per refusal: action `delegated.denied`, `decision=denied`, `via='mcp'`, `error_code=forbidden`, detail `{"route":"<METHOD pattern>"}`, `project_id` and `host_id` null.
3. **Default deny:** a mutating route added after v1.12.1 is refused for `api_delegated` in the same way unless this contract names it as allowed or as deciding in its handler.
4. **Unchanged:** console sessions; GET routes; `POST /v1/hosts/{id}/snapshot`, `POST /v1/services/{id}/probe`, catalog `logs`, `status` and `parse`, `POST /v1/auth/signout` and `POST /v1/confirmations/{id}` stay allowed; the D25 routes and the v1.12 console-only routes keep their own behaviour and audit actions.

## v1.13 env-set editing, secret previews, admin catalog edit (2026-10-20, approved spec `docs/spec-env-editing.md` rev 1)

1. **Preview rule:** `preview(v)` is the first 4 runes of `v` followed by `…` when `v` has at least 16 runes, otherwise `••••`. It never exposes more than 4 runes.
2. **`GET /v1/projects/{id}/env-sets/{set}`:** each key is `{key, is_secret, value, preview}`. A secret key has `value: null` and `preview` = `preview(v)`; a plain key has `preview: null`.
3. **`PUT /v1/projects/{id}/env-sets/{set}/keys/{key}`** (new), body `{"value": string, "is_secret"?: bool}`: sets one key, creating the set if needed. `is_secret` applies only to a new key (default `true`); for an existing key it must be absent or equal to the stored flag, else `bad_request` with message `secret flag is fixed; delete and re-add the key`. Key and value rules are the dotenv rules (key grammar, no NUL, no line break, value ≤ 4096 bytes); errors never echo the value. Response: the key as item 2 shows it. Audit `env_set.key_put` (`set`, `key`, `created`), no value.
4. **`DELETE /v1/projects/{id}/env-sets/{set}/keys/{key}`** (new): removes one key; an unknown key is `not_found`. Audit `env_set.key_delete` (`set`, `key`).
5. **`PATCH /v1/projects/{id}/env-sets/{set}/keys/{key}`** is removed (`404 not_found`). A key's secret flag is fixed once created.
6. **`PUT /v1/projects/{id}/env-sets/{set}`** (dotenv) accepts optional `new_keys_secret` (bool, default `true`) for keys new to the set; existing keys keep their flag.
7. **Auth:** all env-set routes stay owner or admin, console session only. Items 3 and 4 are refused for `api_delegated` by v1.12.1 item 3 (`delegated.denied`). Adding or deleting a key changes the set's key list and voids host approvals of entries that use the set, as a whole-set replace does; a value-only change does not.
8. **`PUT /v1/projects/{id}/catalog/{name}`:** owner or admin (was owner), for console sessions and for the delegated D25 plan and its confirm. Create, delete and permissions stay owner-only.
9. **Redaction:** in log lines, status text (including the `ImageStatus`/`ImageDeploy` string fields) and error strings, an env-set secret value of at least 6 bytes (raw, base64 and JSON-escaped forms; the floor is unchanged from v1.4) is replaced by `preview(v)` instead of `[REDACTED]`. Audit rows keep their fixed phrases. Registry tokens and secret-file pieces keep `[REDACTED]`. Text already redacted by an older agent (`[REDACTED]`) is accepted as is.
