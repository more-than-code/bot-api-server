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
