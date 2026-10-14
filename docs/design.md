# bot-api-server: per-repo design

**Date:** 2026-10-13. **Status:** Approved design (D1–D31), wave 1 = phase 1. D34 (2026-10-14) amends umbrella D21. Service names and `GET /v1/projects/{id}/services` (2026-10-14) follow `docs/spec-project-services.md`.
Cross-repo design: umbrella `docs/design-bot-agent-deploy.md` §2 (permissions), §3 (auth), §6 (server, app schema, Postgres roles and metrics). Contracts: `docs/contracts/`.

## Layout

```
cmd/bot-api-server/        main: config, DB pool, migrations on start (flag), HTTP server
internal/config/           env config (below)
internal/db/               pgx pool, migrations (embedded SQL), queries
internal/auth/             Google OIDC + PKCE, sessions, device flow
internal/authz/            authorize(user, project, capability), plus host relation (D34)
internal/api/              REST handlers, envelope, error mapping
internal/agentws/          /agent/v1/ws: enroll, hello, heartbeat, ingest, tasks, hub of live connections
internal/ingest/           sample validation (allowlists) and batched inserts
internal/audit/            append-only audit writer
migrations/                0001_app.sql, 0002_metrics.sql (TimescaleDB hypertables), 0003_shared_hosts.sql
```

## Config (env)

| Var | Purpose |
|---|---|
| `BOT_API_LISTEN` | e.g. `127.0.0.1:8090` |
| `DATABASE_URL` | Postgres `deploybot` as `deploybot_api` |
| `BOT_API_MIGRATE_DATABASE_URL` | optional; the migration login (owner). Migrations run only with `--migrate`. |
| `BOT_API_GOOGLE_CLIENT_ID`, `BOT_API_GOOGLE_CLIENT_SECRET` | OAuth client |
| `BOT_API_OAUTH_REDIRECT_URIS` | comma-separated allowlist (console callbacks) |
| `BOT_API_DEVICE_VERIFICATION_URI` | console `/device` URL |
| `BOT_API_AGENT_WS_URL` | the public `wss://…/agent/v1/ws` shown in `install_command` |
| `BOT_API_PUBLIC_ORIGIN` | for logs only |

TLS terminates at the reverse proxy in production; dev listens on the tailnet.

## Notes

- One process. In-flight tasks, OAuth states, and live agent connections are in memory.
- Metrics tables use `timestamptz`. Raw retention is 7 days; hourly continuous aggregates are kept 1 year (add the policies in migrations; they need TimescaleDB enabled by Joe).

## D34 Shared hosts

Amends umbrella D21 ("a host belongs to exactly one project"). The host still has one owning project (`hosts.project_id`). `app.host_shares` grants another project `metrics` or `deploy` access. A row whose project is the owning project is rejected by a `BEFORE` trigger and by the store. `services.project_id` records which project a service belongs to. The agent still enrolls with no protocol change; a discovered service is inserted on the host's owning project, and rediscovery does not move `project_id`.

Permission checks for host and service routes use `authz.HostRelation` and `authz.AuthorizeHost` (spec §4). A user who is in both the owning project and a share is an owner; that clears the share list. A user in several shares keeps every share. Host view, status, and metrics are allowed when any share allows them. A service check uses only the share whose project is that service's project. `GET /v1/hosts/{id}` `share_level` is the highest of those shares (`deploy` over `metrics`). `GET /v1/projects/{id}/hosts` is different: the label is relative to that project, so the same user listing the sharing project still sees `relation: "shared"`. Owned rows come first, then shared rows, each by name in byte order (`COLLATE "C"`). The host-list cursor is `(rel_rank, name, id)`. The next page compares those values and does not look the cursor host up. A cursor in the previous `(time, id)` shape is rejected. Deploy shares still see only that project's services; anyone who can see the host gets the full process list and may snapshot (v1.1.1). A caller in two deploy shares sees both projects. Metrics shares can read the host and its charts.

Deleting a sharing project drops its shares and moves its services on other hosts back to those hosts' owners, in the same transaction. Deleting the owning project still revokes host credentials, and its shares go too. Deleting a host row drops `host_shares` by `ON DELETE CASCADE`.

`migrations/0003_shared_hosts.sql` is applied by `--migrate` (as `deploybot_owner`). It backfills `services.project_id`, then sets `NOT NULL`, and grants `deploybot_api` select, insert, update, and delete on `app.host_shares`. `--migrate` ignores `*.down.sql`. `migrations/0003_shared_hosts.down.sql` is a hand-run rollback for before phase 2: run it as `deploybot_owner`, then `DELETE FROM app.schema_migrations WHERE name = '0003_shared_hosts.sql'` before `--migrate` will apply 0003 again.

## Service names

`services.display_name` is the name a person types. `services.owner_user` is the account that owns the listening socket, copied from the agent's `Discovered.user`. Both are nullable. Rediscovery updates `owner_user` and the other discovered columns; it does not write `display_name`. A value that is empty, not printable, or longer than 64 bytes is stored as null and does not drop the service.

`PATCH /v1/services/{id}` sets or clears `display_name`. The body is that one field. The handler trims it and requires 1–64 printable characters. The edit permission is the shared-hosts service write capability: owner admin+, or a deploy-share admin for a service whose project is that share. A case-insensitive duplicate on the same host is `conflict`, from the partial unique index. The audit action is `service.rename` with detail `from` and `to`, on success and on denial.

`GET /v1/projects/{id}/services` requires project membership (`CapRead`). Rows are every service on hosts the project owns, plus services whose `project_id` is that project on hosts shared at `deploy`. A metrics share contributes nothing, including services that belong to the metrics project. Each row is the Service object plus `host_name`, `host_status` (the same rules as `Host.status`), and `project_name`. Search, sort, `total`, and paging run in SQL: one count and one page. `q` is bound with `LIKE` wildcards escaped. Sort and direction are an allowlist. Names sort by byte order of the lowercased label (`COLLATE "C"`), not locale. Host and kind use that same collation on the stored text. Ties break by `id` ascending. Nulls sort last in both directions. The cursor is opaque base64url JSON `{o, h}`: an offset and a short hash of `q`, `host_id`, `sort`, and `dir`. The first page has `prev_cursor` null. `GET /v1/hosts/{id}/services` orders by name in byte order (`COLLATE "C"`), like every other name sort, so Postgres and memstore agree. That list is otherwise unchanged apart from the two new Service fields.

`migrations/0004_service_names.sql` adds the columns and `services_host_display_name_uidx`. `services_project_idx` already exists from 0003; 0004 creates it only if it is missing, and the down script does not drop it. `--migrate` does not apply `migrations/0004_service_names.down.sql`. Running that file by hand drops the two columns and the unique index. Names typed by people are lost. Then `DELETE FROM app.schema_migrations WHERE name = '0004_service_names.sql'` before `--migrate` will apply 0004 again. Grants are unchanged.
