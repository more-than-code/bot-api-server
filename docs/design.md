# bot-api-server: per-repo design

**Date:** 2026-10-13. **Status:** Approved design (D1–D31), wave 1 = phase 1.
Cross-repo design: umbrella `docs/design-bot-agent-deploy.md` §2 (permissions), §3 (auth), §6 (server, app schema, Postgres roles and metrics). Contracts: `docs/contracts/`.

## Layout

```
cmd/bot-api-server/        main: config, DB pool, migrations on start (flag), HTTP server
internal/config/           env config (below)
internal/db/               pgx pool, migrations (embedded SQL), queries
internal/auth/             Google OIDC + PKCE, sessions, device flow
internal/authz/            authorize(user, project, capability): the one permission check
internal/api/              REST handlers, envelope, error mapping
internal/agentws/          /agent/v1/ws: enroll, hello, heartbeat, ingest, tasks, hub of live connections
internal/ingest/           sample validation (allowlists) and batched inserts
internal/audit/            append-only audit writer
migrations/                0001_app.sql, 0002_metrics.sql (TimescaleDB hypertables)
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
