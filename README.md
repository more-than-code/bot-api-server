# bot-api-server

Go service for deploybot: Google OAuth sign-in and sessions, projects and members, join tokens and host credentials, the bot-agent WebSocket, metrics ingest into Postgres `deploybot`, live probes, and the REST API used by bot-console and bot-mcp-server.

- Design: `docs/design.md` (repo layout) and the umbrella `docs/design-bot-agent-deploy.md` §6 (server) and §3 (auth).
- Contracts (frozen, do not edit here): `docs/contracts/api-v1.md`, `docs/contracts/oauth-v1.md`, and `docs/contracts/agent-protocol-v1.md`.

## Run locally

Phase 1 needs Go 1.27 and a Postgres 18 database with TimescaleDB. The server does not create tables on startup. `--migrate` does not create roles, schemas, or the TimescaleDB extension.

1. Copy `.env.example` to `.env` and replace every `CHANGE_ME` and `dummy-google-*` value. The example file is not a working configuration.
2. Create empty databases named `deploybot` and, for integration tests, `deploybot_test`. Do not create the extension yourself.
3. As a superuser, start a new session and run `migrations/roles.sql.example` as the first command in that session. Run it once connected to `deploybot`, and again connected to `deploybot_test`. Replace the `CHANGE_ME` passwords first. The script creates `deploybot_owner`, `deploybot_migrator`, and `deploybot_api`, installs `timescaledb`, and creates the `app` and `metrics` schemas. It is not applied by `--migrate`.
4. Apply the numbered migrations as `deploybot_migrator`:

   ```sh
   set -a
   source .env
   set +a
   go run ./cmd/bot-api-server --migrate
   ```

   `--migrate` reads `BOT_API_MIGRATE_DATABASE_URL`, runs `SET ROLE deploybot_owner`, and refuses to continue when `timescaledb` is missing. It is the only path that runs the numbered SQL files.
5. Start the API with `DATABASE_URL` pointing at `deploybot_api`:

   ```sh
   go run ./cmd/bot-api-server
   ```

   It listens on `BOT_API_LISTEN`. `GET /health` returns `{"status":"ok"}`.

`DEPLOYBOT_TEST_DATABASE_URL` is for integration tests only. Those tests refuse to run unless the connected database name is `deploybot_test`, and that database must already have had `roles.sql.example` applied. Leave the variable unset for `go test ./...`.

## Shared hosts

A host still belongs to one owning project. An owner admin can share it with another project at `metrics` or `deploy` (`PUT /v1/hosts/{id}/shares/{project_id}`). `GET /v1/projects/{id}/hosts` returns hosts that project owns and hosts shared with it. Owned hosts come first, then shared hosts, each ordered by name. The caller must be a member of the target project, and the owning project cannot be a share. Removing a share while that project still has services on the host returns 409 `conflict` unless `?reassign=owner` moves those services to the owner. Anyone who can see the host gets the full process list and may snapshot. Contract: `docs/contracts/api-v1.md` (v1.1.1). Behaviour: `docs/spec-shared-hosts.md`.

`migrations/0003_shared_hosts.sql` is applied by `--migrate`. It backfills `services.project_id` from the host, then sets the column `NOT NULL`, and grants `deploybot_api` select, insert, update, and delete on `app.host_shares`. `migrations/0003_shared_hosts.down.sql` is not applied by `--migrate`. Run that file by hand as `deploybot_owner`, and only before phase 2 (until then `services.project_id` can be rebuilt from the host). Then delete the applied row so a later `--migrate` will run 0003 again:

```sql
DELETE FROM app.schema_migrations WHERE name = '0003_shared_hosts.sql';
```

## Service names

A service keeps the discovered `name` the agent uses as its key. People set `display_name` with `PATCH /v1/services/{id}` and body `{"display_name": "<name>" | null}`. The name is trimmed, then it must be 1–64 printable characters. An empty string is `bad_request`. `null` clears it. The same name on one host, ignoring case, is `conflict`. The permission is the service edit capability from shared hosts: an owner admin, or a deploy-share admin renaming a service of its own project. The audit action is `service.rename`, including when the caller is denied. The agent stores the account that owns the listening socket in `owner_user` and never writes `display_name`. A later discovery batch updates `owner_user` and leaves the name.

`GET /v1/projects/{id}/services` lists every service on hosts that project owns, plus that project's own services on hosts shared with it at `deploy`. A metrics share adds no rows. The caller must be a member of the project; anyone else gets 404. `q` is a case-insensitive substring over the display name, discovered name, kind, host name, owner, and ports. `%`, `_`, and `\` match literally. `sort` is `name` (the display name, or the discovered name when the display name is null), `host`, `kind`, `status`, or `last_seen`. Name order is the byte order of the lowercased label, not the database locale. `dir` defaults to `asc`, and to `desc` for `last_seen`. The payload is `items`, `next_cursor`, `prev_cursor`, and `total`. The cursor is bound to `q`, `host_id`, `sort`, and `dir`. `GET /v1/hosts/{id}/services` orders by name in byte order (`COLLATE "C"`), like every other name sort, so Postgres and memstore agree. That list is otherwise unchanged apart from `display_name` and `owner_user` on each row.

`migrations/0004_service_names.sql` adds the two nullable columns and a unique index on `(host_id, lower(display_name))` where the name is not null. It does not change grants. `--migrate` does not apply `migrations/0004_service_names.down.sql`. That script drops the columns and the unique index. Names typed by people are lost. The project index from 0003 stays. After a hand run, delete the applied row before `--migrate` will apply 0004 again:

```sql
DELETE FROM app.schema_migrations WHERE name = '0004_service_names.sql';
```

## MCP OAuth

This process is the OAuth authorization server MCP clients use (`docs/contracts/oauth-v1.md`, api-v1 v1.4). A public client registers at `POST /oauth/register`. The person approves at the console. `POST /oauth/token` then issues an MCP access token (one hour) and a rotating refresh token (30 days). A second use of that code revokes the whole grant family, including later refreshes and delegated API tokens. `bot-mcp-server` exchanges a live MCP access token for a five-minute API token. Those exchanges are not counted against the token endpoint's per-IP limit; a missing or wrong client secret is. An MCP access token, an MCP refresh token, or a legacy `mcp` session presented to any `/v1/*` route is `401` with code `invalid_token`. The device flow (`POST /v1/auth/device/token`) issues an MCP access token for 30 days, in a grant family for the pseudo-client `deploybot-cli`. Looking up, approving, or denying a device code needs a console session.

`BOT_API_PUBLIC_ORIGIN` is the issuer. A trailing slash is removed. `BOT_API_MCP_RESOURCE` is the audience clients must send: the MCP endpoint URL `<mcp origin>/mcp`, exactly as bot-mcp-server publishes it (e.g. `http://localhost:8091/mcp`); it is not trimmed. `BOT_API_CONSOLE_ORIGIN` is where `/oauth/authorize` sends the browser (`/oauth/consent?request=…`). When `BOT_API_MCP_RESOURCE` is set, `BOT_API_MCP_CLIENT_SECRET_FILE` is required before the process opens the database. The file must be a regular non-symlink file with mode `0600`. The first line is the plaintext secret for client id `bot-mcp-server` (a trailing CR is removed; a leading space is kept). That line must be at least 32 characters. A shorter line refuses to start, and the error does not include the secret. The database stores only the SHA-256 of that line. Leave `BOT_API_MCP_RESOURCE` empty to start without that client.

`migrations/0005_mcp_oauth.sql` adds the OAuth tables, the session columns (`audience`, `grant_id`, `client_id`, `code_id`, `rotated_at`), widens `sessions.kind`, inserts `deploybot-cli`, and expires every live `kind = 'mcp'` session. It grants `deploybot_api` select, insert, update, and delete on the four new tables. `--migrate` does not apply `migrations/0005_mcp_oauth.down.sql`. Run that file by hand as `deploybot_owner`. It deletes `mcp_access`, `mcp_refresh`, and `api_delegated` sessions, restores the old kind check, and drops the new columns and tables. Legacy `mcp` rows stay expired. Clients, grants, codes, and pending requests are lost. Then delete the applied row before `--migrate` will apply 0005 again:

```sql
DELETE FROM app.schema_migrations WHERE name = '0005_mcp_oauth.sql';
```

## Project invites

An owner or admin creates a link with `POST /v1/projects/{id}/invites`. The body is `role` (`admin` or `viewer`), optional `expires_in_sec` (3600–2592000, default 604800), and optional `max_uses` (1–50, default 1). The 201 response is the invite plus `token` and `url`. Those two fields are not returned again. `url` is `<BOT_API_CONSOLE_ORIGIN>/invite/<token>`. A trailing slash on the origin is removed. If the origin is empty, create returns 500 and does not store a token. `GET /v1/projects/{id}/invites` lists every invite for that project, newest first, including expired, revoked, and used-up rows. `DELETE /v1/projects/{id}/invites/{invite_id}` sets `revoked_at`. A second delete keeps the original timestamp. An invite that belongs to another project is `not_found`.

`POST /v1/invites/lookup` and `POST /v1/invites/accept` take `{"token":"..."}`. Both require a console session. Any other session kind is 401 `unauthorized`. Lookup and accept share a limit of 30 requests a minute per user and 60 a minute per source IP. Past either limit the response is 429 `rate_limited`. Lookup does not change the invite or the membership. An unknown, malformed, expired, revoked, or used-up token is `not_found`, and those responses are the same body. Accept runs in one transaction. Someone who is already a member gets their current role, and `uses` stays unchanged. Anyone else is added with the invite's role and `uses` increases by one. Concurrent accepts never go past `max_uses`.

The plaintext token is not stored, not logged, and not written into audit detail. Audit actions are `invite.create`, `invite.revoke`, and `invite.accept`. Deleting a project deletes its invites. Contract: `docs/contracts/api-v1.md` (v1.5). Behaviour: `docs/spec-project-invites.md`.

`migrations/0006_invites.sql` creates `app.invites`. `deploybot_api` may select and insert, and may update only `uses` and `revoked_at`. Soft-delete does not fire the foreign key, so the migration adds `app.invites_delete_for_project`, which runs as `deploybot_owner`. A real `DELETE` of the project still cascades. `--migrate` does not apply `migrations/0006_invites.down.sql`. Run that file by hand as `deploybot_owner`. It drops the helper and the table. Memberships already created by an accept stay. Invite links stop working. Then delete the applied row before `--migrate` will apply 0006 again:

```sql
DELETE FROM app.schema_migrations WHERE name = '0006_invites.sql';
```
