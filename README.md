# bot-api-server

Go service for deploybot: Google OAuth sign-in and sessions, projects and members, join tokens and host credentials, the bot-agent WebSocket, metrics ingest into Postgres `deploybot`, live probes, and the REST API used by bot-console and bot-mcp-server.

- Design: `docs/design.md` (repo layout) and the umbrella `docs/design-bot-agent-deploy.md` §6 (server) and §3 (auth).
- Contracts (frozen, do not edit here): `docs/contracts/api-v1.md` and `docs/contracts/agent-protocol-v1.md`.

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
