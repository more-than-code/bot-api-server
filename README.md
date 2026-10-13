# bot-api-server

Go service for deploybot: Google OAuth sign-in and sessions, projects and members, join tokens and host credentials, the bot-agent WebSocket, metrics ingest into Postgres `deploybot`, live probes, and the REST API used by bot-console and bot-mcp-server.

- Design: `docs/design.md` (repo layout) and the umbrella `docs/design-bot-agent-deploy.md` §6 (server) and §3 (auth).
- Contracts (frozen, do not edit here): `docs/contracts/api-v1.md` and `docs/contracts/agent-protocol-v1.md`.
