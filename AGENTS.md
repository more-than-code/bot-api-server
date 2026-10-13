# bot-api-server

Go service. Umbrella: `/Users/joe/workspace/deploybot` (cross-repo design `docs/design-bot-agent-deploy.md`, ledger `tasks/todo.md`).

Do not connect to pi4 or any shared database except through the `DATABASE_URL` you are given. Do not create roles or databases. Do not print secrets or `.env`. The contracts in `docs/contracts/` are frozen; report problems instead of editing them.

```bash
go build ./... && go vet ./... && go test ./...
```

Database tests run only when `DEPLOYBOT_TEST_DATABASE_URL` is set; without it they skip.
