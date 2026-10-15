# Spec: Services tab shows deploybot services; gone services

**Status:** approved by Joe 2026-10-15 ("ye"), including the three-option Show select
**Tier:** 3 (api-v1 contract, migration 0008, console, MCP tool, small agent fix)
**Builds on:** `docs/spec-project-services.md`, `docs/spec-project-catalog.md` (owned services), api-v1 v1.6.1, agent-protocol v1.3.1.

## 1. Goal

Joe, 2026-10-15: "Expect the table show services created from the bot agent only. Why 2 3031 ports?"

Today the project's Services tab lists every listener the agent has ever reported, and never hides one that went away. pi1 shows `port 3031 · joe` (the old user unit, last seen 14:00) next to `tra-backend · catalog` (the catalog unit, last seen 14:13), though neither runs. Rows from yesterday (3021, 5174) are still listed too.

Decisions (Joe, AskUserQuestion, 2026-10-15):
1. By default the tab shows only **deploybot services** (source `owned` or `declared`). A toggle reveals discovered listeners, which mohiguide still needs for health checks and wave 2 adoption.
2. A service the agent no longer reports is **gone**. Gone discovered rows are hidden by default. Owned rows stay and show as **stopped**, since deploybot can start them again.

## 2. Approach

**"Gone" is exact, not a timer.** The agent's `services` report (and `hello.services`) is the host's full set: it is sent when the set changes and at least every 300 s (agent-protocol v1.0; checked in `bot-agent/internal/agent/run/session.go` `maybeServices`, which always sends `discover()`'s whole result). On each report the API marks the host's rows that are missing from it as gone (`gone_at = report time`) and clears `gone_at` on the rows it contains. No threshold to tune, and no false "gone" while a host is merely offline: no report means no change, and the host's own status already says offline.

**One `view` parameter instead of free-form filters.** The tab needs three fixed views. Combining a `source` filter and a `gone` filter gets "owned in any state, plus discovered only if present" wrong or needs two calls.

**Rejected:**
- *Time threshold (~3 missed reports):* reports come on change or every 300 s, so any threshold is either slow (15 min) or flaps.
- *Deleting gone rows:* loses renames and health checks; Joe chose to hide them.
- *Changing the API default:* MCP and scripts would silently lose rows. The API default stays `all`; the console asks for `deploybot`.

## 3. Contract diff (api-v1 v1.7, additive)

| | Before (v1.6.1) | After (v1.7) |
|---|---|---|
| `Service` | no presence field | adds `"gone_at"`: RFC 3339 time or `null`. `null` means the service is in its host's latest services report. |
| `GET /v1/projects/{id}/services` | no view filter | adds query `view` ∈ `all` (default, unchanged behaviour) \| `deploybot` \| `deploybot_and_discovered`. Any other value → `bad_request`. |
| Same route, `sort=status` | health status, then name | unchanged, but rows with `gone_at` set sort after all present rows |
| Ingest of a `services` report | upserts reported rows | also sets `gone_at = <report time>` on this host's rows not in the report (if still `null`), and `gone_at = null` on reported rows |

View semantics:
- `deploybot`: rows with `source` in (`owned`, `declared`), whether gone or not.
- `deploybot_and_discovered`: `deploybot`, plus `source = discovered` rows with `gone_at IS NULL`.
- `all`: every row, as today.

`q`, `host_id`, `sort`, `dir`, `limit`, `cursor` and the total count all apply within the view. A cursor is bound to its view: reusing it with another `view` → `bad_request`.

Nothing else changes: `GET /v1/hosts/{id}/services` (host page), health checks, rename, permissions, and agent-protocol are unchanged.

## 4. Changes

| Repo | Change |
|---|---|
| umbrella | `docs/contracts/api-v1.md` v1.7 section (copied into each repo's `docs/contracts/`); this spec; `AGENTS.md` (migrations through 0008, contract list). |
| bot-api-server | Migration `0008_service_gone.sql` (+ hand-run `.down.sql`): `services.gone_at timestamptz NULL`. Backfill: on each host, rows whose `last_seen_at` is earlier than the host's newest `last_seen_at` get `gone_at = last_seen_at`. Every report upserts all present rows with the same `at`, so the newest value marks the latest report. `UpsertDiscovered` (db + memstore) marks and clears `gone_at` in the same transaction. List query adds `view` (validated, in SQL), sort puts gone rows last for `status`, and the cursor carries the view. `Service` JSON gains `gone_at`. |
| bot-console | Services tab: a **Show** select above the table, with options "deploybot services" (default, `view=deploybot`), "Also discovered" (`deploybot_and_discovered`) and "Everything, including gone" (`all`). It is kept in the URL (`?show=`) like the host filter. The Status cell shows a **stopped** badge for an owned/declared row with `gone_at`, and **gone** for a discovered one, instead of the health status. The empty state for the default view reads "No services run by deploybot yet. Show discovered listeners." (link to the second view). |
| bot-mcp-server | `list_services` gains an optional `view` argument (same three values, default `all`) and returns `gone_at`. The tool description says gone rows are listeners no longer reported. |
| bot-agent | `discover()` today turns a failed process scan into an **empty** set, and a failed owned-program lookup (helper) into a set **without** the catalog programs; both are then sent as the full set. Under this spec they would mark every service gone, or show running catalog programs as stopped. Change: when the scan fails, or when the policy is enabled and the owned lookup fails, `maybeServices` sends nothing for that cycle (the API keeps the last state; the existing log lines stay). The first-ever report after start waits for a successful scan. agent-protocol v1.3.2: a services report is only sent from a complete discovery; `hello` gains `services_complete` (absent = true), because `hello.services` is also stored and an incomplete first discovery must not mark rows gone (found while freezing the contract, 2026-10-15). |

Note: Joe picked "a toggle"; the spec uses a three-option select. The third option is the only way to reach gone discovered rows (which keep renames and health checks) without a second control. Joe to confirm in approval.

## 5. Acceptance criteria

1. After an agent report that omits a previously reported service, that row has `gone_at` = the report's time; a later report containing it sets `gone_at` back to `null`. The row id, `display_name` and health checks are unchanged.
2. A host that sends no report (offline, asleep) does not change any `gone_at`.
3. A report never touches rows of another host.
4. `view=deploybot` returns only `owned`/`declared` rows (gone or present); `view=deploybot_and_discovered` adds only discovered rows with `gone_at = null`; `view=all` and no `view` return exactly what v1.6.1 returned, plus the `gone_at` field.
5. `view=bogus` → 400 `bad_request`; a cursor from one view used with another → `bad_request`; `total` counts only the view's rows.
6. `sort=status` lists present rows before gone rows, in both directions of `dir`.
7. Migration 0008 backfill on a copy of the dev DB: pi1's `port-3031` (14:00) and `tra-backend` (14:13, stopped) get `gone_at`; rows in pi1's latest report keep `null`. The down script removes the column.
8. Console default view on Home Lab shows `tra-backend · catalog` with a **stopped** badge and no `port …` rows; "Also discovered" adds the live port rows; "Everything" also shows `port 3031`, `port 3021` and `port 5174` with a **gone** badge. Choosing a view survives reload (URL).
9. MCP `list_services` without `view` returns the same rows as before plus `gone_at`; with `view=deploybot` it matches the API.
10. bot-agent: with a scan that fails (test double), or the policy enabled and the helper failing, no `services` frame is sent for that cycle; with both working the frame carries discovered and owned items as today.
11. One browser smoke of the Services tab (switch all three views, read console errors) before the wave is called clean (lesson 2026-10-15).

## 6. Tests

- API unit (memstore) and DB integration: mark/clear on report (1), host isolation (3), no report → no change (2), each view (4), bad view and cursor reuse (5), status sort (6), backfill SQL on fixture rows (7).
- Console: server-render tests for the three views' query mapping, the stopped/gone badges, the empty-state link and the URL round trip; the select uses the shared `Select` primitive (components-reuse rule).
- bot-agent: `maybeServices` with failing scan / failing helper sends nothing; recovery sends the full set.
- MCP: tool schema accepts `view`, passes it through, rejects other values; output includes `gone_at`.

## 7. Verification gates

- bot-api-server: `go vet ./...`, `go test ./...`, TestIntegration on `deploybot_test` (migrate to 0008 there first).
- bot-console: `pnpm test`, `pnpm run check`, `pnpm run build`.
- bot-mcp-server and bot-agent: `go vet ./...`, `go test ./...`.
- Live: migrate pi4 `deploybot` to 0008 (Joe's approval), restart the dev API, check criterion 8 in the console and criterion 9 through MCP.

## 8. Rollback

The column and the parameter are additive, and the API default is unchanged. To roll back: revert the console (shows everything again), revert the API (ignores `gone_at`), then run `0008_service_gone.down.sql`. Old clients ignore the new field. The agent fix only withholds bad reports; reverting it restores today's behaviour. Hosts need no rollback step.

## 9. Risks

- **The full-set assumption.** Confirmed for the current agent, except the two failure paths fixed in §4. Agents older than the fix (mohiguide runs @148026f, pi1 runs 4c802d7) can still send an empty or owned-less set after a failed scan; that is rare (no failures logged so far), and the rows recover on the next good report. Upgrading pi1 and mohiguide is an ops step after release (Joe approves host changes).
- **Agent restart with an empty first report.** Rows flip to gone and back within one report cycle. That is harmless (no data lost), but visible in the console for up to 300 s. Accepted.
- **Shared hosts.** A report from a host shared with this project at `deploy` level marks gone rows of the other project too. That is correct (they are not running), and the view rules still decide who sees them.

## 10. Delegation

Grok workers in worktrees, as in earlier waves: one for API + migration, one for console, one for MCP, one for the agent fix. Fresh Grok sessions review per lens (spec, security, tests, ui). The orchestrator runs the gates, the migration and the live check, and commits/pushes only on Joe's approval.
