# Spec: Services under the project, processes under the host, service names (api-v1 v1.2 + v1.3)

**Tier:** 3 (public API contract, DB migration, console navigation, MCP tool surface)
**Status:** Approved 2026-10-14 (Joe: "yes, approve the spec")
**Requested by:** Joe, 2026-10-14: "How about move services under the project, only processes under the host?" and "Service name is meaningless; table should be paged, sortable, searchable" (decision: editable names plus a better default, no CAP_SYS_PTRACE).
**Builds on:** `docs/spec-shared-hosts.md` (§4 matrix, amendment v1.1.1), contract `docs/contracts/api-v1.md` v1.1.1 and v1.2 (frozen, not yet implemented), agent protocol v1.1 (`Discovered.user`, shipped in bot-agent `da0b547`).

## 1. Goal

A service belongs to a project (`services.project_id`, v1.1); a process is an OS fact of a host (v1.1.1). The console should follow that model:

- **Project page** gets a **Services** tab: every service the project can see, across all its owned and shared hosts, with a Host column. It is paged, sortable and searchable on the server. Services carry a human name.
- **Host page** keeps **Overview + Processes** only.

## 2. Approach and rejected alternatives

**Chosen:** one new project-scoped list endpoint with server-side search, sort and paging, and the already-frozen v1.2 naming fields, implemented in the same round. The table is rebuilt once.

Rejected:

- **Aggregate in the console** by calling `GET /v1/hosts/{id}/services` once per host. That needs N requests, cannot sort or page globally, and repeats permission logic in the console.
- **Keep Services under the host.** On a shared host a project's members would see a host tab that silently hides other projects' services. The page structure would contradict the data model.
- **Keyset (seek) cursor.** It is correct at any size, but Prev links and "page x of y" without JavaScript need a cursor stack. Projects have hundreds of services, not millions. An opaque cursor that encodes an offset, plus `total`, is simpler and enough. It can become keyset later without a contract change, because the cursor is opaque.

## 3. Changes

| Repo | Change |
|---|---|
| bot-api-server | Migration `0004_service_names.sql`, with a hand-run `0004_service_names.down.sql`: `services.display_name text NULL`, `services.owner_user text NULL`, a unique index on `(host_id, lower(display_name)) WHERE display_name IS NOT NULL`, and an index for project listing on `(project_id)`. The agent ingest stores `Discovered.user` into `owner_user`; rediscovery never touches `display_name`. `PATCH /v1/services/{id}` (v1.2). `GET /v1/projects/{id}/services` (v1.3). Audit `service.rename`. Store, memstore and DB updated in parallel, filtering in SQL. |
| bot-console | Project page: new **Services** tab (DataTable in server mode). Host page: drop the Services tab, keep Overview + Processes. Probe and the rename form move to the project Services rows. Labels follow v1.2 item 4. Process rows link their service to the owning project's Services tab when the caller is a member of that project; otherwise the label is plain text. Old links `?tab=services` on a host page redirect to the owning project's Services tab, filtered to that host. |
| bot-mcp-server | `list_services` takes exactly one of `host_id` or `project_id`, plus optional `q`, `sort`, `dir`, `limit` and `cursor`, passed through. Summaries use the v1.2 label. No rename tool in this round. A write tool needs the server-enforced confirmation flow (D-later). |
| bot-agent | None. `Discovered.user` already ships. |
| umbrella | Contract v1.3 section in `docs/contracts/api-v1.md`, copied to the four repos; design doc §6/§7 notes; this spec. |

## 4. Contract diff

### v1.2 (already frozen; implemented in this round, unchanged)

`Service` gains `display_name` and `owner_user`. `PATCH /v1/services/{id}` with `{"display_name": "<name>" | null}`. The permission is the service *edit* capability of shared-hosts §4. Audit `service.rename`. The name is unique per host, case-insensitive (a duplicate returns `conflict`). The agent never overwrites it. Client label: `display_name`, otherwise `name` unless it is `port-<n>`, otherwise `port <n> · <owner_user>` (or `port <n>`).

### v1.3 (new)

1. **`GET /v1/projects/{id}/services`**. The caller must be a member of project `id` (any role); otherwise `not_found`.
   - **Rows:** services on hosts owned by `id` (every service, whatever its project, because owner-project members see everything), **plus** services whose `project_id = id` on hosts shared with `id` at level `deploy`. Services of `id` on a host where the share is now `metrics` are excluded, which matches the §4 `metrics` share 403.
   - **Row shape:** `Service` plus `"host_name"`, `"host_status"` and `"project_name"` (the service's project).
   - **Query:**
     - `q`: case-insensitive substring over `display_name`, `name`, `kind`, `host_name`, `owner_user`, and ports as text; trimmed; at most 100 characters; otherwise `bad_request`.
     - `host_id`: optional; must be a host the row rules above reach; otherwise `bad_request`.
     - `sort` ∈ `name` (sorts by `lower(coalesce(display_name, name))`), `host`, `kind`, `status` (health status, then name), `last_seen`. The default is `name`.
     - `dir` ∈ `asc`, `desc`. The default is `asc`, except `last_seen` defaults to `desc`.
     - `limit` 1–200, default 50.
     - `cursor` (opaque).
   - Ties are always broken by `id`.
   - **Payload:** `{"items":[...], "next_cursor": "<opaque>|null", "prev_cursor": "<opaque>|null", "total": <int>}`. A cursor is bound to its `q`, `host_id`, `sort` and `dir`. Reusing it with different ones returns `bad_request` ("cursor does not match query").
2. **`GET /v1/hosts/{id}/services` is unchanged** (the v1.1 filtering, ≤ 500 items). It stays for MCP and per-host use. Its rows also gain the v1.2 fields.
3. **Permissions are not widened.** Each row returned by (1) is a row the caller could already read through `GET /v1/services/{id}`.

## 5. Acceptance criteria

1. Migration 0004 applies on `deploybot_test` and `deploybot`. Existing rows have `display_name` NULL. The grants for `deploybot_api` are unchanged (column additions only). The down script restores the 0003 shape.
2. After the next discovery batch from pi1, `owner_user` is filled for socket-owning processes, and `port-<n>` services show `port <n> · <user>` in the console.
3. `PATCH /v1/services/{id}`:
   - It sets, clears and trims the name.
   - Bad length or characters return `bad_request`.
   - A duplicate on the same host, differing only in case, returns `conflict`.
   - Owner viewer, `metrics` share and `deploy`-share viewer get 403. Owner admin+ gets 200. A `deploy`-share admin gets 200 on its own project's services and 403 on others.
   - An audit row `service.rename` records old → new.
   - Rediscovery keeps the name.
4. `GET /v1/projects/{id}/services` returns exactly the §4 rows for every actor. The HTTP matrix test runs against memstore, and a subset runs in Postgres `TestIntegration`:
   - Owner project: all services on its hosts.
   - Sharing project at `deploy`: only its own services on shared hosts, plus everything on hosts it owns.
   - At `metrics`: no rows from that host.
   - Non-member: 404.
5. Search, sort, `dir`, `host_id`, paging, `total`, prev/next and the cursor-mismatch `bad_request` are each covered by tests on both stores. Ordering is stable with ties.
6. Console: project **Services** tab with paging, sorting and search through the API (the URL keeps `services.*` params; works without JavaScript). Host page shows Overview + Processes only. `?tab=services` on a host page redirects to the project tab with `services.host=<id>`. Probe and rename work from project rows and keep the table state. `components-reuse.test.ts` still passes.
7. MCP `list_services` with `project_id`: the parameters pass through. Exactly-one-of `host_id`/`project_id` is validated. The summary uses the v1.2 label.
8. All gates pass in every touched repo.

## 6. Rollback

- **API:** revert the commits and hand-run `0004_service_names.down.sql`. It drops the two columns and the index; names typed by people are lost, and the down script says so. 0003 is untouched.
- **Console and MCP:** revert the commits. The old host Services tab comes back. It only reads `GET /v1/hosts/{id}/services`, which is unchanged.
- **Order:** roll back the console and MCP first, then the API. The API change is additive, so old clients keep working against the new API.

## 7. Failure modes

| Case | Handling |
|---|---|
| Rename races rediscovery | Rediscovery updates only discovered columns; `display_name` is written only by PATCH. The unique index catches concurrent duplicate renames, and the loser gets `conflict`. |
| Cursor after rows change | Offset paging can skip or repeat a row when rows are inserted or deleted between pages. Accepted at this scale and documented in the contract. `total` is recomputed on every request. |
| A share is downgraded to `metrics` while its services remain | Those rows drop out of the project list (§4). They come back if the share returns to `deploy`. The data is unchanged. |
| A host is unshared with `?reassign=owner` | Its rows move to the owner project's list on the next request. |
| An old bookmark to the host Services tab | Redirects to the project tab (AC 6). |

## 8. Tests

- **New:**
  - Migration 0004, plus the down script parsing.
  - PATCH matrix and audit.
  - The project list matrix.
  - Search, sort, paging and cursor on memstore and Postgres.
  - Ingest of `owner_user`.
  - Console: Services tab load and actions, label function, host-page redirect, process-to-service link rule.
  - MCP: `list_services` argument validation and pass-through.
- **Updated:** host-page tests (no Services tab), and the shared-hosts matrix rows for services (unchanged results).
- **Regression:** full suites in API, console and MCP; `TestIntegration` on pi4.

## 9. Verification gates

- **API:** `go build ./...`, `go vet ./...`, `go test -count=1 ./...`, `gofmt -l cmd internal migrations` (prints nothing). `TestIntegration` on pi4 `deploybot_test`. After approval to migrate: `--migrate` on `deploybot` and a grant check showing 0 failures.
- **Console:** `pnpm check` (0 errors, 0 warnings), `pnpm test`, `pnpm build`.
- **MCP:** the same Go gates.
- **Live:** pi1 rediscovery fills `owner_user`, the project Services tab lists pi1's services, and a rename persists across a discovery batch.

## 10. Applicable skill guidance

- **api-contracts:** additive fields, a new route, an opaque cursor, and an unchanged old route. Consumers (console, MCP) are ours and ship in the same wave.
- **data-migration:** column additions are online-safe. The unique index is partial and small, and its down script is documented and not applied automatically.
- **security-baseline:** `display_name` is validated at the boundary (1–64 printable characters, trimmed) and rendered escaped. `q` is length-capped and parameterized (no `LIKE` pattern injection: `%` and `_` are escaped). Permissions are not widened (§4 item 3).
- **frontend-engineering / ui-portability-baseline:** DataTable gains a server mode instead of a second table component. Shared components stay the only path (`components-reuse`).

## 11. Delegation plan

The workers are Grok, run in parallel waves:

1. **API** (v1.2 + v1.3), first.
2. **Console and MCP**, in parallel against the frozen v1.3 section once it is written. Their tests use mocked `fetch` or a fake API until the API merges.

Reviews are independent Grok lens sessions: security, spec and tests per repo. The orchestrator runs the gates, the pi4 integration test and the live check.
