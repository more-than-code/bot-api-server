# Spec: shared hosts (one owning project, explicit shares, services per project)

**Date:** 2026-10-14
**Status:** Approved by Joe 2026-10-14 (Tier 3)
**Design:** amends [design-bot-agent-deploy.md](design-bot-agent-deploy.md) D21 ("a host belongs to exactly one project") and §2 permissions.
**Contracts:** api-v1 → **v1.1** (additive, plus one filtering change); agent protocol unchanged.

## 1. Goal

One physical host (e.g. pi1, which runs Tour Agent, Tutored, and Briefed) can serve several projects without one project's members seeing or controlling another project's services.

## 2. Approach

**Chosen: an owning project, explicit shares, and services assigned to projects.**
- A host keeps exactly one **owning project**: the one whose join token enrolled it. That project's admins manage the host's credential, revocation, and shares.
- The owner's admins can **share** the host with another project at one of two levels:
  - `metrics`: host status and host-wide charts;
  - `deploy`: metrics, plus managing that project's own services on the host. Its actions arrive in phase 2.
- Every service has a `project_id`. Discovered services default to the owning project. In phase 2 a deploy from a sharing project assigns that project. Service-level reads and actions check the **service's** project.

**Rejected:**
- **Plain many-to-many host↔project.** Members of any attached project would see every process and could, in phase 2, control every service on the host. That breaks project isolation.
- **Several agents per host, one per project.** It duplicates collection, needs several credentials for one machine, and still leaks host-wide data.
- **Do nothing.** One "Home Lab" project works for phase 1, but phase 2 actions on a shared box would have no per-project boundary.

## 3. Changes

| Area | Change |
|---|---|
| bot-api-server: migration `0003_shared_hosts.sql` | Table `app.host_shares(host_id uuid FK hosts ON DELETE CASCADE, project_id uuid FK projects ON DELETE CASCADE, level text CHECK (level IN ('metrics','deploy')), created_by uuid, created_at timestamptz, PRIMARY KEY(host_id, project_id))`. The owning project cannot also be a share (enforced in a trigger or in the API). `app.services.project_id uuid NOT NULL REFERENCES app.projects`, backfilled from `hosts.project_id`; index `(project_id)`. Grants follow the existing default privileges. |
| bot-api-server: authz | New relation lookup `HostRelation(user, host) → {owner role | share level + role in the sharing project | none}`, used in place of "member of `host.project_id`" (matrix in §4). Service-level checks use `services.project_id` plus the host relation. |
| bot-api-server: API | Contract v1.1 (§5). |
| bot-api-server: agent WS | Unchanged. New discovered services get `project_id` = the host's owning project. |
| bot-console | Project → Hosts lists owned and shared hosts, with a "shared by {project} ({level})" badge. The host page gets a **Sharing** section for owner admins: list, add by project, change level, remove. Tabs are filtered by the relation (§4). |
| bot-mcp-server | `list_hosts` returns shared hosts too, with `relation`. Nothing else changes, because the API filters. |
| Docs | Design D21 amended to D34; §2 matrix replaced by §4 below; api-v1 v1.1; console design; AGENTS.md. |

## 4. Permission matrix

The relation is computed per (user, host). "Owner viewer/admin/owner" is the user's role in the **owning** project. "Share X" means the user is a member of a project the host is shared with at level X; the user's role there is shown in brackets.

| Capability | Owner viewer | Owner admin+ | Share `metrics` (any role) | Share `deploy` [viewer] | Share `deploy` [admin+] | None |
|---|---|---|---|---|---|---|
| See host in project list, status | ✓ | ✓ | ✓ | ✓ | ✓ | 404 |
| Host metrics charts | ✓ | ✓ | ✓ | ✓ | ✓ | 404 |
| Host-wide process list, `host_snapshot` | ✓ | ✓ | ✓ | ✓ | ✓ | 404 |
| Services list | all | all | ✗ 403 | own project's only | own project's only | 404 |
| Processes list | all | all | all | all | all | 404 |
| Probe / health history (service) | ✓ | ✓ | ✗ | own services | own services | 404 |
| Edit health checks (service) | ✗ | ✓ | ✗ | ✗ | own services | 404 |
| Phase 2: logs | ✓ | ✓ | ✗ | own services | own services | 404 |
| Phase 2: deploy / run / stop / redeploy | ✗ | ✓ (all services) | ✗ | ✗ | own services; deploy assigns own project | 404 |
| Manage shares, revoke credential | ✗ | ✓ | ✗ | ✗ | ✗ | 404 |
| Leave a share (remove own project's share) | — | — | admin+ of sharing project | — | admin+ of sharing project | — |

**Amendment 2026-10-14 (Joe: "processes per host should be visible to all members"; contract api-v1 v1.1.1):** the process list and `host_snapshot` are host-level OS facts. Every member of the owning project or of any sharing project, at any share level and any role, sees the full, unfiltered process list and may take a snapshot. Services, probe, health history, health-check edits and phase 2 actions stay per project as above. The isolation trade-off in §2 is accepted for processes: cmdlines are redacted (agent protocol v1.0.3) and no service can be controlled through the process list.

Owner admins keep full control of every service on their host, including services assigned to a sharing project. Owning the machine means you can always stop what runs on it.

## 5. Contract diff (api-v1 v1.0.2 → v1.1)

Before → after:

- `Host` gains `"relation": "owner" | "shared"` and `"share_level": "metrics" | "deploy" | null`.
- `GET /v1/projects/{id}/hosts`: before, hosts with `project_id = id`. After, also hosts shared with project `id` (`relation: "shared"`).
- `Service` gains `"project_id"`.
- `GET /v1/hosts/{id}/services` and `GET /v1/hosts/{id}/processes`: before, all rows for any project member. After, filtered by §4. For a sharing project, processes are those whose `service_id` is one of its services.
- `POST /v1/hosts/{id}/snapshot`: owner-project members only (403 for shares). *Amended by v1.1.1: any member who can see the host; processes are unfiltered for every member.*
- **New:**
  - `GET /v1/hosts/{id}/shares` (owner admin+) → `{"items":[{"project_id","project_name","level","created_by","created_at"}]}`.
  - `PUT /v1/hosts/{id}/shares/{project_id}` (owner admin+), body `{"level":"metrics|deploy"}` → upsert, 200. The caller must also be a member (any role) of the target project, so projects can't be enumerated.
  - `DELETE /v1/hosts/{id}/shares/{project_id}` (owner admin+, or admin+ of that project) → 200. Returns 409 `conflict` if that project still has services on the host, unless `?reassign=owner` moves them to the owning project.
- **Audit actions:** `host.share`, `host.share_update`, `host.unshare`.

Compatibility: every consumer is ours (console, MCP) and ships in the same wave. The new fields are additive; the filtering change only narrows what shared projects see.

## 6. Acceptance criteria

1. The migration applies on `deploybot_test` and `deploybot`. Existing services are backfilled to their host's project with no nulls, and `deploybot_api` grants are unchanged apart from the new table (same §6.3 rules: app CRUD).
2. Every cell in §4 has an HTTP-level test against the real mux and memstore, and a subset runs against Postgres in `TestIntegration`.
3. Sharing a host with project B shows it in B's host list with `relation: "shared"`. Removing the share hides it again (404 for B's members).
4. A `metrics` share can read charts, the full process list and the snapshot, but gets 403 on services, probe and health history (amended v1.1.1).
5. A `deploy` share sees only its own services, and the full host process list (amended v1.1.1). An owner admin still sees and controls all of them.
6. Unshare with remaining services gives 409; `?reassign=owner` succeeds and moves them.
7. The console shows owned and shared hosts with a badge, the Sharing section (owner admins only), and tabs filtered per §4.
8. MCP `list_hosts` includes shared hosts. Tool results for a shared host match the API's filtering.
9. Every share change is audited.

## 7. Tests

New: the authz matrix (table-driven over §4 cells); share CRUD including the enumeration guard, 409/reassign, and cascades on project or host delete; filtering on services and processes; migration backfill in integration; console load/action tests for the Sharing section and badges; MCP `list_hosts` with shared hosts. Regression: every existing suite.

## 8. Verification gates

bot-api-server: `go build/vet/test`, `gofmt`, `TestIntegration` on `deploybot_test` (run by the orchestrator), migration on `deploybot`, and the grant check. bot-console: `pnpm check` 0/0, test, build. bot-mcp-server: `go` gates. Live: share pi1 from "Home Lab" with a second project and walk §4 in the browser.

## 9. Rollback

Migration `0003` has a documented down script (drop `host_shares`, drop `services.project_id`). The column contents are derivable from `hosts.project_id` until phase 2, so nothing is lost before deploys exist. API and console roll back by reverting the wave's commits; the agent is unaffected.

## 10. Failure modes considered

- A share is removed while a sharing user has the page open: the next load returns 404 and the console shows "no longer shared".
- The owning project is deleted: its hosts' credentials are revoked (existing behaviour), and shares cascade away.
- A sharing project is deleted: its share cascades. Its services on the host go back to the owner (the same move as `reassign=owner`, in the delete transaction).
- A user is a member of both the owner and a sharing project: the most permissive relation applies (owner).

## 11. Placement

Proposed: its **own small wave right after the console restructure** (wave 1d), before any phase 2 work, so phase 2 builds on per-service ownership from day one.
