# Spec: Catalog wave 2b — managed files for image entries

**Status:** revision 1 **approved by Joe 2026-10-16 ("yes", F1–F5 defaults)**.
**Tier:** 3 (api-v1, agent-protocol, root helper on hosts, migration 0010, console)
**Builds on:**
- `docs/spec-catalog-images.md` rev 3 and its §13 (wave 2a, done on dev 2026-10-16);
- mohiguide decision 2, file half (`tasks/ops/mohiguide.md`): "Secret files encrypted and config files plain, … mounted read-only";
- the pi3 mirror plan (`tasks/ops/pi3-mohiguide-mirror.md`), where `mo-services` is blocked on this wave.

## 1. Goal

An image entry can mount small files that the project owns, read-only, at a path inside the container. This replaces compose bind mounts such as:
- `./fcm-mohiguide.json:/run/secrets/fcm-mohiguide.json:ro` (secret: a Firebase service-account key read through `GOOGLE_APPLICATION_CREDENTIALS`);
- `mohiguide.conf` for nginx (config: plain text).

The first users are `mo-services` on pi3 (the dev mirror), then on the HK host.

Out of scope: binary files, files larger than 64 KiB, writable files, shared files between projects, and `depends_on` or stacks.

## 2. Decisions proposed (Joe to confirm; defaults marked)

| # | Question | Default | Alternative |
|---|---|---|---|
| F1 | How the file reaches the container | **The root helper writes it to its own root-only directory and bind-mounts it read-only.** The source path is derived by the helper, never sent. | Upload a tar into the created container (`PUT /containers/{id}/archive`) before start. No host file, but the file lands in the writable layer, so `read_only` cannot be enforced. |
| F2 | Who writes on the host | **The helper (root), not the agent.** Decision 2 said "written by the agent to its own path"; that was written for the rev 1 proxy. An agent-owned directory that is bind-mounted would let a compromised agent plant a symlink. Docker resolves a bind source as root, so the next deploy would mount any host file (for example `/etc/shadow`). | The agent writes under `/var/lib/bot-agent` (rejected: the symlink hole above). |
| F3 | File mode inside the container | **0444, owner root.** Any container user can read it, which a non-root app needs. The host directory is 0700 root, so other host users cannot. | An optional `uid` per mount with mode 0400. |
| F4 | Content | **UTF-8 text, ≤ 64 KiB, no NUL.** Covers JSON keys, PEM, and nginx conf. | Base64 binary. |
| F5 | Changed content | **The next deploy recreates the container** (not `unchanged`). Content changes do **not** void a shared-host approval, like env values in 2a. | Content changes void the approval too. |

## 3. Threat model additions (on top of spec-catalog-images §3)

1. **Bind source never from the request.** The helper builds `Source = /var/lib/bot-agent-runner/files/<slug>-<entry>[-prev]/<file>` itself. `<file>` follows the file-name rule (§4.1). The request carries only names, targets and content.
2. **No symlink or path escapes.** The helper creates the base and slot directories itself (0700 root). It writes with `openat` relative to an open directory handle, `O_NOFOLLOW|O_CREAT|O_EXCL`, to a temporary name, then `renameat`. Before create it checks with `lstat` that every component is a regular directory or file owned by root. If anything is wrong, the deploy is refused with `forbidden_spec`.
3. **Always read-only.** `Mounts[].ReadOnly = true` is fixed by the helper. There is no `BindOptions`, so propagation stays Docker's default `rprivate`.
4. **Agent cannot read the store.** The agent unit gains `InaccessiblePaths=-/var/lib/bot-agent-runner`. The agent sees secret contents only inside the task frame, the same trust as env values (images §3.4).
5. **Secret file contents are redacted** like env values, by exact-value matching. The whole content is matched, plus every line of at least 16 bytes after trimming, so a private key line printed alone is caught.
6. **Never via MCP:** no tool reads or writes project files. `list_catalog` shows file names only.

## 4. Design

### 4.1 Project files (API)

- **New table `app.project_files`:** `project_id`, `name`, `is_secret`, `content` (plain text, or AES-256-GCM ciphertext with `key_version` for secrets, the same key as env sets), `sha256`, `size`, `updated_by`, `updated_at`. Primary key `(project_id, name)`.
- **Name rule:** `^[a-z0-9][a-z0-9._-]{0,63}$`. Not `.` or `..`, and no `/`.
- **Limits:** 64 files per project, 64 KiB per file.
- **Routes** (owner/admin, console sessions only, like env sets; a delegated or MCP token is `forbidden`):
  - `PUT /v1/projects/{id}/files/{name}`, body `{"content": "…", "secret": true}`. `secret` defaults to `true`. This replaces the content.
  - `GET /v1/projects/{id}/files`: names, `is_secret`, `size`, `sha256` (secret files: `null`), `updated_at`. Never the content of a secret file.
  - `GET /v1/projects/{id}/files/{name}`: the content of a plain file only. A secret file → `forbidden`.
  - `DELETE /v1/projects/{id}/files/{name}`: refused with `conflict` while an entry references the file.
- **Audit:** `file.put`, `file.delete`, with names only.

### 4.2 Image entry spec

The spec gains `files`:

```json
"files": [
  {"file": "fcm-mohiguide.json", "target": "/run/secrets/fcm-mohiguide.json"},
  {"file": "mohiguide.conf", "target": "/config/nginx/site-confs/mohiguide.conf"}
]
```

- `file` must name an existing project file. An unknown file → `bad_request` on save, and again at deploy if it was deleted since.
- `target`:
  - absolute, normalised, no `.` or `..`;
  - not `/`, and not under `/proc`, `/sys` or `/dev`;
  - unique across `files` and `volumes` targets, and not inside a volume target.
- At most 16 files per entry. The resolved total must fit the task frame (the existing frame check in agent-protocol v1.4.1 returns `bad_request`).
- `spec_hash` covers the `files` list (names and targets), not content.

### 4.3 Agent protocol (v1.5)

- `image_deploy` and `image_rollback` task specs gain `files: [{"name","target","content","secret"}]`. Content is resolved by the API, like `env`. Task records keep `name` and `target` only.
- The agent adds secret contents and their lines (§3.5) to that task's redaction set and passes `files` to `container_deploy`.

### 4.4 Helper (`bot-agent-runner`)

- **Unit:** `StateDirectory=bot-agent-runner`, `StateDirectoryMode=0700`. The agent unit gains `InaccessiblePaths=-/var/lib/bot-agent-runner`. These are host security files, so Joe reviews them before install.
- **`container_deploy`** (under the entry flock, alongside the existing slot handling):
  1. writes the files into a new slot `files/<slug>-<entry>.new/` (0700 root; files 0444, root);
  2. on the existing rename to `-prev`, also renames `files/<slug>-<entry>` to `files/<slug>-<entry>-prev`, after removing any older `-prev` slot;
  3. renames `.new` to `files/<slug>-<entry>`;
  4. adds to `HostConfig.Mounts` one `{Type: "bind", Source: <slot>/<name>, Target, ReadOnly: true}` per file.
- **`container_rollback`** swaps the file slots together with the containers.
- **`container_remove`** removes that container's slot.
- **Leftovers:** a slot without a container (for example after a crash) is removed on the next deploy of that entry.
- **Change check:** the container label `dev.deploybot.files_hash` = SHA-256 of the sorted `name:sha256` pairs. A deploy whose digest, spec hash and files hash all match is `unchanged`; otherwise it recreates (F5).

### 4.5 Console

- **Project → Settings → Files:**
  - a list with name, secret or plain, size and updated time;
  - **Add / replace:** a name, a paste box (never pre-filled, cleared after save) and a secret toggle (on by default);
  - plain files can be viewed; secret files never;
  - delete with a confirmation, with the `conflict` message naming the entries.
- **Container form:** file rows (a select of project files, plus a target), and the `docker run` preview shows `-v <file>:<target>:ro`.

### 4.6 MCP

No file tools. `list_catalog` shows file names only. Targets are dropped, as it already does for volume targets.

## 5. Contract diff (summary)

| Contract | Before | After |
|---|---|---|
| api-v1 v1.9 | no project files; image spec without `files` | `/v1/projects/{id}/files` routes (§4.1); image spec `files` (§4.2); audit `file.put`, `file.delete` |
| agent-protocol v1.5 | `image_deploy`/`image_rollback` without files | `files` in those specs (§4.3); helper `container_deploy` accepts `files`; label `dev.deploybot.files_hash` |
| Migration 0010 | — | `app.project_files` (+ hand-run down) |

## 6. Acceptance criteria

1. A secret file saved in the console is stored as ciphertext. `GET` never returns its content, and the API log, audit and task records never contain it.
2. An entry with `files` deploys on pi3. Inside the container each file is at its target, read-only (a write fails with `EROFS`), mode 0444. `mo-services` starts with `GOOGLE_APPLICATION_CREDENTIALS` pointing at the mounted key.
3. On the host, `/var/lib/bot-agent-runner/files` is root 0700, and the `bot-agent` user cannot list it.
4. A planted symlink in a slot makes the next deploy fail `forbidden_spec`, and nothing is mounted.
5. Redeploy with the same content → `unchanged`. Changed content → recreated. Rollback restores the previous content with the previous container.
6. An unhealthy deploy rolls back containers and file slots together.
7. A secret file's content (or one line of it) printed by the container is redacted in the log tail and in `container_logs`.
8. Deleting a file that an entry references → `conflict`. Removing the entry's container removes its slot.
9. MCP has no file tools. `list_catalog` shows file names only.
10. An entry without `files` behaves exactly as in 2a (regression).

## 7. Rollback

- **Per host:** an entry without `files` needs nothing new. Reverting the helper and agent binaries to 9ea5177 refuses `files` specs (unknown key), and existing containers keep running with their mounts. Slots under `/var/lib/bot-agent-runner/files` can be removed by hand.
- **API:** migration 0010 has a hand-run down. Entries with `files` must be edited first.

## 8. Tests

- **Helper:**
  - slot write, rename and rollback;
  - a symlink, a non-root owner or a wrong mode in a slot → refused;
  - the create body has bind mounts with `ReadOnly=true` and nothing else new;
  - target rules.
- **Agent:** files passed through; secret content and lines redacted in results and logs; task records without content.
- **API:**
  - routes, the role and session gate, encryption round trip, `GET` never showing secret content;
  - spec validation; delete `conflict`;
  - frame-size refusal with files;
  - migration up and down on `deploybot_test`.
- **Console:** settings form (paste never pre-filled, cleared after save), container form file rows, preview.
- **Live (pi3, dev Mohiguide):** AC2–AC7 with a test Firebase key and a test conf.

## 9. Delegation

As in wave 2a: Grok workers in `../work-<slug>` worktrees.
- **Workers:** helper + agent (bot-agent), API (bot-api-server), console (bot-console). MCP is only the `list_catalog` field.
- **Frozen first:** the contract sections are frozen in the umbrella before dispatch, and each worker publishes response fixtures that the console tests against (lesson 2026-10-16).
- **Reviews:** fresh Grok sessions per lens, with a security pass on the helper diff.
- **Gates and live check:** run by the orchestrator, which commits only on Joe's request.

## 10. Contract freeze notes (2026-10-16)

Frozen as api-v1 **v1.9** and agent-protocol **v1.5**. Details added while freezing, all within the approved design:
1. **`hello.programs.files`:** the API refuses to deploy an entry with files to a host whose agent does not report `files: true`. Older agents (pi1, mohiguide at 878700c) get a clear `bad_request` instead of a confusing failure.
2. **Limits:**
   - the helper accepts image-verb requests up to 2 MiB (it was 64 KiB, which one 64 KiB file plus env would exceed);
   - the `container_logs` `redact` list grows to 2048 values and 512 KiB.
3. **Redaction (§3.5):** also covers JSON string values and the lines inside them, because an app that logs its parsed Firebase key prints the PEM lines, not the JSON file's lines.
4. **Stale slot cleanup:** runs at the start of each deploy of that entry.

