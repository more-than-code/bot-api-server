# Spec: Catalog wave 2a — container images (Docker through the root helper)

**Status:** revision 3 (2026-10-15). Revision 2 was approved by Joe ("yes", O1–O8) on condition that the second Grok security pass found no Critical; it found one (entry name interpolated into Engine paths), so revision 3 adds tightenings only (§12). **Revision 3 approved by Joe 2026-10-15 ("yes").**
- Revision 1 was approved on condition that the Grok security review only tightened it ("go ahead", defaults O1–O7).
- The review (fresh Grok session, security + architecture lens, verdict **rework**) found three Critical and six High design holes in the HTTP pass-through proxy. The fix changes the design: typed helper verbs replace the proxy. So this revision comes back for approval.
- Revision 1 → 2 changes are listed in §11.

**Tier:** 3 (api-v1, agent-protocol, root helper on hosts, migration, console, MCP)
**Builds on:**
- `docs/spec-project-catalog.md` (§3.1 image spec, §3.1a container form, §7a sequencing);
- the design `docs/design-bot-agent-deploy.md` §5.2–5.4, D25/D30/D31 (D26 is replaced, §11);
- the wave 1 root helper `bot-agent-runner`;
- the six mohiguide decisions and the webadmin pilot (Joe, 2026-10-15, relayed by the ops session).

## 1. Goal

Run containers from the project catalog the way wave 1 runs programs. The owner defines an image entry once. Members with permission deploy, redeploy, roll back, start, stop, restart and read logs on a chosen host. Everything goes through the agent, the root helper and the host's `runner.toml`.

**First real use: mohiguide** (PRODUCTION, Docker 29.8.1, amd64).
1. The **webadmin pilot**: a one-shot job that fills a named volume from a private ghcr.io image. It runs in shadow mode with no production effect.
2. Then the full move of its compose services, one at a time, in planned windows (that needs wave 2b's managed files).

pi3 (Debian 12 arm64, Docker 29.9, no containers) is the dev live-check host, before the mohiguide pilot. It replaced pi1 (Joe, 2026-10-15, AskUserQuestion) because its Docker is clean.

## 2. Scope

| | **Wave 2a** (this spec) | **Wave 2b** (next spec) |
|---|---|---|
| Docker access through typed root-helper verbs | yes | — |
| Image entries: `service` and `job` kinds, `command` / `entrypoint` | yes | — |
| Deploy, redeploy with `-prev` rollback, digest pinning + history (N=3), manual rollback | yes | — |
| Registry credentials (decision 1) | yes | — |
| Project env sets, paste .env, secret by default (decision 4) | yes | — |
| Named volumes, per project, `read_only` (decision 2, volume half) | yes | — |
| Per-project network with entry aliases (decision 3) | yes | — |
| Container discovery with real names (owned and other containers), read-only | yes | — |
| Managed files mounted read-only (decision 2, file half) | — | yes |
| `depends_on`, deploy stack, `networks` field, in-network health check | — | later |

Adopt (design §5.2) is dropped. Joe chose route B, and compose containers still get their names through read-only discovery.

## 3. Threat model

Access to the Docker socket equals root on the host. The design holds these lines:

1. **One root process opens `/var/run/docker.sock`: the existing helper `bot-agent-runner`.** The agent stays unprivileged; its unit and sandbox are unchanged, including `InaccessiblePaths=` on the Docker sockets.
2. **No pass-through.** The agent sends typed JSON verbs, one per connection (the wave 1 framing). The helper builds every Docker Engine request itself, from typed fields, with a fixed body shape. Nothing the agent sends reaches Docker as raw HTTP: no client path, no query, no header, no body. So request smuggling, upgrades, `exec`, `attach` and `archive` are not reachable.
3. **Project scoping on the host.** `runner.toml` lists the project slugs this host may run containers for. The helper sets the labels `dev.deploybot.owner=bot-agent`, `dev.deploybot.host=<host id>`, `dev.deploybot.project=<slug>` and `dev.deploybot.entry=<entry>` itself. Every mutating verb acts only on a container whose four labels match the request. Volumes and the network are named and checked per project.
4. **Secrets boundary, stated honestly.** Env values and registry tokens reach the agent in the task frame and are passed to the helper for that task. A compromised agent can therefore read the secrets of the tasks it receives. That is the same trust the agent already has for its host; sealing values to the helper is a later option (§10 O8).
   - The helper never returns them: list, status and inspect results are projections without env, command, mounts or host config.
   - Results, logs and audit are redacted with the design §5.4 regex **and** exact-value matching (raw, base64 and JSON-escaped forms). The exact-value marker is `[REDACTED]`.
5. **A compromised API or agent can ask for anything the policy allows, but no more.** That means: the image patterns, the listed projects, project-scoped volumes and network, and no host bind mounts, privilege, devices, extra capabilities, host namespaces or public ports (unless the policy allows public ports).

## 4. Design

### 4.1 Host side: helper verbs

`bot-agent-runner` (bot-agent repo) gains image verbs. It keeps the wave 1 transport:
- socket activation with `Accept=yes`, one process per connection;
- `SO_PEERCRED` = bot-agent;
- JSON in and out, with size limits.

Two changes to its units:
- `ReadWritePaths=/var/run/docker.sock` is added to the helper service.
- `RuntimeMaxSec` goes from 60 to 900, because an image pull can take minutes.

It talks to the Docker Engine API (`/v1.47`, supported by Docker 29) through its own HTTP client on the unix socket.

**Locks:**
- the wave 1 helper-wide flock stays for program verbs;
- image verbs take a flock per `(project, entry)`, held from the first inspect to the last mutation of that verb, so two deploys of one entry cannot interleave. The API also allows only one in-flight deploy/rollback per (host, project, entry).

**Verbs** (all validate against `runner.toml` first; `project` must be in `projects`, `entry` must match the entry rule):

| Verb | Input | What the helper does |
|---|---|---|
| `image_pull` | `project`, `ref`, `auth?` `{username, token}` | Parses `ref` with the Docker reference grammar. Normalised registry host + path must match an `images` pattern: anchored, `*` = exactly one path component, the host matched literally. Calls `POST /images/create` with exactly `fromImage` and `tag` (or digest), nothing else. `X-Registry-Auth` is built from `auth` only when `auth.registry` equals the parsed host. Returns the repo digest and the image id. |
| `container_deploy` | `project`, `entry`, typed spec (§4.2) with resolved `env` values, `digest` | See §4.3. Builds the create body from typed fields only. |
| `container_rollback` | `project`, `entry` | Swaps `<name>-prev` back into place (§4.3). |
| `container_start` / `stop` / `restart` | `project`, `entry` | Only on the container whose four labels match. `stop` waits up to 30 s. |
| `container_remove` | `project`, `entry` | Stops if running, then removes the container (never volumes, no `v`). Used for job re-runs and an explicit "remove" action. |
| `container_logs` | `project`, `entry`, `tail` ≤ 2000 | Non-follow logs, same 64 KiB cap and redaction as programs. |
| `container_status` | `project`, `entry` | Projection: state, exit code, restart count, started/finished times, image digest, ports. |
| `container_list` | — | Projection of **all** containers: id, name, state, published ports (host ip/port → container port), image digest, the four `dev.deploybot.*` labels (other labels dropped). |

**The create body is built, never forwarded.** The helper constructs a Docker `ContainerCreate` body with exactly these fields:
- `Image` = `repo@sha256:<digest>`;
- `Cmd` / `Entrypoint` from the spec's argv arrays;
- `Env` = resolved `KEY=value` list;
- `Labels` = the four labels only;
- `ExposedPorts`;
- `HostConfig.PortBindings` with `HostIp` set explicitly to `127.0.0.1`. `0.0.0.0` is allowed only when `allow_public_ports = true`; an empty value and `::` are never used.
- `HostConfig.Mounts` with `Type=volume` entries built by the helper (below);
- `HostConfig.RestartPolicy`: jobs always `no`;
- `HostConfig.NetworkMode` = `deploybot-<slug>`;
- `NetworkingConfig.EndpointsConfig[deploybot-<slug>].Aliases = [entry]`;
- `User` only if the spec sets a non-root user.

Every other `HostConfig` field keeps Docker's default because the helper never sets it. That covers `Privileged`, `CapAdd`, `Devices`, `DeviceCgroupRules`, `DeviceRequests`, `GroupAdd`, `MaskedPaths`, `ReadonlyPaths`, `PublishAllPorts`, `UsernsMode`, `CgroupnsMode`, `PidMode`, `IpcMode`, `LogConfig`, `Runtime`, `SecurityOpt`, `Sysctls` and `Binds`. Docker's default capability set and `/proc` and `/sys` masks apply.

**Volumes:**
- `Source` must match `^<slug>-[a-z0-9][a-z0-9-]{0,62}$`, the project slug from the request.
- Before create, the helper inspects the volume. If it exists, its driver must be `local` with **no driver options** and label `dev.deploybot.project=<slug>`; otherwise the deploy is refused (`forbidden_spec`). If it is missing, the helper creates it with driver `local`, no options and the labels. A volume made with `local` bind options (a host path in disguise) is therefore never mounted.
- `Target` must be absolute, with no `.`/`..` segments; `ReadOnly` is a bool.
- No `VolumeOptions`, `BindOptions` or `TmpfsOptions`.
- No shared volumes in 2a.

**Network:**
- The helper ensures `deploybot-<slug>` exists with driver `bridge`, empty options, default IPAM and labels `owner`, `host` and `project`.
- An existing network with that name but a different driver or labels → refuse (`forbidden_spec`).
- Containers join only that network, with exactly one alias, the entry name.

**Names:**
- The container name is `<slug>-<entry>`. The rollback slot is `<slug>-<entry>-prev`.
- Image entry names must not end with `-prev` or `-` (both refused by the API).
- If a name is already taken by a container whose labels differ (another project with a colliding slug/entry pair, or a hand-made container), the deploy is refused with `conflict`. Nothing is renamed or removed.

**runner.toml additions** (absent = images off):

```toml
images = ["ghcr.io/joe-and-his-friends/*"]   # existing key; empty = no image entries
projects = ["mohiguide"]                      # slugs this host may run containers for
max_containers = 20
allow_public_ports = false                    # true: 0.0.0.0 binds allowed
```

`hello.programs` reports `images: true|false` and `docker: true|false` (the helper can reach Docker). Paths, patterns and project lists are not reported.

### 4.2 Image entry spec (catalog kind `image`)

```json
{
  "kind": "service" | "job",
  "image": "ghcr.io/joe-and-his-friends/mo-webadmin:latest",
  "command": ["…"],                     // optional argv → Cmd
  "entrypoint": ["…"],                  // optional argv → Entrypoint
  "ports": [{"host":3031,"container":3031,"public":false}],
  "env": {"NODE_ENV":"production"},     // plain inline
  "env_sets": ["services"],             // all keys of these project env sets
  "secret_env": {"DB_URL":"services.MONGODB_URI"},  // one key of one set
  "volumes": [{"name":"webadmin","target":"/var/www","read_only":false}],
  "restart": "no" | "on-failure" | "unless-stopped",  // job: forced "no"
  "user": "",                           // optional; never "root"/"0"/"0:…"
  "healthy_after_sec": 30               // service: 5–600, default 30
}
```

- **Volume names** in the spec are short (`webadmin`). The real volume is `<slug>-webadmin`, so a spec cannot name another project's volume.
- **Env keys** (all sources) follow the api-v1 key rule and the v1.6.1 denylist (`LD_*`, `NODE_OPTIONS`, `BASH_ENV`, …).
- **Precedence**, lowest first: `env_sets` (in order) < `secret_env` < `env`.
- **Shared-host approval:** the approval covers the spec hash **plus** the env-set names and a hash of each referenced set's key names, so adding a key to a set voids the approval. Values are never in the hash, plans or audit.

### 4.3 Agent tasks and sequences

The task kinds are `image_deploy`, `image_rollback`, `image_start`, `image_stop`, `image_restart`, `image_remove`, `image_logs` and `image_status`. The API resolves values and attaches the registry auth for the image's registry host. The agent calls the helper verbs.

**Deploy a service:**
1. `image_pull`. On failure: `image_unavailable`, and nothing has changed.
2. If the current container runs the same digest with the same spec hash and `force` is not set: `unchanged`.
3. `container_deploy`. Under the entry flock, the helper:
   - removes an old `-prev`;
   - stops the current container and renames it to `-prev` (both names derived, labels checked);
   - creates the new container from the digest and starts it.
4. The agent waits for health: the service's http/tcp checks if any, otherwise running for `healthy_after_sec` with restart count 0.
   - Healthy → `succeeded`.
   - Unhealthy → `container_rollback`, which removes the new container and renames `-prev` back, then starts it. The result is `rolled_back`, or `rollback_failed` (alerts in the console).

**Deploy a job:**
1. Pull.
2. `container_remove` of the old job container (stop first if it is running).
3. Create and start.
4. Poll `container_status` until exit or `timeout_sec` (default 600, max 3600).
   - Exit 0 → `succeeded`.
   - Non-zero → `failed` with the exit code.
   - Timeout → `container_stop` (wait), then `failed` / `timeout`.
5. The stopped container stays, so its logs can be read.

**Rollback action:** `image_rollback` with a digest from the last 3 in the history runs the service sequence with that digest (the pull is by digest).

**Named volumes on first mount:** Docker copies image content into a new, empty volume at the mount point. The agent neither relies on that nor prevents it. The pilot is deployed twice to show a re-run into a non-empty volume behaves as the image intends.

**Results:**
- what they carry: outcome, digest, exit code, timings, and a redacted log tail (50 lines);
- never: env values, command lines or tokens.

**Discovery:** each cycle the agent calls `container_list`.
- Owned containers (four labels, project in policy) → `source='owned'`, `owner.kind='image'`, name = entry, with `container_name` and `image_digest`.
- Every other container → `kind='container'` discovered items named by container name, with their published ports. These replace the anonymous `port <n> · root` docker-proxy rows.

If the helper or Docker is unavailable, discovery is incomplete and no services frame is sent (agent-protocol v1.3.2).

### 4.4 API

**Catalog:**
- `kind: "image"` entries are accepted, validated as in §4.2.
- Image entry names: not ending `-prev` or `-`.
- Permission action **`deploy`** covers deploy, redeploy, job run, rollback and remove. Defaults: owner and admin all actions, viewer `logs`.

**Routes:**
- `POST /v1/projects/{id}/catalog/{name}/deploy` `{host_id, force?, idempotency_key}`;
- `POST …/rollback` `{host_id, digest, idempotency_key}`;
- `POST …/remove` `{host_id, idempotency_key}`;
- `GET …/deploys?host_id=` returns the history, newest first.

run/stop/restart/logs/status reuse the wave 1 routes and dispatch by kind. Checks run in the wave 1 order, plus one in-flight deploy per (host, entry): a second request → `conflict`.

**History:** `app.image_deploys`. The agent never deletes images in 2a, so the 3 rollback digests stay on the host.

**Env sets** (owner/admin): tables `app.env_sets` and `app.env_values` (`is_secret`, AES-GCM ciphertext for secrets).
- `PUT /v1/projects/{id}/env-sets/{name}` `{"dotenv": "…"}`. **Normative grammar:**
  - one `KEY=value` per line, with an optional leading `export `;
  - `#` comment lines and blank lines;
  - a value may be wrapped in matching single or double quotes; no escapes, no interpolation, no multi-line values;
  - keys follow the api-v1 rule and denylist;
  - duplicate keys → `bad_request`;
  - limits: 256 keys, 4096 bytes per value, 256 KiB per file.

  Errors list line numbers and keys, never values. Every value is stored as a secret.
- `PATCH …/keys/{key}` `{is_secret}`.
- `GET` returns names, keys and flags, plus plain values only.
- `DELETE` is refused while an entry references the set.

**Registry credentials:** `PUT /v1/projects/{id}/registries/{host}` `{username, token}`, plus `GET` (hosts and usernames) and `DELETE`. The credential is sent only inside `image_deploy`/`image_rollback` frames whose image's parsed registry host equals `{host}`.

**Encryption:** `BOT_SECRETS_KEY` (api env file, 600), AES-256-GCM with `key_version`. Postgres (pi4 for dev) holds ciphertext only.

**Never via MCP:** no tool reads or writes env sets or registries.

**Migration:** `0009_catalog_images.sql`, after 0008.

### 4.5 Console

- **Catalog → New service → Container:**
  - the §4.2 form: kind toggle, argv editors, port rows with a "public" box shown only when the host allows it, env-set multi-select, secret_env rows, volume rows (short names) with read-only;
  - a read-only `docker run` preview.

  The paste-a-`docker run` prefill keeps refusing unsupported flags.
- **Deploy dialog:** host (name labels), force, outcome, short digest, exit code, log tail, and a history of 3 with **Roll back** on the older entries.
- **Project → Settings → Env sets and registries:** paste box (never pre-filled, cleared after save), key list with secret/plain toggles, registry rows with a write-only token field.

### 4.6 MCP

- `list_catalog` shows image entries without values.
- `deploy_entry` and `rollback_entry` use the D25 two-step confirmation.
- `entry_logs` and `entry_status` work for images.
- There are no env-set or registry tools.

## 5. Contract diff (summary; exact text frozen at implementation)

- **api-v1 v1.8:**
  - the image entry schema and name rule; permission `deploy`;
  - the deploy, rollback, remove and history routes; the env-set and registry routes;
  - the approval hash including env-set key names;
  - Service fields `container_name` and `image_digest` for owned images;
  - result outcomes (`succeeded`, `unchanged`, `failed`, `timeout`, `rolled_back`, `rollback_failed`, `image_unavailable`, `forbidden_spec`, `conflict`);
  - the audit actions.
- **agent-protocol v1.4:**
  - the `image_*` task kinds and results;
  - task frames carrying resolved env and an optional registry auth, both redacted on both sides;
  - `hello.programs.images` and `.docker`;
  - `Discovered` with `kind='container'` names, plus `image_digest`;
  - the **local helper interface**: the verb table, the create-body construction, the volume, network and name rules, the locks, and the projections, as for wave 1.
- **Not changed:** program entries and tasks, oauth-v1.

## 6. Acceptance criteria

1. **Typed verbs only:** the agent has no path to Docker except the helper's typed verbs; no verb accepts raw HTTP, paths, query strings, headers or bodies. Unit tests feed the helper malformed and oversized JSON, unknown fields and extra keys: all are refused.
2. **The create body:** the helper's request to a fake Engine contains exactly the fields listed in §4.1. A golden test fails if any other field appears, including empty-valued ones.
3. **Pulls:**
   - only `fromImage` and `tag` reach the Engine;
   - a reference outside `images` is refused: another registry, an extra path component, a userinfo/port trick, case tricks;
   - `X-Registry-Auth` is sent only when the parsed host equals the credential's host.
4. **Volumes:**
   - a volume with `local` driver options (for example `type=none,o=bind,device=/`) is refused;
   - a volume of another project is unreachable by name;
   - a new volume is created with no options and the project label.
5. **Network:** a pre-existing `deploybot-<slug>` with another driver or labels is refused; containers get exactly one alias. Two projects on one host cannot resolve each other's names.
6. **Ownership:** start/stop/restart/remove/logs/rollback act only on a container whose four labels match. A compose container, another project's container, or a colliding name is refused with nothing changed.
7. **Projections:** list/status results contain no env, command, mounts, host config, graph-driver paths, log config or non-deploybot labels.
8. **Redaction:** results, logs and audit contain no env value or token, checked with the real values in raw, base64 and JSON-escaped form.
9. **Service deploy:**
   - success → `succeeded`;
   - the same digest and spec → `unchanged` with no recreate;
   - `force` → recreated;
   - unhealthy → `rolled_back`, with the old container serving again;
   - two concurrent deploys of one entry → the second is `conflict` at the API, and helper-level locking is proved by a test.
10. **Jobs:**
    - exit 0 → `succeeded`;
    - exit 3 → `failed` with exit code 3;
    - a timeout stops the container and reports `timeout`;
    - a re-run replaces the stopped job container;
    - `RestartPolicy` is always `no`.
11. **Rollback:** a rollback to a digest from the history works; a digest not in the last 3 → `bad_request`.
12. **Env sets:**
    - the grammar table (quotes, `export`, comments, duplicates, escapes refused, multi-line refused, denylisted keys, limits);
    - errors list line numbers and keys only;
    - secret values are never returned;
    - adding a key voids a shared-host approval.
13. **Credentials:** a private image pulls with stored credentials; missing credentials → `image_unavailable`; the token is in no log, result or audit row.
14. **Live check, pi3 (dev):** a public multi-arch image as a service on 127.0.0.1; redeploy `unchanged`; a failing tag → automatic rollback; a job; logs, stop, start; discovery names the pi3 containers.
15. **Pilot, mohiguide** (planned window; Joe approves every host change):
    - the webadmin job from the private ghcr image into the new volume `mohiguide-webadmin`, with its digest recorded, exit 0 and logs visible;
    - a second run into the non-empty volume;
    - the volume content equals `./webadmin` (read-only compare);
    - the compose containers are unchanged (same ids, same state);
    - the Services tab shows the compose containers by name.
16. **Browser smoke** of every new dialog and page.

## 7. Rollback

- **Per host:** set `images = []` (or remove `projects`) in `runner.toml`, then the helper refuses image verbs. Or revert the helper unit's `ReadWritePaths=/var/run/docker.sock`. Containers deploybot created keep running under their restart policy; remove them by hand if wanted.
- **API, console and MCP:** revert the commits; image entries become `not_implemented` again. Migration 0009 has a down script that drops the encrypted data, so take a dump first.
- **mohiguide:** the pilot is shadow-only. Remove the `mohiguide-webadmin` container and volume; swag never pointed at them.

## 8. Tests

Summarised in §6. The helper uses a fake Engine on a unix socket (records requests, returns canned responses), with no real Docker in unit tests. Golden create bodies. Reference-grammar and pattern tables. Lock tests with two concurrent verbs. Agent sequences with a fake helper. API validation, grammar, encryption, release and approval-hash tests. Console server-render tests plus a browser smoke. MCP schema and confirm tests.

## 9. Delegation

Grok workers in worktrees:
- bot-agent (helper verbs and Engine client in one worker; agent tasks and discovery in a second, with a clear file split);
- the API;
- the console;
- MCP.

Reviews:
- **security** lens twice on the helper and agent;
- **spec, tests and ui** lenses.

The orchestrator runs the gates, migrations and live checks. Host files go to Joe before they are installed. Commit, push and deploy happen only on Joe's approval.

## 10. Open points (defaults proposed; O1–O7 accepted by Joe for revision 1)

- **O1 Split 2a / 2b:** yes (unchanged).
- **O2 Adopt:** dropped (unchanged).
- **O3 Container user:** the image's default user is allowed; an explicit root `user` is refused. Docker's default capability set applies, with **no `CapAdd`**. Devices, device cgroup rules and the other fields in §4.1 can never be set, because the helper builds the body. That is the condition the review set for O3 to be safe.
- **O4 Volumes:** per project only; **no shared volumes in 2a** (changed: revision 1 had a `shared_volumes` policy key).
- **O5 Health default:** 30 s (unchanged).
- **O6 Network cleanup:** never automatic (unchanged).
- **O7 In-network health check:** later (unchanged).
- **O8 (new) Secrets boundary:** the agent sees the values of the tasks it receives (§3.4). Sealing them to the helper (an API ↔ helper key, with the agent passing opaque blobs) is a later hardening, not 2a. *Default: accept for 2a.*

## 11. Changes from revision 1 (from the Grok security review, verdict "rework")

| Review finding | Revision 2 |
|---|---|
| Critical: an HTTP pass-through proxy can be smuggled (chunked or pipelined bodies, upgrades; `exec`/`archive` reachable) | No proxy. The existing root helper gets typed verbs; the helper builds every Engine request. |
| Critical: `Mounts.VolumeOptions.DriverConfig` with `local` bind options mounts host `/` | The helper builds mounts itself (no options), and inspects existing volumes (driver `local`, no options, project label) or refuses them. |
| Critical: `images/create` accepts `fromSrc`, `changes` and `repo` (URL fetch, metadata service, import) | Only `fromImage` + `tag`; the reference is parsed with the grammar and the pattern match is anchored per component. |
| High: a blocklist misses `HostConfig` fields; an empty `HostIp` publishes on all interfaces | The body is constructed with a fixed field set; `HostIp` is always explicit; a golden test checks the body. |
| High: network create/connect lets a container join other networks or claim aliases | The helper creates and checks `deploybot-<slug>` itself, with exactly one network and one alias. |
| High: volume and project scoping is missing on the host | `runner.toml` gains a `projects` list, plus four labels including project and entry; volumes are `<slug>-…`. |
| High: list and inspect leak mounts, commands and image history | Projections only; there is no image-inspect verb. |
| High: the rename rule blocks rollback or allows name theft; races | Names are derived; there is a flock per entry plus one in-flight deploy per entry at the API; entry names may not end in `-prev`. |
| High: a secrets boundary overstated | Stated honestly (§3.4, O8); regex + exact redaction in raw, base64 and JSON forms. |
| Medium: env-set grammar and approvals | Normative grammar and limits; key names are in the approval hash. |
| Medium: unit shape and job timeouts | Wave 1 helper transport (`RuntimeMaxSec` 900); a job timeout stops the container; jobs always restart `no`. |
| Low: too much mechanism | Smaller surface: no proxy, no inspect pass-through. |

## 12. Revision 3 tightenings (second Grok security pass, verdict "approve with changes")

These rules are normative and take precedence over the earlier text where they are stricter. None of them changes the design.

1. **Every interpolated field is validated in the helper (was Critical).** The helper itself checks:
   - `entry` against `^[a-z0-9][a-z0-9-]{0,47}$` (the API rule), plus the no-`-prev`, no-trailing-`-` rule;
   - `project` by exact membership in `runner.toml` `projects`;
   - volume short names against `^[a-z0-9][a-z0-9-]{0,47}$`.

   Engine URLs are built with path escaping, and requests use the full container **id** from the helper's own lookup by name, never the name. Registry auth is sent as base64url JSON built by the helper, and `username`/`token` containing CR, LF or NUL are refused.
2. **The image allowlist is checked again at create.** `container_deploy` and rollback parse the `Image` reference (`repo@sha256:<64 hex>`) and match the repo against `images` again. A digest not shaped as 64 hex is refused and never falls back to a tag.
3. **Check labels before any mutation.** Before stopping, renaming or removing anything, the helper resolves `<slug>-<entry>` and `<slug>-<entry>-prev` by name and verifies all four labels on each. Any container under those names with other labels (for example mohiguide's production `mohiguide-restore`, should an entry be called `restore`) → `conflict`, with nothing touched.
   - Volumes: create-then-verify (if the create loses a race, the existing volume must pass the label/driver/options check).
   - Because `<slug>-<entry>` is not injective across projects, labels — not names — decide ownership everywhere.
4. **Pulls:** send either `fromImage=<name>&tag=<non-empty tag>` or `fromImage=<name>@sha256:<digest>`, never both and never an empty tag. A reference with neither tag nor digest gets the API default `latest`, made explicit before the pattern check.
5. **Pinned defaults and resource limits.** The create body also sets:
   - `HostConfig.CgroupnsMode = "private"`;
   - `HostConfig.PidsLimit = 1024`;
   - an optional `memory_mb` in the entry spec → `HostConfig.Memory` (no default limit; the console suggests one). Swap equals memory, so no extra swap.
   - Anonymous volumes from image `VOLUME` lines are removed with the container: `container_remove` and the `-prev` cleanup pass `v=1`, which Docker applies to anonymous volumes only. Named volumes are never removed.
   - `max_containers` is enforced by the helper, counting live containers, `-prev` containers and job containers with deploybot labels.
6. **User:** parsed as the Engine does (`user`, `uid`, `user:group`, `uid:gid`). Refused: uid 0, gid 0, `root` in either position, and leading-zero numerics. Allowed: `^[a-z_][a-z0-9_-]{0,31}$` names or positive uids/gids.
7. **Encryption:** every ciphertext has a fresh random 96-bit nonce stored beside it, AES-GCM associated data = `project_id | set or registry | key`, and decryption fails closed. The key, nonces and plaintext are never logged.
8. **Env:**
   - **Inline `env`:** the v1.6 secret-looking-key refusal applies, no NUL/newline.
   - **`secret_env`:** references resolve only within the entry's own project. The set name follows `^[a-z0-9][a-z0-9-]{0,47}$` and is split at the first `.`.
   - **Previews, the MCP D25 plan, the history and audit** show key names and secret/plain flags only, never values. That includes the console `docker run` preview, which shows `-e KEY` for set and secret keys.
9. **Honesty about leaks (§3.4 addendum):** redaction of stdout/logs is a best-effort filter, not a boundary. Anyone allowed to `deploy` can choose a command or image that prints a value in another encoding or sends it over the network. Containers keep outbound network access, which apps such as mo-services need for FCM.
10. **Network scope (decision 3 clarified):** in 2a only deploybot-created containers of one project share `deploybot-<slug>`. Compose containers (swag and the others) are **not** attached, so name resolution between swag and a deploybot container only works once both run under deploybot (the full move). The helper never connects a container to any network other than its project's. Docker's inter-bridge isolation is assumed (the default iptables setup); the live check confirms it on pi3 and mohiguide.
11. **Shared hosts:** the approval covers the spec, the env-set names and the key names, but not values. A guest project can change secret values without a new approval; that is accepted and documented (the host owner approves *what runs*, not the guest's credentials).

## 13. Changes during implementation (all approved by Joe, 2026-10-15/16)

| Change | Why | Where |
|---|---|---|
| Dev live-check host pi1 → **pi3** (Debian 12 arm64, clean Docker) | pi1 runs app dev servers; pi3 has no containers to collide with | §1, AC14, §12.10 |
| **agent-protocol v1.4.1:** the task `spec` is the ImageSpec as stored (env sets and `secret_env` as references); resolved values travel only in the top-level `env`; a frame over the agent limit is refused with `bad_request` and never sent | v1.4 sent every secret twice; a large set could push a frame over 1 MiB and close the agent connection | contract |
| **agent-protocol v1.4.2:** `container_logs` takes an optional `redact` list; the helper removes those exact values before the regex and the 2048-char cut; the agent sends it for deploy/rollback log tails | the regex could split a secret before exact redaction ran, leaking part of it in the log tail | contract |
| **api-v1 v1.8.1:** `ImageStatus.state` gains `unknown` for a deploy/rollback that ran past its budget | the API has no container state then; `""` was outside the enum and `missing` would mislead | contract |
| The API also strips exact secret values from logs and status results of every image action (decrypting only to build the redaction set) | final security review: `image_logs` results carried only regex redaction | API |
| Container `docker run` paste: harmless flags (`-d`, `--detach`, `--name`, `--rm`, `-i`, `-t`, `-it`, `--interactive`, `--tty`) are ignored with a notice; any other unsupported flag refuses the whole paste (the program paste rule of `spec-project-catalog.md` is unchanged) | browser smoke: refusing `-d` rejected nearly every real command | console |
| Deploy timing: deploy/rollback stay synchronous; task budget = 300 s + `healthy_after_sec` (service) or `timeout_sec` (job) + 60 s; only those console/MCP calls get a matching long timeout; the API records the outcome even if the client disconnects; a stale in-flight row expires at its `in_flight_until` | the 35 s client timeouts and the 15 s task timeout could not fit a pull plus a health wait | API, console, MCP |
| Env-set and registry routes accept only a console session | a delegated MCP token could flip a key to plain and read its value | API |
| `BOT_SECRETS_KEY_FILE` (0600 file, base64 of 32 bytes) carries the §4.4 `BOT_SECRETS_KEY`; when absent, only the secret features return `unavailable` | same handling as the MCP client secret file | API |
| Helper unit `ReadWritePaths=-/var/run/docker.sock` and agent unit `InaccessiblePaths=-…` use the ignore-if-missing prefix | the same build runs on hosts without Docker (us1) | packaging |
