# Spec: MCP browser OAuth wave (audience-bound tokens, no passthrough)

**Tier:** 3. It adds new public auth endpoints, a DB migration, a contract change in two services, an MCP client flow, and it revokes existing `mcp` tokens.
**Status:** Approved 2026-10-14 (Joe: "yes, approve both specs").
**Requested by:** Joe, 2026-10-14. The requirements were confirmed from a side chat, and Joe then said "then do the MCP browser OAuth spec". Ledger item: "MCP browser OAuth wave".
**Ends:** design deviation **D36** (token passthrough). **Keeps:** **D35** (a token is a session of the user's account; it reaches the user's projects with the user's role, checked live).
**Placement:** before, or together with, the phase 2 mutating MCP tools.

## 1. Goal

1. Claude Code and other MCP clients sign in by themselves through the standard MCP authorization flow. The user approves in the browser with Google, and no CLI step or token file is needed.
2. Tokens that MCP clients hold are bound to an **audience equal to the MCP server's resource URL** and are useless against bot-api-server directly.
3. bot-mcp-server never replays a client token upstream. It exchanges it for a short-lived API token.
4. `deploybot login` (device code plus a static header) stays as the fallback for clients without a browser. Its tokens follow the same audience and exchange rules.

## 2. Today

- bot-mcp-server serves `/.well-known/oauth-protected-resource` with `resource` = its public origin and `authorization_servers` = [bot-api-server]. On a missing token it answers 401 with `WWW-Authenticate: Bearer resource_metadata=…`.
- bot-mcp-server forwards the caller's `mcp` session token unchanged (D36).
- bot-api-server:
  - has Google OIDC sign-in, `app.sessions` (kind `console` for 7 days, `mcp` for 30 days, stored as a SHA-256 hash, no project column), and the device flow (`/v1/auth/device/*`);
  - has **no** OAuth authorization-server metadata, `/authorize`, `/token`, or registration endpoint;
  - keeps OAuth state in memory, in one process.

## 3. Approach

bot-api-server becomes an **OAuth 2.1 authorization server** for exactly one resource, bot-mcp-server. It uses Google only as the way users prove who they are; Google tokens never reach MCP clients. bot-mcp-server stays a resource server. For each client token it does an **RFC 8693 token exchange** at bot-api-server and calls the API with the short-lived result.

### 3.1 Authorization server (bot-api-server)

| Item | Decision |
|---|---|
| Metadata | `GET /.well-known/oauth-authorization-server` (RFC 8414): `issuer` = API public origin; `authorization_endpoint` `/oauth/authorize`; `token_endpoint` `/oauth/token`; `registration_endpoint` `/oauth/register`; `revocation_endpoint` `/oauth/revoke`; `response_types_supported` `["code"]`; `grant_types_supported` `["authorization_code","refresh_token"]`; `code_challenge_methods_supported` `["S256"]`; `token_endpoint_auth_methods_supported` `["none","client_secret_basic"]`; `scopes_supported` `["deploybot"]`. Served with `Cache-Control: max-age=300`. |
| Client registration | **Dynamic client registration** (RFC 7591) at `POST /oauth/register`, open and unauthenticated as the MCP spec expects, but **public clients only** (`token_endpoint_auth_method: none`):<br>• `client_name`: 1–64 characters, printable.<br>• `redirect_uris`: 1–5. Each is either an exact `https://` URL, or a loopback `http://127.0.0.1` / `http://[::1]` / `http://localhost` URL where any port matches (RFC 8252 §7.3).<br>• No wildcards, fragments or userinfo.<br>• `grant_types` ⊆ {authorization_code, refresh_token}.<br>• Rate limit: 10 registrations per IP per hour.<br>• Clients unused for 30 days are deleted.<br>**Client ID metadata documents (the newer MCP option) are not in this wave;** see §10. |
| Resource | One allowed resource: `BOT_API_MCP_RESOURCE` = bot-mcp-server's public origin, exactly as in its protected-resource document. `resource` (RFC 8707) is **required** on `/oauth/authorize` and `/oauth/token`; any other value → `invalid_target`. |
| Authorize | `GET /oauth/authorize` with `response_type=code`, `client_id`, `redirect_uri` (exact registered match, with loopback port flexibility), `code_challenge` + `code_challenge_method=S256` (required), `state`, `resource`, optional `scope=deploybot`. Errors: invalid `client_id` or `redirect_uri` → an error page and **no redirect**; other errors → redirect with `error=`. On success it stores a pending authorization (5 min, in the DB) and redirects (303) to the console consent page `/<console>/oauth/consent?request=<opaque id>`. |
| Consent (bot-console) | A new page `/oauth/consent`:<br>• It requires a console session; signed out, it goes through the normal Google sign-in and returns.<br>• It shows the client name (marked "unverified", because registration is open), the redirect host in full, the text "acts as you, with your project roles in N projects", and Approve / Deny.<br>• A remembered grant for the same (user, client, resource) skips the page once, and only if it is less than 30 days old.<br>• Approve or Deny posts through a console form action to the API (`POST /v1/oauth/requests/{id}/approve|deny`, console session), which returns the redirect URL with `code` + `state` (or `error=access_denied`). The console then redirects the browser. |
| Code | Random, at least 128 bits, stored hashed, valid for 60 s, single use. It is bound to the client, redirect URI, PKCE challenge, resource and user. Reusing a code revokes every token issued from it. |
| Token | `POST /oauth/token`:<br>• `grant_type=authorization_code` (with `code_verifier`, `redirect_uri`, `client_id`, `resource`), or `grant_type=refresh_token` (with `refresh_token`, `client_id`, optional `resource`).<br>• **Access token:** opaque, at least 256 bits, a new session kind `mcp_access`, `audience` = resource, valid 1 h.<br>• **Refresh token:** opaque, a new session kind `mcp_refresh`, valid 30 days, **rotated on every use**. Reuse of a rotated refresh token revokes the whole grant family.<br>• Response: `access_token`, `token_type=Bearer`, `expires_in`, `refresh_token`, `scope`.<br>• No CORS. |
| Revoke | `POST /oauth/revoke` (RFC 7009) for access or refresh tokens; it revokes the family. |
| Device flow | `/v1/auth/device/token` now issues an `mcp_access` token with `audience` = MCP resource and a **30-day** lifetime, without a refresh token. It stays a static header for headless clients. `deploybot login` is unchanged apart from the token it receives. |
| API rule (no passthrough) | bot-api-server rejects any token whose `audience` is the MCP resource on every `/v1/*` route with 401 `invalid_token`. Only the token-exchange grant accepts such a token. |

### 3.2 Token exchange (bot-api-server ↔ bot-mcp-server)

- `POST /oauth/token`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=<client token>`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `resource=<API origin>`.
- Client authentication is `client_secret_basic` for the **pre-provisioned confidential client `bot-mcp-server`**. It is created by config, never through dynamic registration. Its secret is an env file, mode 600: `BOT_API_MCP_CLIENT_SECRET_FILE` on the API side holds the hash; `BOT_MCP_CLIENT_SECRET_FILE` on the MCP side holds the secret.
- The API checks that the subject token is live, of kind `mcp_access`, and has `audience` = the MCP resource. It issues an **`api_delegated`** token: audience = API origin, valid 5 min, not refreshable, same user, marked `via=mcp` for audit. The response carries `issued_token_type=urn:ietf:params:oauth:token-type:access_token`.
- bot-mcp-server caches the delegated token in memory, keyed by a hash of the client token, until 30 s before it expires. It never logs either token.
- Audience validation in bot-mcp-server **is** the exchange. If the exchange fails (invalid, expired, revoked, or wrong audience), bot-mcp-server answers the MCP HTTP request itself with **401** and `WWW-Authenticate: Bearer error="invalid_token", resource_metadata=…`, before any tool runs. That also fixes today's limitation, where an expired token surfaced as a tool error with HTTP 200.
- This changes bot-mcp-server's rule "no credentials of its own": it now holds one client secret, which **only** lets it exchange user tokens. It can never act without a user token. `AGENTS.md` and the design are updated.

### 3.3 Storage (migration 0005, bot-api-server)

- `app.oauth_clients`: id, name, redirect_uris, created_at, last_used_at, kind (`public` or `internal`).
- `app.oauth_requests`: pending authorizations, valid 5 min.
- `app.oauth_codes`: hashed codes.
- `app.oauth_grants`: user, client, resource, created_at, revoked_at; this is the family for rotation and revocation.
- `app.sessions` gains `audience text NULL`, `grant_id uuid NULL` (FK → oauth_grants), `client_id uuid NULL`. The `kind` CHECK becomes `console | mcp | mcp_access | mcp_refresh | api_delegated`; `mcp` stays only for the cut-over in §7.
- Grants for `deploybot_api` follow the existing app CRUD rules.
- The down script (hand-run) drops the new tables and columns.
- The in-memory OAuth state for **Google** sign-in is unchanged.

### 3.4 Console

- The `/oauth/consent` page (see above).
- **Account → Connected apps:** lists the user's active grants (client name, redirect host, created and last used) with a Revoke row action (icon-only, as in the UI spec), plus device-flow tokens.
- Built on the shared components and the new UI stack.

### 3.5 MCP client experience

- **Claude Code:** `claude mcp add --transport http deploybot https://<mcp>/mcp`. On the first call the client gets a 401, discovers the metadata, registers, opens the browser, the user signs in with Google and approves, and the client stores the tokens and refreshes them itself.
- **Headless:** `deploybot login`, then the static header, as today.
- The README gives both.

## 4. Contract diff

| Contract | Before | After |
|---|---|---|
| New `docs/contracts/oauth-v1.md` | — | Authorization-server metadata, `/oauth/register`, `/oauth/authorize`, `/oauth/token` (code, refresh, token exchange), `/oauth/revoke`, error codes, token lifetimes, audience rules |
| api-v1 v1.4 | Any live session token works on `/v1/*` | Tokens with the MCP audience → 401 `invalid_token`. New console-only routes: `GET /v1/oauth/requests/{id}`, `POST …/approve`, `POST …/deny`, `GET /v1/me/grants`, `DELETE /v1/me/grants/{id}`. Audit actions `oauth.client_register`, `oauth.authorize` (allow or deny), `oauth.token_revoke`, `oauth.refresh_reuse`. `via` on audit rows is `mcp` for `api_delegated` tokens. |
| bot-mcp-server HTTP | The token is passed through; an API 401 becomes a tool error over HTTP 200 | Every request exchanges or uses its cached exchanged token; a failure gives HTTP 401 with `WWW-Authenticate`. The protected-resource document is unchanged (`resource`, `authorization_servers`); `scopes_supported: ["deploybot"]` is added. |
| Device flow | Issues kind `mcp`, 30 days, no audience | Issues kind `mcp_access`, 30 days, audience = MCP resource |

## 5. Acceptance criteria

1. Standard flow end to end against the dev stack, with Claude Code as the client:
   - `claude mcp add --transport http deploybot http://localhost:8091/mcp`, then a tool call, opens the browser;
   - Google sign-in and Approve follow;
   - `list_projects` succeeds;
   - after the access token expires (shortened to 2 min in a test config), a refresh happens without the browser.
2. PKCE:
   - missing, `plain`, or a wrong verifier → `invalid_grant` or `invalid_request`;
   - a code used twice → `invalid_grant`, and every token from that code is revoked;
   - a code older than 60 s → `invalid_grant`.
3. Redirect URIs:
   - exact https match;
   - loopback with any port;
   - non-loopback http, a wildcard, a fragment or userinfo are rejected at registration;
   - an unregistered `redirect_uri` on authorize → an error page with no redirect.
4. Resource:
   - a missing or foreign `resource` → `invalid_target`;
   - an issued access token has `audience` = MCP resource.
5. No passthrough:
   - an MCP-audience token used directly on any `/v1/*` route → 401 `invalid_token` (table test over every route);
   - bot-mcp-server never sends a client token to `/v1/*` (test with a recording fake API);
   - delegated tokens last 5 min and cannot be refreshed.
6. Token exchange:
   - only the `bot-mcp-server` client with the right secret may exchange;
   - a subject token of kind `console`, an expired one, a revoked one, or one with the wrong audience → `invalid_grant`;
   - bot-mcp-server answers HTTP 401 with `WWW-Authenticate` when the exchange fails.
7. Refresh:
   - rotation on every use;
   - reuse of an old refresh token revokes the family (all of its access and refresh tokens).
8. Device flow: `deploybot login` still works, and its token works only through bot-mcp-server.
9. Consent:
   - a signed-out user goes to sign-in and back;
   - the page shows the client name as unverified and the full redirect host;
   - Deny returns `access_denied`;
   - a remembered grant skips the page for 30 days;
   - Connected apps lists and revokes grants, and revoking kills the family at once.
10. Cut-over: after migration, existing `mcp` sessions are revoked, and the release notes say to log in again.
11. Rate limits: registration and authorize are rate-limited per IP; tests for both.
12. Audit rows for register, authorize (allow and deny), revoke and refresh reuse.
13. All gates in the API, MCP and console. `TestIntegration` on pi4 covers migration 0005, codes, rotation, family revocation and the API audience rule.

## 6. Rollback

- Revert in order: console, MCP, API.
- Hand-run `0005_mcp_oauth.down.sql`. It drops the new tables and columns and restores the `kind` CHECK. All OAuth and delegated tokens are lost.
- Users then run `deploybot login` again (legacy `mcp` tokens, D36 behaviour) until the wave is retried.

## 7. Cut-over and deployment

Deploy order:
1. Migration 0005.
2. API with the `bot-mcp-server` client secret, plus the MCP side with its secret file.
3. bot-mcp-server.
4. Console.

At the API deploy, every legacy `mcp` session is revoked in the same transaction as the code switch. Users of `deploybot login` log in again; today that is Joe only. There is no compatibility window, because a window would keep D36 alive.

## 8. Failure modes

| Case | Handling |
|---|---|
| bot-api-server unreachable during exchange | bot-mcp-server returns HTTP 503 (not 401, so clients don't wipe their tokens). |
| Clock skew between the servers | Lifetimes are checked only on bot-api-server; the cache expires 30 s early. |
| Malicious dynamic client (consent phishing) | "Unverified" label, the full redirect host on consent, no auto-approve for a new client, rate limits, registration auditing, and grants revocable in Connected apps. |
| Stolen client access token | Useless against the API directly (AC 5); usable through MCP for at most 1 h; revocable. |
| Stolen refresh token | Rotation plus reuse detection revokes the family the first time the attacker and the user race. |
| Restart of bot-api-server mid-authorize | Pending requests and codes are in the DB, not in memory, so the flow survives. |

## 9. Security notes (security-baseline)

- PKCE S256 only. Codes and tokens are stored as SHA-256 hashes and compared in constant time.
- No tokens in URLs except the authorization code (single use, 60 s).
- The consent page is a console form action (SvelteKit origin check), and the API approve route needs the console session.
- `client_name` and `redirect_uri` are validated at registration and rendered escaped.
- The confidential-client secret is never logged, and its file is mode 600.

## 10. Open questions (resolved during exploration, before implementation)

1. **Which registration method current Claude Code uses**: dynamic registration, client ID metadata documents (newer MCP spec), or both. The plan is dynamic registration now. If Claude Code prefers metadata documents, add them in this wave as a second option, with a fetch allowlist of https only, size and time limits, and a cache. The worker brief includes a probe step against the real client before building.
2. **Whether the claude.ai web connector callback** (`https://claude.ai/api/mcp/auth_callback`) **should be allowed.** It needs bot-mcp-server reachable from the internet, which is not the case today (tailnet and localhost only). It is out of scope until hosting allows it.

## 11. Delegation

- **Wave A:** a Grok worker on bot-api-server (migration, authorization server, exchange, audience rule).
- **Wave B, in parallel against the frozen `oauth-v1.md`:**
  - bot-mcp-server (exchange middleware, 401 handling, secret file);
  - bot-console (consent page, Connected apps).
- Independent Grok lens reviews per repo: security (two passes, because this is auth), spec, tests.
- The orchestrator runs the gates, the pi4 integration test, and the live check with Claude Code (AC 1), which needs Joe to approve in the browser once.
