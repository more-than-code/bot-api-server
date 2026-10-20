# Contract: Deploybot OAuth v1 (MCP authorization)

**Status:** Frozen 2026-10-14, from the approved spec `docs/spec-mcp-oauth.md`. Copies in the repos must not be edited; amendments go in a new dated section at the end.

**Parties:** the **AS** (authorization server) is bot-api-server. The **RS** (resource server) is bot-mcp-server. The **client** is an MCP client such as Claude Code, or `deploybot login`.

**Config names:**
- `BOT_API_PUBLIC_ORIGIN`: the AS issuer, e.g. `http://localhost:8090` in dev.
- `BOT_API_MCP_RESOURCE`: the RS resource, exactly the `resource` in bot-mcp-server's protected-resource document: the MCP endpoint URL `<mcp origin>/mcp`, e.g. `http://localhost:8091/mcp` (v1.4.1).
- `BOT_API_CONSOLE_ORIGIN`: e.g. `http://localhost:5180`.
- `BOT_API_MCP_CLIENT_SECRET_FILE` (AS side) and `BOT_MCP_CLIENT_SECRET_FILE` (RS side).

All endpoints in §1–§6 are on the AS origin and are **not** under `/v1`. OAuth error bodies are RFC 6749 JSON `{"error","error_description"}`, not the api-v1 envelope. Every response carries `Cache-Control: no-store`, except metadata (§1).

## 1. Metadata

`GET /.well-known/oauth-authorization-server` → 200, `Cache-Control: max-age=300`:

```json
{"issuer":"<BOT_API_PUBLIC_ORIGIN>",
 "authorization_endpoint":"<issuer>/oauth/authorize",
 "token_endpoint":"<issuer>/oauth/token",
 "registration_endpoint":"<issuer>/oauth/register",
 "revocation_endpoint":"<issuer>/oauth/revoke",
 "response_types_supported":["code"],
 "grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:token-exchange"],
 "code_challenge_methods_supported":["S256"],
 "token_endpoint_auth_methods_supported":["none","client_secret_basic"],
 "scopes_supported":["deploybot"]}
```

The RS protected-resource document (bot-mcp-server, unchanged path `/.well-known/oauth-protected-resource`) is `{"resource":"<BOT_API_MCP_RESOURCE>","authorization_servers":["<issuer>"],"bearer_methods_supported":["header"],"scopes_supported":["deploybot"]}`.

## 2. Client registration (RFC 7591)

`POST /oauth/register`, `Content-Type: application/json`, unauthenticated.

**Request:**
- `client_name`: 1–64 printable characters.
- `redirect_uris`: 1–5 entries, each either:
  - an `https://` URL with no fragment and no userinfo, matched exactly; or
  - `http://127.0.0.1[:port]/…`, `http://[::1][:port]/…`, or `http://localhost[:port]/…`, where any port matches at authorize time (RFC 8252 §7.3) and the path must match exactly.
- `grant_types` ⊆ {`authorization_code`,`refresh_token`}; default both.
- `response_types` = [`code`]; default.
- `token_endpoint_auth_method` = `none`; default. Anything else → `invalid_client_metadata`.

Unknown members are ignored. Wildcards, `http` on a non-loopback host, more than 5 URIs, or any other invalid URI → `invalid_redirect_uri`.

**Response:** 201 with `{"client_id","client_id_issued_at","client_name","redirect_uris","grant_types","response_types","token_endpoint_auth_method":"none"}`. `client_id` is an opaque string of at least 128 bits. No `client_secret`.

**Rules:**
- Rate limit: 10 registrations per source IP per hour → 429 `{"error":"rate_limited"}`.
- Clients with no use for 30 days are deleted.
- The confidential client `bot-mcp-server` (§6) is created from config and is never returned or modifiable here.

## 3. Authorization (RFC 6749 §4.1 + PKCE RFC 7636 + resource RFC 8707)

`GET /oauth/authorize`:

| Param | Rule |
|---|---|
| `response_type` | `code` |
| `client_id` | A registered public client |
| `redirect_uri` | Required. It must match a registered URI (loopback: any port, same path). |
| `code_challenge` | Required, 43–128 characters, base64url |
| `code_challenge_method` | Required, `S256` only |
| `state` | Optional, ≤ 512 characters; echoed back |
| `resource` | Required, exactly `BOT_API_MCP_RESOURCE` |
| `scope` | Optional; if present it must be `deploybot` |

**Errors:**
- Unknown `client_id`, or a `redirect_uri` that is missing or doesn't match → HTTP 400 HTML page "invalid authorization request", **with no redirect**.
- All other errors → 303 to `redirect_uri?error=<code>&error_description=…&state=…`, with codes:
  - `invalid_request`: a missing or invalid challenge, or a method other than S256;
  - `unsupported_response_type`;
  - `invalid_scope`;
  - `invalid_target`: a missing or foreign `resource`.
- Rate limit: 60 per source IP per minute → 429 page.

**Success:**
1. The AS stores a pending request (`app.oauth_requests`, valid 5 minutes, opaque id of at least 128 bits).
2. It answers 303 to `<BOT_API_CONSOLE_ORIGIN>/oauth/consent?request=<id>`.

### 3.1 Consent (console-only API, api-v1 v1.4)

These routes need a **console** session (Bearer). Other session kinds → 401.

- `GET /v1/oauth/requests/{id}` → `{"id","client":{"id","name","verified":false},"redirect_host","resource","remembered":bool,"projects_count":int,"expires_at"}`. An unknown or expired id, or one already decided → `not_found`.
- `POST /v1/oauth/requests/{id}/approve` → `{"redirect_to":"<redirect_uri>?code=…&state=…"}`. This creates or reuses the grant (user, client, resource) and issues a code (§3.2). It is audited as `oauth.authorize` with decision allow.
- `POST /v1/oauth/requests/{id}/deny` → `{"redirect_to":"<redirect_uri>?error=access_denied&state=…"}`. Audited `oauth.authorize` with decision deny.
- `remembered` is true when a non-revoked grant for (user, client, resource) is less than 30 days old. The console may then approve without showing the page; it still calls `approve`.

### 3.2 Authorization code

- At least 128 bits, stored as a SHA-256 hash, valid **60 s**, single use.
- Bound to the client, the exact `redirect_uri` presented, the challenge, the resource, the user and the grant.
- A **second redemption** → `invalid_grant`, and it revokes every token issued from that code's first redemption.

## 4. Token endpoint

`POST /oauth/token`, `application/x-www-form-urlencoded`. Public clients send `client_id` in the body. The `bot-mcp-server` client uses `client_secret_basic`. No CORS.

### 4.1 `grant_type=authorization_code`

Body: `code`, `redirect_uri`, `client_id`, `code_verifier` (43–128 characters), `resource` (must equal the code's resource).

The verifier is checked as S256 against the challenge. On success:

```json
{"access_token":"<opaque>","token_type":"Bearer","expires_in":3600,
 "refresh_token":"<opaque>","scope":"deploybot"}
```

- The **access token** is a session of kind `mcp_access`, `audience` = `BOT_API_MCP_RESOURCE`, valid 1 h.
- The **refresh token** is a session of kind `mcp_refresh`, valid 30 days, in the same grant family.

### 4.2 `grant_type=refresh_token`

Body: `refresh_token`, `client_id`, optional `resource` (must equal the family's resource).

- Issues a new access token and a **new refresh token**; the old refresh token is revoked (rotation).
- Presenting an already-rotated refresh token → `invalid_grant`, **and the whole family is revoked** (all access and refresh tokens of that grant). It is audited `oauth.refresh_reuse`.

### 4.3 `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)

- **Client authentication:** `client_secret_basic` as `bot-mcp-server` **only**; any other client → `unauthorized_client`.
- **Body:** `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `resource=<BOT_API_PUBLIC_ORIGIN>`.
- **Subject rules:** the subject must be a live session of kind `mcp_access` whose `audience` = `BOT_API_MCP_RESOURCE` and whose grant is not revoked. Anything else (expired, revoked, kind `console`, `mcp_refresh`, `api_delegated`, legacy `mcp`, or a wrong audience) → `invalid_grant`.
- **Response:** `{"access_token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}`. The new token is a session of kind `api_delegated`, `audience` = `BOT_API_PUBLIC_ORIGIN`, valid 5 min, not refreshable, with the subject's user and grant. Audit rows written with it carry `via='mcp'`.

### 4.4 Errors

400 with `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `invalid_target`, or `invalid_scope`, or 401 with `invalid_client` (and `WWW-Authenticate: Basic` for a failed `client_secret_basic`). Rate limit: 60 per source IP per minute → 429. **(v1.4.1)** A request that passes `client_secret_basic` as `bot-mcp-server` is not counted against the per-IP limit (bot-mcp-server sends every user's exchange from one address); a request with failed or absent client authentication is counted.

## 5. Revocation (RFC 7009)

`POST /oauth/revoke`, form `token`, optional `token_type_hint`, `client_id` (public) or Basic (`bot-mcp-server`). Revoking an `mcp_access` or `mcp_refresh` token revokes its **grant family**. The answer is always 200 with an empty body, also for unknown tokens. Audited `oauth.token_revoke`.

## 6. Confidential client `bot-mcp-server`

- Created at AS start from config: `client_id` `bot-mcp-server`, secret = the first line of `BOT_API_MCP_CLIENT_SECRET_FILE`. The AS stores only a hash and compares in constant time. The file must be mode 0600, or the AS refuses to start.
- The RS reads `BOT_MCP_CLIENT_SECRET_FILE` (mode 0600).
- Allowed grant: token exchange only.

## 7. Resource-server behaviour (bot-mcp-server)

1. Every request to `/mcp` needs `Authorization: Bearer <t>`. A missing header → 401 `WWW-Authenticate: Bearer resource_metadata="<RS origin>/.well-known/oauth-protected-resource"`.
2. The RS exchanges `<t>` (§4.3) unless a cached delegated token exists for `sha256(t)`. The cache is in memory only and its entries expire 30 s before `expires_in`. Neither token is ever logged.
3. Exchange `invalid_grant` or `invalid_request` → **HTTP 401** with `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"`, before any MCP processing. AS unreachable or 5xx → **HTTP 503**.
4. Calls to `/v1/*` use **only** the delegated token. The client token is never sent to `/v1/*`.

## 8. API audience rule (api-v1 v1.4)

On every `/v1/*` route, a Bearer token whose session kind is `mcp_access` or `mcp_refresh` (MCP audience) → 401 `invalid_token`. `api_delegated` and `console` tokens are accepted as sessions of their user. Legacy `mcp` sessions are revoked at cut-over (§10).

## 9. Device flow (changes to api-v1)

`POST /v1/auth/device/token` on success now issues kind `mcp_access` with `audience` = `BOT_API_MCP_RESOURCE`, valid **30 days**, with no refresh token and a grant family with client = the device-flow pseudo-client `deploybot-cli`. Other device-flow responses are unchanged. `deploybot login` stores it as before; it then works only through bot-mcp-server.

## 10. Storage and cut-over (migration 0005)

- **New tables:** `app.oauth_clients`, `app.oauth_requests`, `app.oauth_codes`, `app.oauth_grants`.
- **`app.sessions` gains** `audience text NULL`, `grant_id uuid NULL` (FK, `ON DELETE CASCADE`), `client_id text NULL`.
- **`kind` CHECK:** `console | mcp | mcp_access | mcp_refresh | api_delegated`.
- **Cut-over:** the migration **revokes every `kind='mcp'` session** (sets `expires_at = now()`). The hand-run down script restores the 0004 shape.

## 11. Account API (console-only, api-v1 v1.4)

- `GET /v1/me/grants` → `{"items":[{"id","client_name","redirect_host","created_at","last_used_at","kind":"oauth"|"device"}]}`, active grants only.
- `DELETE /v1/me/grants/{id}` → 200 `null`; revokes the family. Audited `oauth.token_revoke`. Another user's grant → `not_found`.

## 12. Audit actions (api-v1 v1.4)

`oauth.client_register`, `oauth.authorize` (allow and deny), `oauth.token_revoke`, `oauth.refresh_reuse`. Detail never contains tokens, codes, or verifiers.

## v1.4.1 amendments (2026-10-14, from the OAuth-wave security review)

1. **Code reuse** (§4.1): a second redemption of an authorization code revokes the **whole grant family** (every session with that `grant_id`, including tokens issued by later refreshes, and any `api_delegated` sessions derived from them), not only the sessions issued directly from the code.
2. **Token endpoint rate limit** (§4.4): requests authenticated as `bot-mcp-server` are exempt from the per-IP limit.
3. **RS issuer** (§1): bot-mcp-server advertises `authorization_servers` = the API origin (scheme, host, port) and refuses to start if its API URL has a path, query or fragment.
4. **RS exchange bounds** (§7): bot-mcp-server caps concurrent in-flight exchanges (over the cap → 503) and remembers a subject token refused with `invalid_grant` for 60 s (keyed by its SHA-256, bounded, oldest evicted), answering 401 without another exchange.
5. **Device approval** (§9): `GET /v1/auth/device/{user_code}` and its `approve` and `deny` routes need a `console` session; any other kind → 401.
6. **Resource identifier** (§1, §2): the RS resource is the MCP endpoint URL `<mcp origin>/mcp`, the canonical server URI that MCP clients (Claude Code) send as `resource`. The bare origin is refused with `invalid_target`. Found in the first live Claude Code sign-in, 2026-10-15.
