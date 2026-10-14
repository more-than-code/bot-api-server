# Spec: project invite links

**Tier:** 3 (api-v1 v1.5, migration 0006, console route). **Status:** approved by Joe 2026-10-14 ("yes, approve the spec"), all §8 defaults accepted. **Date:** 2026-10-14.
**Request (Joe, 2026-10-14):** "support shared link to invite a user as a project member".

## 1. Goal

Today `POST /v1/projects/{id}/members` takes an email and returns `not_found` until that person has signed in once, so inviting someone new takes two round trips. An admin should instead be able to create a link, send it any way they like, and have whoever opens it sign in with Google and join the project with a preset role.

## 2. Approach

An invite is a bearer token, modelled on host join tokens (api-v1 "Join tokens"):
- 256-bit, 43-char base64url, stored as SHA-256;
- the plaintext is shown once at creation;
- it expires, can be revoked, and is audited.

**Joining needs an explicit click.** Opening the link shows "Join *Project* as *role*?" with a **Join** button that POSTs. A GET never joins, so link previews, chat unfurlers and prefetchers cannot use up an invite or add the wrong account.

**Defaults, with your call in §8:**
- **Single use** (`max_uses` 1, up to 50 allowed).
- **Expires after 7 days** (allowed range 1 h to 30 d).
- **Role** is `viewer` or `admin`, never `owner`. Creating an `admin` invite needs admin+, the same rule as `POST members` today.
- **Not bound to an email.** Whoever holds the link can join, which is the point of a "shared link". The link is therefore a credential. The console says so when it shows the link, and it is never shown again.

**Rejected alternatives:**
- **Email-bound invites:** these need outgoing mail, which we don't have, and the existing email-add already covers that case.
- **Auto-join on GET:** prefetch and unfurl hazards, described above.
- **Reusing the `join_tokens` table:** different subject and lifecycle (a host vs a user). A separate table keeps the CHECKs simple.

## 3. Contract diff (api-v1 v1.5)

New type: `Invite {"id","role","created_by","created_at","expires_at","max_uses","uses","revoked_at"}`. Its status is derived: active, expired, used up, or revoked.

| Method | Path | Who | Body | Result |
|---|---|---|---|---|
| POST | `/v1/projects/{id}/invites` | admin+ | `{"role":"admin\|viewer","expires_in_sec"?:3600..2592000 (default 604800),"max_uses"?:1..50 (default 1)}` | `Invite` + `"token"` + `"url"` (`<BOT_API_CONSOLE_ORIGIN>/invite/<token>`), 201. Token and url appear **only here**. |
| GET | `/v1/projects/{id}/invites` | admin+ | — | list of `Invite` (never the token) |
| DELETE | `/v1/projects/{id}/invites/{invite_id}` | admin+ | — | `null` (sets `revoked_at`) |
| POST | `/v1/invites/lookup` | signed-in user | `{"token"}` | `{"project_name","role","already_member":bool}`. Returns `not_found` for an unknown, expired, used-up or revoked invite; these cases are not told apart. |
| POST | `/v1/invites/accept` | signed-in user | `{"token"}` | `{"project_id","role"}`, 200. |

**Accept rules** (one transaction, with a `SELECT … FOR UPDATE` on the invite row):
- **Invalid invite:** an unknown, expired, used-up or revoked invite → `not_found`.
- **Already a member:** returns 200 with the existing role. It does not count as a use and never downgrades or upgrades the role.
- **Otherwise:** inserts the member and increments `uses`.

The token travels only in POST bodies, never in an API URL. That keeps it out of API access logs.

**Unchanged:** `POST /members` by email, and every other route.

**Audit actions:**
- `invite.create` (role, max_uses, expiry);
- `invite.revoke`;
- `invite.accept` (invite id, user id).

None of these records the token.

**Rate limit:** lookup and accept are limited to 30/min per user and 60/min per IP, in memory, as in the OAuth wave.

## 4. Storage (migration 0006, after the OAuth wave's 0005)

`app.invites`:
- `id uuid pk`;
- `project_id fk → projects on delete cascade`;
- `token_hash bytea unique`;
- `role text check in ('admin','viewer')`;
- `created_by fk users`;
- `created_at`, `expires_at`;
- `max_uses int check 1..50`;
- `uses int default 0 check uses <= max_uses`;
- `revoked_at`.

Grants for `deploybot_api` follow the house style: select, insert, and update (`uses`, `revoked_at`) only. The migration ships with a hand-run `0006_invites.down.sql`.

## 5. Console

**Project → Members tab:**
- an **Invite link** button (icon `Link`) opens a dialog: a role select, an expiry select (1 day / 7 days / 30 days), and uses (1, 5 or 25);
- once the invite is created, the dialog shows the URL with `CopyButton` and the warning "Anyone with this link can join as *role* until it expires. It won't be shown again.";
- below the members table, a "Pending invites" table lists role, created by, expires, and uses/max, with an icon-only **Revoke** `RowAction` (`Ban`) that opens `ConfirmAction`.

**`/invite/[token]`** (new route):
- **Signed out:** redirect to `/signin?next=/invite/<token>`. `safeNext` must accept this path.
- **Load:** server-side lookup. If it fails, show a Notice "This invite link is invalid, expired or already used."
- **Already a member:** "You're already a member", with a link to the project.
- **Otherwise:** "Join *Project* as *role*?", with a **Join** button that calls form action `?/accept` and then `redirect(303, /projects/<id>)`.
- **Headers:** `Cache-Control: no-store`, `Referrer-Policy: no-referrer` (so the token never leaks through the Referer header to the Google sign-in or elsewhere), and `X-Frame-Options: DENY`.

**MCP:** no new tool in this wave. Agents don't need to invite people. Revisit on request.

## 6. Acceptance criteria

1. An admin creates an invite. The token and url are returned once; the list never contains them; the DB holds only the hash.
2. A signed-in non-member opens the url, sees the project name and role, clicks Join, and lands on the project with that role.
3. A single-use invite then refuses a second user with `not_found`. `max_uses` = N admits exactly N users under concurrent accepts (race test).
4. Expired, revoked, and unknown tokens all give the same `not_found` body.
5. An existing member who accepts keeps their role, and `uses` does not change.
6. A viewer cannot create, list or revoke invites (`forbidden`); a non-member gets `not_found`; a role of `owner` gives `bad_request`.
7. A GET of `/invite/<token>` never changes state.
8. The invite page sends `no-store`, `no-referrer` and the frame-denial header.
9. Audit rows are written for create, revoke and accept, and none contains the token.
10. Lookup and accept hit their rate limits.
11. Deleting a project cascades its invites.

## 7. Rollout and rollback

1. Workers for API and console run in parallel, as in earlier waves.
2. Gates and Grok lenses: security twice on the API, plus spec, tests and ui.
3. `TestIntegration` on pi4.
4. Migrate pi4 to 0006.

**Rollback:** revert the commits and run the down script. Existing members are unaffected, because accepting only inserts membership rows.

## 8. Questions for Joe (defaults in bold)

1. Single use by default, with up to 50 uses allowed? **Yes.**
2. Allow `admin` invites, or `viewer` only? **Both, admin+ to create.**
3. Default expiry: **7 days**, max 30?
4. Order: **after the OAuth wave lands, before catalog wave 1** (it is small and touches neither the agent nor pi1)?
