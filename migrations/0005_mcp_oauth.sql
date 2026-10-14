-- MCP OAuth authorization server. Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0005_mcp_oauth.down.sql. --migrate does not apply *.down.sql.
--
-- oauth-v1 §10. Sessions gain an audience, a grant family, and a client id.
-- kind mcp stays legal so the cut-over can expire those rows in place.
-- Existing mcp sessions stop working in this transaction: users sign in again.
-- deploybot-cli is the device-flow pseudo-client. bot-mcp-server is inserted
-- at process start, because its secret hash comes from the secret file.

CREATE TABLE app.oauth_clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    grant_types text[] NOT NULL DEFAULT '{}',
    response_types text[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method text NOT NULL,
    secret_hash bytea NULL,
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NULL,
    CONSTRAINT oauth_clients_kind_chk CHECK (kind IN ('public', 'internal')),
    CONSTRAINT oauth_clients_auth_chk CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic')),
    CONSTRAINT oauth_clients_secret_len CHECK (secret_hash IS NULL OR octet_length(secret_hash) = 32)
);

INSERT INTO app.oauth_clients (
    id, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, kind
) VALUES (
    'deploybot-cli', 'deploybot-cli', '{}', '{}', '{code}', 'none', 'internal'
);

CREATE TABLE app.oauth_grants (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES app.oauth_clients (id) ON DELETE CASCADE,
    resource text NOT NULL,
    redirect_host text NOT NULL DEFAULT '',
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NULL,
    revoked_at timestamptz NULL,
    CONSTRAINT oauth_grants_kind_chk CHECK (kind IN ('oauth', 'device'))
);

-- One live browser grant per user, client, and resource. Device grants are
-- one family per login, so they are not in this index.
CREATE UNIQUE INDEX oauth_grants_live_oauth_uidx
    ON app.oauth_grants (user_id, client_id, resource)
    WHERE revoked_at IS NULL AND kind = 'oauth';

CREATE INDEX oauth_grants_user_idx ON app.oauth_grants (user_id);

CREATE TABLE app.oauth_requests (
    id text PRIMARY KEY,
    client_id text NOT NULL REFERENCES app.oauth_clients (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    state text NOT NULL DEFAULT '',
    resource text NOT NULL,
    scope text NOT NULL DEFAULT 'deploybot',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz NULL,
    decision text NULL,
    user_id uuid NULL REFERENCES app.users (id),
    CONSTRAINT oauth_requests_decision_chk CHECK (decision IS NULL OR decision IN ('allow', 'deny'))
);

CREATE TABLE app.oauth_codes (
    id uuid PRIMARY KEY,
    code_hash bytea NOT NULL,
    client_id text NOT NULL REFERENCES app.oauth_clients (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    resource text NOT NULL,
    user_id uuid NOT NULL REFERENCES app.users (id),
    grant_id uuid NOT NULL REFERENCES app.oauth_grants (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz NULL,
    CONSTRAINT oauth_codes_hash_unique UNIQUE (code_hash),
    CONSTRAINT oauth_codes_hash_len CHECK (octet_length(code_hash) = 32)
);

ALTER TABLE app.sessions
    ADD COLUMN audience text NULL,
    ADD COLUMN grant_id uuid NULL CONSTRAINT sessions_grant_fk REFERENCES app.oauth_grants (id) ON DELETE CASCADE,
    ADD COLUMN client_id text NULL,
    ADD COLUMN code_id uuid NULL CONSTRAINT sessions_code_fk REFERENCES app.oauth_codes (id) ON DELETE SET NULL,
    ADD COLUMN rotated_at timestamptz NULL;

CREATE INDEX sessions_grant_idx ON app.sessions (grant_id) WHERE grant_id IS NOT NULL;

ALTER TABLE app.sessions DROP CONSTRAINT sessions_kind_chk;
ALTER TABLE app.sessions
    ADD CONSTRAINT sessions_kind_chk CHECK (kind IN ('console', 'mcp', 'mcp_access', 'mcp_refresh', 'api_delegated'));

-- Cut-over. Legacy mcp sessions are the D36 passthrough tokens.
UPDATE app.sessions
SET expires_at = now()
WHERE kind = 'mcp' AND expires_at > now();

-- Default privileges already grant app CRUD to deploybot_api. Say it
-- here as well so the new tables do not depend on grant timing.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.oauth_clients TO deploybot_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.oauth_grants TO deploybot_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.oauth_requests TO deploybot_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.oauth_codes TO deploybot_api;
