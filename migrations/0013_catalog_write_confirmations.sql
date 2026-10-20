-- Catalog write confirmations (api-v1 v1.12). Applied only by
-- `bot-api-server --migrate` (SET ROLE deploybot_owner). The matching
-- rollback is 0013_catalog_write_confirmations.down.sql. --migrate does not
-- apply *.down.sql.
--
-- A delegated catalog create, update, or delete stores one single-use plan.
-- The confirm route reads catalog_confirmations, then service_confirmations,
-- then this table. body is the normalized ImageSpec applied on confirm. It
-- is never returned. base_spec_hash is null for create. Pending plans are
-- not secrets: env-set values and file contents are not in the spec.
--
-- user_id and project_id both ON DELETE CASCADE (v1.12). service_confirmations
-- does not cascade its user foreign key.

CREATE TABLE app.catalog_write_confirmations (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL,
    project_id uuid NOT NULL,
    action text NOT NULL,
    entry_name text NOT NULL,
    base_spec_hash text,
    body jsonb,
    request_hash bytea NOT NULL,
    idempotency_key text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT catalog_write_confirmations_token_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT catalog_write_confirmations_request_len CHECK (octet_length(request_hash) = 32),
    CONSTRAINT catalog_write_confirmations_action_chk CHECK (action IN ('create', 'update', 'delete')),
    CONSTRAINT catalog_write_confirmations_name_chk CHECK (entry_name ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
    CONSTRAINT catalog_write_confirmations_base_chk CHECK (base_spec_hash IS NULL OR base_spec_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT catalog_write_confirmations_key_chk CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT catalog_write_confirmations_body_chk CHECK (body IS NULL OR jsonb_typeof(body) = 'object'),
    CONSTRAINT catalog_write_confirmations_shape_chk CHECK (
        (action = 'create' AND body IS NOT NULL AND base_spec_hash IS NULL)
        OR (action = 'update' AND body IS NOT NULL AND base_spec_hash IS NOT NULL)
        OR (action = 'delete' AND body IS NULL AND base_spec_hash IS NOT NULL)
    ),
    CONSTRAINT catalog_write_confirmations_user_fk FOREIGN KEY (user_id) REFERENCES app.users (id) ON DELETE CASCADE,
    CONSTRAINT catalog_write_confirmations_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE
);

-- Default privileges grant app CRUD. Narrow this table the same way as
-- app.service_confirmations: the server updates used_at and nothing else.
REVOKE ALL ON TABLE app.catalog_write_confirmations FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_write_confirmations TO deploybot_api;
GRANT UPDATE (used_at) ON TABLE app.catalog_write_confirmations TO deploybot_api;
