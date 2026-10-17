-- Health-check confirmations (api-v1 v1.10). Applied only by
-- `bot-api-server --migrate` (SET ROLE deploybot_owner). The matching
-- rollback is 0011_service_confirmations.down.sql. --migrate does not
-- apply *.down.sql.
--
-- A delegated PUT stores one single-use plan. The confirm route reads
-- catalog_confirmations first, then this table. checks is the normalized
-- set the confirm applies: the confirm body does not resend it, and the
-- hash columns cannot rebuild it. Pending plans are not secrets.

CREATE TABLE app.service_confirmations (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    action text NOT NULL,
    request_hash bytea NOT NULL,
    current_hash bytea NOT NULL,
    checks jsonb NOT NULL,
    idempotency_key text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT service_confirmations_token_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT service_confirmations_request_len CHECK (octet_length(request_hash) = 32),
    CONSTRAINT service_confirmations_current_len CHECK (octet_length(current_hash) = 32),
    CONSTRAINT service_confirmations_action_chk CHECK (action = 'health_checks'),
    CONSTRAINT service_confirmations_checks_chk CHECK (jsonb_typeof(checks) = 'array'),
    CONSTRAINT service_confirmations_key_chk CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT service_confirmations_user_fk FOREIGN KEY (user_id) REFERENCES app.users (id),
    CONSTRAINT service_confirmations_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT service_confirmations_service_fk FOREIGN KEY (service_id) REFERENCES app.services (id) ON DELETE CASCADE
);

-- Default privileges grant app CRUD. Narrow this table the same way as
-- app.catalog_confirmations: the server updates used_at and nothing else.
REVOKE ALL ON TABLE app.service_confirmations FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.service_confirmations TO deploybot_api;
GRANT UPDATE (used_at) ON TABLE app.service_confirmations TO deploybot_api;
