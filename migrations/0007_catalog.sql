-- Project catalog (api-v1 v1.6, wave 1 programs). Applied only by
-- `bot-api-server --migrate` (SET ROLE deploybot_owner). The matching
-- rollback is 0007_catalog.down.sql. --migrate does not apply *.down.sql.
--
-- deploybot_api may insert and delete catalog rows. UPDATE is limited to
-- the columns a running server changes. Postgres requires UPDATE on at
-- least one column of a table before SELECT … FOR UPDATE, so each table
-- that is locked names that column below. Grants are replaced by delete
-- and insert, so catalog_grants has no UPDATE. Image entries and
-- secret_env are not stored in this wave.

CREATE TABLE app.catalog_entries (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    spec jsonb NOT NULL,
    spec_hash text NOT NULL,
    command_display text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT catalog_entries_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT catalog_entries_created_by_fk FOREIGN KEY (created_by) REFERENCES app.users (id),
    CONSTRAINT catalog_entries_project_name_unique UNIQUE (project_id, name),
    CONSTRAINT catalog_entries_kind_chk CHECK (kind = 'program'),
    CONSTRAINT catalog_entries_name_chk CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
    CONSTRAINT catalog_entries_hash_chk CHECK (spec_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE app.catalog_grants (
    entry_id uuid NOT NULL,
    subject text NOT NULL,
    actions text[] NOT NULL,
    PRIMARY KEY (entry_id, subject),
    CONSTRAINT catalog_grants_entry_fk FOREIGN KEY (entry_id) REFERENCES app.catalog_entries (id) ON DELETE CASCADE,
    CONSTRAINT catalog_grants_subject_chk CHECK (
        subject IN ('role:admin', 'role:viewer')
        OR subject ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    CONSTRAINT catalog_grants_actions_chk CHECK (
        cardinality(actions) BETWEEN 1 AND 4
        AND actions <@ ARRAY['run', 'stop', 'restart', 'logs']::text[]
    )
);

CREATE TABLE app.catalog_host_approvals (
    entry_id uuid NOT NULL,
    host_id uuid NOT NULL,
    spec_hash text NOT NULL,
    status text NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamptz NOT NULL,
    approved_by uuid,
    approved_at timestamptz,
    PRIMARY KEY (entry_id, host_id),
    CONSTRAINT catalog_approvals_entry_fk FOREIGN KEY (entry_id) REFERENCES app.catalog_entries (id) ON DELETE CASCADE,
    CONSTRAINT catalog_approvals_host_fk FOREIGN KEY (host_id) REFERENCES app.hosts (id) ON DELETE CASCADE,
    CONSTRAINT catalog_approvals_requested_fk FOREIGN KEY (requested_by) REFERENCES app.users (id),
    CONSTRAINT catalog_approvals_approved_fk FOREIGN KEY (approved_by) REFERENCES app.users (id),
    CONSTRAINT catalog_approvals_hash_chk CHECK (spec_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT catalog_approvals_status_chk CHECK (status IN ('pending', 'approved')),
    CONSTRAINT catalog_approvals_approved_pair_chk CHECK (
        (status = 'pending' AND approved_by IS NULL AND approved_at IS NULL)
        OR (status = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE INDEX catalog_approvals_host_idx ON app.catalog_host_approvals (host_id);

CREATE TABLE app.catalog_confirmations (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL,
    project_id uuid NOT NULL,
    entry_id uuid NOT NULL,
    entry_name text NOT NULL,
    host_id uuid NOT NULL,
    action text NOT NULL,
    spec_hash text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT catalog_confirmations_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT catalog_confirmations_req_len CHECK (octet_length(request_hash) = 32),
    CONSTRAINT catalog_confirmations_action_chk CHECK (action IN ('run', 'stop', 'restart')),
    CONSTRAINT catalog_confirmations_user_fk FOREIGN KEY (user_id) REFERENCES app.users (id),
    CONSTRAINT catalog_confirmations_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT catalog_confirmations_entry_fk FOREIGN KEY (entry_id) REFERENCES app.catalog_entries (id) ON DELETE CASCADE,
    CONSTRAINT catalog_confirmations_host_fk FOREIGN KEY (host_id) REFERENCES app.hosts (id) ON DELETE CASCADE
);

CREATE TABLE app.idempotency_keys (
    user_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    status_code integer,
    response jsonb,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, idempotency_key),
    CONSTRAINT idempotency_user_fk FOREIGN KEY (user_id) REFERENCES app.users (id) ON DELETE CASCADE,
    CONSTRAINT idempotency_key_chk CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT idempotency_hash_len CHECK (octet_length(request_hash) = 32),
    CONSTRAINT idempotency_response_pair_chk CHECK (
        (status_code IS NULL AND response IS NULL)
        OR (status_code IS NOT NULL AND response IS NOT NULL)
    )
);

ALTER TABLE app.hosts ADD COLUMN programs jsonb;
ALTER TABLE app.services ADD COLUMN catalog_entry text;
ALTER TABLE app.services ADD CONSTRAINT services_catalog_entry_chk CHECK (
    catalog_entry IS NULL OR catalog_entry ~ '^[a-z0-9][a-z0-9-]{0,47}$'
);

-- Default privileges grant app CRUD. Narrow the new tables.
REVOKE ALL ON TABLE app.catalog_entries FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_entries TO deploybot_api;
GRANT UPDATE (spec, spec_hash, command_display, updated_at) ON TABLE app.catalog_entries TO deploybot_api;

REVOKE ALL ON TABLE app.catalog_grants FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_grants TO deploybot_api;

REVOKE ALL ON TABLE app.catalog_host_approvals FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_host_approvals TO deploybot_api;
GRANT UPDATE (spec_hash, status, requested_by, requested_at, approved_by, approved_at)
    ON TABLE app.catalog_host_approvals TO deploybot_api;

REVOKE ALL ON TABLE app.catalog_confirmations FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_confirmations TO deploybot_api;
GRANT UPDATE (used_at) ON TABLE app.catalog_confirmations TO deploybot_api;

REVOKE ALL ON TABLE app.idempotency_keys FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.idempotency_keys TO deploybot_api;
GRANT UPDATE (status_code, response) ON TABLE app.idempotency_keys TO deploybot_api;
