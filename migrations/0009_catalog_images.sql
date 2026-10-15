-- Catalog images (api-v1 v1.8). Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0009_catalog_images.down.sql. --migrate does not apply *.down.sql.
--
-- Secret env values and registry tokens are ciphertext only. The nonce is
-- stored beside each ciphertext. app.services.container_name already exists
-- (0001), and this migration adds image_digest. deploybot_api already has table
-- UPDATE on app.services, so the new column needs no extra grant.

ALTER TABLE app.catalog_entries DROP CONSTRAINT catalog_entries_kind_chk;
ALTER TABLE app.catalog_entries
    ADD CONSTRAINT catalog_entries_kind_chk CHECK (kind IN ('program', 'image'));

ALTER TABLE app.catalog_grants DROP CONSTRAINT catalog_grants_actions_chk;
ALTER TABLE app.catalog_grants
    ADD CONSTRAINT catalog_grants_actions_chk CHECK (
        cardinality(actions) BETWEEN 1 AND 5
        AND actions <@ ARRAY['run', 'stop', 'restart', 'logs', 'deploy']::text[]
    );

ALTER TABLE app.catalog_confirmations DROP CONSTRAINT catalog_confirmations_action_chk;
ALTER TABLE app.catalog_confirmations
    ADD CONSTRAINT catalog_confirmations_action_chk CHECK (
        action IN ('run', 'stop', 'restart', 'deploy', 'rollback', 'remove')
    );

-- The confirmation id is single use. image_digest and image_force let the
-- confirm step rebuild the same image task. They are not secrets.
ALTER TABLE app.catalog_confirmations
    ADD COLUMN image_digest text NULL,
    ADD COLUMN image_force boolean NULL;
ALTER TABLE app.catalog_confirmations
    ADD CONSTRAINT catalog_confirmations_image_digest_chk CHECK (
        image_digest IS NULL OR image_digest ~ '^sha256:[0-9a-f]{64}$'
    );

ALTER TABLE app.services ADD COLUMN image_digest text NULL;
ALTER TABLE app.services ADD CONSTRAINT services_image_digest_chk CHECK (
    image_digest IS NULL OR image_digest ~ '^sha256:[0-9a-f]{64}$'
);

CREATE TABLE app.image_deploys (
    id uuid PRIMARY KEY,
    entry_id uuid NOT NULL,
    host_id uuid NOT NULL,
    digest text,
    spec_hash text NOT NULL,
    outcome text NOT NULL,
    exit_code integer,
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    by_user uuid NOT NULL,
    via text NOT NULL,
    in_flight boolean NOT NULL,
    in_flight_until timestamptz,
    CONSTRAINT image_deploys_entry_fk FOREIGN KEY (entry_id) REFERENCES app.catalog_entries (id) ON DELETE CASCADE,
    CONSTRAINT image_deploys_host_fk FOREIGN KEY (host_id) REFERENCES app.hosts (id) ON DELETE CASCADE,
    CONSTRAINT image_deploys_by_fk FOREIGN KEY (by_user) REFERENCES app.users (id),
    CONSTRAINT image_deploys_digest_chk CHECK (digest IS NULL OR digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT image_deploys_hash_chk CHECK (spec_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT image_deploys_outcome_chk CHECK (outcome IN (
        'in_flight', 'succeeded', 'unchanged', 'failed', 'timeout',
        'rolled_back', 'rollback_failed', 'image_unavailable', 'forbidden_spec', 'conflict'
    )),
    CONSTRAINT image_deploys_via_chk CHECK (via IN ('console', 'mcp')),
    CONSTRAINT image_deploys_flight_chk CHECK (
        (in_flight AND outcome = 'in_flight' AND finished_at IS NULL)
        OR (NOT in_flight AND outcome <> 'in_flight' AND finished_at IS NOT NULL)
    ),
    CONSTRAINT image_deploys_until_chk CHECK (NOT in_flight OR in_flight_until IS NOT NULL)
);

CREATE UNIQUE INDEX image_deploys_in_flight_uidx
    ON app.image_deploys (host_id, entry_id)
    WHERE in_flight;

CREATE INDEX image_deploys_history_idx
    ON app.image_deploys (entry_id, host_id, finished_at DESC);

CREATE TABLE app.env_sets (
    project_id uuid NOT NULL,
    name text NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by uuid NOT NULL,
    PRIMARY KEY (project_id, name),
    CONSTRAINT env_sets_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT env_sets_user_fk FOREIGN KEY (updated_by) REFERENCES app.users (id),
    CONSTRAINT env_sets_name_chk CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,47}$')
);

CREATE TABLE app.env_values (
    project_id uuid NOT NULL,
    set_name text NOT NULL,
    key text NOT NULL,
    is_secret boolean NOT NULL,
    value text,
    nonce bytea,
    ciphertext bytea,
    key_version integer,
    PRIMARY KEY (project_id, set_name, key),
    CONSTRAINT env_values_set_fk FOREIGN KEY (project_id, set_name)
        REFERENCES app.env_sets (project_id, name) ON DELETE CASCADE,
    CONSTRAINT env_values_key_chk CHECK (key ~ '^[A-Z_][A-Z0-9_]{0,63}$'),
    CONSTRAINT env_values_plain_len_chk CHECK (value IS NULL OR octet_length(value) <= 4096),
    CONSTRAINT env_values_form_chk CHECK (
        (
            NOT is_secret
            AND value IS NOT NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND key_version IS NULL
        )
        OR (
            is_secret
            AND value IS NULL
            AND octet_length(nonce) = 12
            AND octet_length(ciphertext) BETWEEN 16 AND 4112
            AND key_version >= 1
        )
    )
);

CREATE TABLE app.registries (
    project_id uuid NOT NULL,
    host text NOT NULL,
    username text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    key_version integer NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by uuid NOT NULL,
    PRIMARY KEY (project_id, host),
    CONSTRAINT registries_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT registries_user_fk FOREIGN KEY (updated_by) REFERENCES app.users (id),
    CONSTRAINT registries_host_chk CHECK (
        host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$'
        AND (
            position(':' IN host) = 0
            OR split_part(host, ':', 2)::int BETWEEN 1 AND 65535
        )
    ),
    CONSTRAINT registries_username_chk CHECK (
        octet_length(username) BETWEEN 1 AND 255
        AND username !~ E'[\r\n]'
    ),
    CONSTRAINT registries_seal_chk CHECK (
        octet_length(nonce) = 12
        AND octet_length(ciphertext) BETWEEN 16 AND 4112
        AND key_version >= 1
    )
);

REVOKE ALL ON TABLE app.image_deploys FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.image_deploys TO deploybot_api;
GRANT UPDATE (digest, outcome, exit_code, finished_at, in_flight)
    ON TABLE app.image_deploys TO deploybot_api;

REVOKE ALL ON TABLE app.env_sets FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.env_sets TO deploybot_api;
GRANT UPDATE (updated_at, updated_by) ON TABLE app.env_sets TO deploybot_api;

REVOKE ALL ON TABLE app.env_values FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.env_values TO deploybot_api;
GRANT UPDATE (is_secret, value, nonce, ciphertext, key_version)
    ON TABLE app.env_values TO deploybot_api;

REVOKE ALL ON TABLE app.registries FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.registries TO deploybot_api;
GRANT UPDATE (username, nonce, ciphertext, key_version, updated_at, updated_by)
    ON TABLE app.registries TO deploybot_api;
