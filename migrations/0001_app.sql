-- Phase 1 app schema. Applied only by `bot-api-server --migrate`,
-- which has already SET ROLE deploybot_owner.
-- Schema app is created by migrations/roles.sql.example before this file.
-- Hourly continuous aggregates are not created in wave 1.

CREATE TABLE app.schema_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    name text NOT NULL DEFAULT '',
    avatar_url text NOT NULL DEFAULT '',
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_lower CHECK (email = lower(email)),
    CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE TABLE app.user_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES app.users (id),
    provider text NOT NULL,
    provider_subject text NOT NULL,
    email text NOT NULL,
    email_verified boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identities_provider_chk CHECK (provider IN ('google', 'github')),
    CONSTRAINT user_identities_provider_subject_unique UNIQUE (provider, provider_subject)
);

CREATE TABLE app.sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES app.users (id),
    token_hash bytea NOT NULL,
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_kind_chk CHECK (kind IN ('console', 'mcp')),
    CONSTRAINT sessions_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT sessions_token_hash_len CHECK (octet_length(token_hash) = 32)
);

CREATE TABLE app.projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL,
    created_by uuid NOT NULL REFERENCES app.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    CONSTRAINT projects_slug_unique UNIQUE (slug)
);

CREATE TABLE app.project_members (
    project_id uuid NOT NULL REFERENCES app.projects (id),
    user_id uuid NOT NULL REFERENCES app.users (id),
    role text NOT NULL,
    added_by uuid REFERENCES app.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id),
    CONSTRAINT project_members_role_chk CHECK (role IN ('owner', 'admin', 'viewer'))
);

CREATE UNIQUE INDEX project_members_one_owner
    ON app.project_members (project_id)
    WHERE role = 'owner';

CREATE TABLE app.hosts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES app.projects (id),
    name text NOT NULL,
    node_type text NOT NULL,
    os text NOT NULL,
    arch text NOT NULL,
    always_on boolean NOT NULL,
    agent_version text NOT NULL,
    last_seen_at timestamptz,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT hosts_project_name_unique UNIQUE (project_id, name),
    CONSTRAINT hosts_node_type_chk CHECK (node_type IN ('pi', 'workstation'))
);

CREATE TABLE app.join_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES app.projects (id),
    token_hash bytea NOT NULL,
    host_name_hint text,
    created_by uuid NOT NULL REFERENCES app.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    used_by_host_id uuid REFERENCES app.hosts (id),
    revoked_at timestamptz,
    CONSTRAINT join_tokens_hash_unique UNIQUE (token_hash),
    CONSTRAINT join_tokens_hash_len CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX join_tokens_project_idx ON app.join_tokens (project_id, created_at, id);

-- denied_at is not in design §6.2. The device status "denied" cannot be
-- stored without it. created_at is recorded for ordering. See NOTES.md.
CREATE TABLE app.device_codes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash bytea NOT NULL,
    user_code text NOT NULL,
    client_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    approved_by_user_id uuid REFERENCES app.users (id),
    approved_at timestamptz,
    denied_at timestamptz,
    consumed_at timestamptz,
    CONSTRAINT device_codes_hash_unique UNIQUE (device_code_hash),
    CONSTRAINT device_codes_hash_len CHECK (octet_length(device_code_hash) = 32),
    CONSTRAINT device_codes_user_code_unique UNIQUE (user_code),
    CONSTRAINT device_codes_not_both CHECK (approved_at IS NULL OR denied_at IS NULL)
);

CREATE TABLE app.agent_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id uuid NOT NULL REFERENCES app.hosts (id),
    credential_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_from uuid REFERENCES app.agent_credentials (id),
    revoked_at timestamptz,
    CONSTRAINT agent_credentials_hash_unique UNIQUE (credential_hash),
    CONSTRAINT agent_credentials_hash_len CHECK (octet_length(credential_hash) = 32)
);

CREATE TABLE app.services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id uuid NOT NULL REFERENCES app.hosts (id),
    name text NOT NULL,
    source text NOT NULL,
    kind text NOT NULL,
    ports integer[] NOT NULL DEFAULT '{}',
    systemd_unit text,
    systemd_scope text,
    container_name text,
    process_match text,
    deploy_spec jsonb,
    owned_via text,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT services_host_name_unique UNIQUE (host_id, name),
    CONSTRAINT services_source_chk CHECK (source IN ('discovered', 'declared', 'owned')),
    CONSTRAINT services_kind_chk CHECK (kind IN ('container', 'systemd', 'process')),
    CONSTRAINT services_scope_chk CHECK (systemd_scope IS NULL OR systemd_scope IN ('system', 'user')),
    CONSTRAINT services_owned_via_chk CHECK (owned_via IS NULL OR owned_via IN ('adopt', 'create'))
);

CREATE TABLE app.health_checks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id uuid NOT NULL REFERENCES app.services (id) ON DELETE CASCADE,
    protocol text NOT NULL,
    port integer NOT NULL,
    path text,
    interval_sec integer NOT NULL,
    expect_status_min integer NOT NULL,
    expect_status_max integer NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    CONSTRAINT health_checks_protocol_chk CHECK (protocol IN ('http', 'tcp')),
    CONSTRAINT health_checks_interval_chk CHECK (interval_sec BETWEEN 30 AND 300),
    CONSTRAINT health_checks_port_chk CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT health_checks_expect_chk CHECK (
        expect_status_min BETWEEN 200 AND 399
        AND expect_status_max BETWEEN 200 AND 399
        AND expect_status_min <= expect_status_max
    ),
    CONSTRAINT health_checks_path_chk CHECK (
        (protocol = 'tcp' AND path IS NULL)
        OR (
            protocol = 'http'
            AND path IS NOT NULL
            AND octet_length(path) <= 512
            AND left(path, 1) = '/'
            AND left(path, 2) <> '//'
            AND path !~ '[@\\?#[:space:][:cntrl:]]'
        )
    )
);

CREATE TABLE app.audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES app.users (id),
    via text NOT NULL,
    project_id uuid REFERENCES app.projects (id),
    host_id uuid REFERENCES app.hosts (id),
    service_id uuid REFERENCES app.services (id),
    action text NOT NULL,
    decision text NOT NULL,
    task_id uuid,
    result text,
    error_code text,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT audit_log_via_chk CHECK (via IN ('console', 'mcp', 'agent', 'system')),
    CONSTRAINT audit_log_decision_chk CHECK (decision IN ('allowed', 'denied'))
);

CREATE INDEX audit_log_project_at_idx ON app.audit_log (project_id, at DESC, id DESC);

-- Default privileges grant CRUD on every new app table. Narrow these two
-- after they exist so the result does not depend on grant timing.
REVOKE ALL ON TABLE app.audit_log FROM deploybot_api;
GRANT SELECT, INSERT ON TABLE app.audit_log TO deploybot_api;
REVOKE ALL ON TABLE app.schema_migrations FROM deploybot_api;
