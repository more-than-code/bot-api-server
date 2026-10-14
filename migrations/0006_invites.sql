-- Project invite links. Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0006_invites.down.sql. --migrate does not apply *.down.sql.
--
-- An invite is a bearer token. The plaintext is not stored. deploybot_api
-- may read and insert rows, and may update only uses and revoked_at.
-- Soft-delete of a project does not fire the foreign key, so
-- invites_delete_for_project removes the rows. A real DELETE of the
-- project still cascades.

CREATE TABLE app.invites (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    role text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    max_uses integer NOT NULL,
    uses integer NOT NULL DEFAULT 0,
    revoked_at timestamptz,
    CONSTRAINT invites_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT invites_created_by_fk FOREIGN KEY (created_by) REFERENCES app.users (id),
    CONSTRAINT invites_hash_unique UNIQUE (token_hash),
    CONSTRAINT invites_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT invites_role_chk CHECK (role IN ('admin', 'viewer')),
    CONSTRAINT invites_max_uses_chk CHECK (max_uses BETWEEN 1 AND 50),
    CONSTRAINT invites_uses_chk CHECK (uses BETWEEN 0 AND max_uses)
);

CREATE INDEX invites_project_idx ON app.invites (project_id);

-- Default privileges grant app CRUD to deploybot_api. Narrow this table
-- so the runtime role cannot rewrite the token hash, the role, or the cap.
REVOKE ALL ON TABLE app.invites FROM deploybot_api;
GRANT SELECT, INSERT ON TABLE app.invites TO deploybot_api;
GRANT UPDATE (uses, revoked_at) ON TABLE app.invites TO deploybot_api;

-- Owner-only delete, callable when a project is soft-deleted. The function
-- owner is deploybot_owner, so SECURITY DEFINER may delete the rows.
CREATE FUNCTION app.invites_delete_for_project(p_project_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $fn$
    DELETE FROM app.invites WHERE project_id = p_project_id;
$fn$;

REVOKE ALL ON FUNCTION app.invites_delete_for_project(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.invites_delete_for_project(uuid) TO deploybot_api;
