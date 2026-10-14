-- Shared hosts. Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0003_shared_hosts.down.sql. --migrate does not apply *.down.sql.
--
-- A host keeps one owning project (hosts.project_id). host_shares grants
-- another project metrics or deploy access. The owning project cannot
-- also be a share. services.project_id is backfilled from the host
-- before it becomes NOT NULL.

CREATE TABLE app.host_shares (
    host_id uuid NOT NULL REFERENCES app.hosts (id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES app.projects (id) ON DELETE CASCADE,
    level text NOT NULL,
    created_by uuid REFERENCES app.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, project_id),
    CONSTRAINT host_shares_level_chk CHECK (level IN ('metrics', 'deploy'))
);

CREATE INDEX host_shares_project_idx ON app.host_shares (project_id);

-- Reject a share whose project is the host's owner. The API also returns
-- bad_request. SECURITY DEFINER so the check does not depend on the
-- caller's grants. The constraint name is how the API maps the error.
CREATE FUNCTION app.host_shares_not_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $fn$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM app.hosts AS h
        WHERE h.id = NEW.host_id
          AND h.project_id = NEW.project_id
    ) THEN
        RAISE EXCEPTION 'host share cannot be the owning project'
            USING ERRCODE = '23514', CONSTRAINT = 'host_shares_not_owner';
    END IF;
    RETURN NEW;
END;
$fn$;

REVOKE ALL ON FUNCTION app.host_shares_not_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.host_shares_not_owner() TO deploybot_api;

CREATE TRIGGER host_shares_not_owner
    BEFORE INSERT OR UPDATE ON app.host_shares
    FOR EACH ROW
    EXECUTE FUNCTION app.host_shares_not_owner();

-- Default privileges already grant app CRUD to deploybot_api. Say it
-- here as well so the new table does not depend on grant timing.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.host_shares TO deploybot_api;

ALTER TABLE app.services
    ADD COLUMN project_id uuid REFERENCES app.projects (id);

UPDATE app.services AS s
SET project_id = h.project_id
FROM app.hosts AS h
WHERE h.id = s.host_id
  AND s.project_id IS NULL;

ALTER TABLE app.services
    ALTER COLUMN project_id SET NOT NULL;

CREATE INDEX services_project_idx ON app.services (project_id);
