-- Service names. Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0004_service_names.down.sql. --migrate does not apply *.down.sql.
--
-- display_name is set by people. owner_user is the account that owns
-- the listening socket, as reported by the agent. Both are nullable.
-- Existing rows stay NULL. Grants are unchanged: these are columns on
-- app.services, which deploybot_api already has CRUD on.

ALTER TABLE app.services
    ADD COLUMN display_name text NULL,
    ADD COLUMN owner_user text NULL;

-- Case-insensitive per host. Several NULLs are allowed. The API maps
-- a unique violation of this index to conflict.
CREATE UNIQUE INDEX services_host_display_name_uidx
    ON app.services (host_id, lower(display_name))
    WHERE display_name IS NOT NULL;

-- 0003 creates services_project_idx. Keep it when this migration runs
-- on a database that already has the index.
CREATE INDEX IF NOT EXISTS services_project_idx ON app.services (project_id);
