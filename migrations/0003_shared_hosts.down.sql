-- Hand-run rollback for 0003_shared_hosts.sql. --migrate does not apply this file.
-- Run it as deploybot_owner, and only before phase 2 deploys: until then
-- services.project_id is derivable from hosts.project_id, so dropping the
-- column loses nothing that the next --migrate cannot rebuild.
--
-- After this script, delete the 0003_shared_hosts.sql row from
-- app.schema_migrations before running --migrate again.
--
--   DELETE FROM app.schema_migrations WHERE name = '0003_shared_hosts.sql';

DROP TABLE IF EXISTS app.host_shares;
DROP FUNCTION IF EXISTS app.host_shares_not_owner();
ALTER TABLE app.services DROP COLUMN IF EXISTS project_id;
