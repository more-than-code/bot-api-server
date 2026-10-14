-- Hand-run rollback for 0004_service_names.sql. --migrate does not apply this file.
-- Names typed by people are lost: services.display_name is dropped and
-- cannot be rebuilt. owner_user is dropped too; the next discovery batch
-- can fill it again. The project_id index from 0003 is left in place,
-- so the table returns to the 0003 shape.
--
-- After this script, delete the applied row before --migrate will run
-- 0004 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0004_service_names.sql';

DROP INDEX IF EXISTS app.services_host_display_name_uidx;
ALTER TABLE app.services DROP COLUMN IF EXISTS display_name;
ALTER TABLE app.services DROP COLUMN IF EXISTS owner_user;
