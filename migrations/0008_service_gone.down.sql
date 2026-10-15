-- Hand-run rollback for 0008_service_gone.sql. --migrate does not apply this file.
-- Presence is lost: services.gone_at is dropped and cannot be rebuilt.
-- The next complete services report can fill it again.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0008 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0008_service_gone.sql';

ALTER TABLE app.services DROP COLUMN IF EXISTS gone_at;
