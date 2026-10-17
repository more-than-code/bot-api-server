-- Hand-run rollback for 0011_service_confirmations.sql. --migrate does not apply this file.
-- Pending health-check plans are dropped. That is harmless: nothing was applied yet.
-- Take a dump first.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0011 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0011_service_confirmations.sql';

DROP TABLE IF EXISTS app.service_confirmations;
