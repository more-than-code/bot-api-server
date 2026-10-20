-- Hand-run rollback for 0013_catalog_write_confirmations.sql. --migrate does not apply this file.
-- Pending catalog-write plans are dropped. That is harmless: nothing was applied yet.
-- Take a dump first.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0013 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0013_catalog_write_confirmations.sql';

DROP TABLE IF EXISTS app.catalog_write_confirmations;
