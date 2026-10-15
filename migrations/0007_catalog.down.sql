-- Hand-run rollback for 0007_catalog.sql. --migrate does not apply this file.
-- Drops the catalog, its grants, host approvals, confirmations, and
-- idempotency keys. Clears hosts.programs and services.catalog_entry.
-- Running program units are not stopped.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0007 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0007_catalog.sql';

ALTER TABLE app.services DROP CONSTRAINT IF EXISTS services_catalog_entry_chk;
ALTER TABLE app.services DROP COLUMN IF EXISTS catalog_entry;
ALTER TABLE app.hosts DROP COLUMN IF EXISTS programs;

DROP TABLE IF EXISTS app.idempotency_keys;
DROP TABLE IF EXISTS app.catalog_confirmations;
DROP TABLE IF EXISTS app.catalog_host_approvals;
DROP TABLE IF EXISTS app.catalog_grants;
DROP TABLE IF EXISTS app.catalog_entries;
