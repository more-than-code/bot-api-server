-- Hand-run rollback for 0009_catalog_images.sql. --migrate does not apply this file.
-- Encrypted env values and registry tokens are dropped and cannot be rebuilt.
-- Take a dump first.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0009 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0009_catalog_images.sql';

-- Restored checks reject image entries, deploy grants, and image confirmations.
DELETE FROM app.catalog_entries WHERE kind = 'image';
DELETE FROM app.catalog_grants
WHERE NOT (actions <@ ARRAY['run', 'stop', 'restart', 'logs']::text[]);
DELETE FROM app.catalog_confirmations
WHERE action NOT IN ('run', 'stop', 'restart');

DROP TABLE IF EXISTS app.env_values;
DROP TABLE IF EXISTS app.env_sets;
DROP TABLE IF EXISTS app.registries;
DROP TABLE IF EXISTS app.image_deploys;

ALTER TABLE app.services DROP CONSTRAINT IF EXISTS services_image_digest_chk;
ALTER TABLE app.services DROP COLUMN IF EXISTS image_digest;

ALTER TABLE app.catalog_entries DROP CONSTRAINT catalog_entries_kind_chk;
ALTER TABLE app.catalog_entries
    ADD CONSTRAINT catalog_entries_kind_chk CHECK (kind = 'program');

ALTER TABLE app.catalog_grants DROP CONSTRAINT catalog_grants_actions_chk;
ALTER TABLE app.catalog_grants
    ADD CONSTRAINT catalog_grants_actions_chk CHECK (
        cardinality(actions) BETWEEN 1 AND 4
        AND actions <@ ARRAY['run', 'stop', 'restart', 'logs']::text[]
    );

ALTER TABLE app.catalog_confirmations DROP CONSTRAINT catalog_confirmations_action_chk;
ALTER TABLE app.catalog_confirmations
    ADD CONSTRAINT catalog_confirmations_action_chk CHECK (action IN ('run', 'stop', 'restart'));

ALTER TABLE app.catalog_confirmations DROP CONSTRAINT IF EXISTS catalog_confirmations_image_digest_chk;
ALTER TABLE app.catalog_confirmations DROP COLUMN IF EXISTS image_digest;
ALTER TABLE app.catalog_confirmations DROP COLUMN IF EXISTS image_force;
