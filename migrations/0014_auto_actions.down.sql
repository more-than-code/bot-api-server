-- Hand-run rollback for 0014_auto_actions.sql. --migrate does not apply this file.
-- It runs in one transaction, so a failure leaves 0014 fully applied.
-- Automatic-action history rows (via = 'agent') are deleted and cannot be
-- rebuilt. Take a dump first. Roll back the agents and clear health_policy
-- from every entry before this (api-v1 v1.15 item 7).
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0014 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0014_auto_actions.sql';

BEGIN;

DELETE FROM app.image_deploys WHERE via = 'agent';

ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_agent_flight_chk;
ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_auto_outcome_chk;
ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_auto_id_chk;

ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_outcome_chk;
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_outcome_chk CHECK (outcome IN (
        'in_flight', 'succeeded', 'unchanged', 'failed', 'timeout',
        'rolled_back', 'rollback_failed', 'image_unavailable', 'forbidden_spec', 'conflict'
    ));

ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_by_chk;
ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_via_chk;
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_via_chk CHECK (via IN ('console', 'mcp'));

ALTER TABLE app.image_deploys DROP CONSTRAINT IF EXISTS image_deploys_auto_action_unique;
ALTER TABLE app.image_deploys DROP COLUMN IF EXISTS auto_action_id;
ALTER TABLE app.image_deploys ALTER COLUMN by_user SET NOT NULL;

COMMIT;
