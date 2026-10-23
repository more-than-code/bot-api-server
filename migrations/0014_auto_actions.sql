-- Agent automatic actions in deploy history (api-v1 v1.15). Applied only by
-- `bot-api-server --migrate` (SET ROLE deploybot_owner). The matching
-- rollback is 0014_auto_actions.down.sql. --migrate does not apply *.down.sql.
--
-- An agent auto_action frame (restart, rollback, gave_up, or a failed action) writes one
-- image_deploys row with via = 'agent' and no user. auto_action_id is the
-- frame id, so a replayed frame does not write a second row.
-- Existing rows are unchanged.

ALTER TABLE app.image_deploys ALTER COLUMN by_user DROP NOT NULL;
ALTER TABLE app.image_deploys ADD COLUMN auto_action_id uuid NULL;
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_auto_action_unique UNIQUE (auto_action_id);

ALTER TABLE app.image_deploys DROP CONSTRAINT image_deploys_via_chk;
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_via_chk CHECK (via IN ('console', 'mcp', 'agent'));
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_by_chk CHECK (by_user IS NOT NULL OR via = 'agent');

ALTER TABLE app.image_deploys DROP CONSTRAINT image_deploys_outcome_chk;
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_outcome_chk CHECK (outcome IN (
        'in_flight', 'succeeded', 'unchanged', 'failed', 'timeout',
        'rolled_back', 'rollback_failed', 'image_unavailable', 'forbidden_spec', 'conflict',
        'auto_restarted', 'auto_rolled_back', 'auto_gave_up', 'auto_failed'
    ));

-- rev 2: an agent row has an auto_action_id and only an agent row has one,
-- the auto outcomes belong to agent rows, and an agent row is never in flight.
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_auto_id_chk CHECK ((via = 'agent') = (auto_action_id IS NOT NULL));
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_auto_outcome_chk CHECK (
        outcome NOT IN ('auto_restarted', 'auto_rolled_back', 'auto_gave_up', 'auto_failed') OR via = 'agent'
    );
ALTER TABLE app.image_deploys
    ADD CONSTRAINT image_deploys_agent_flight_chk CHECK (via <> 'agent' OR NOT in_flight);
