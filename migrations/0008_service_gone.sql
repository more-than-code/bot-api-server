-- Service presence (api-v1 v1.7). Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0008_service_gone.down.sql. --migrate does not apply *.down.sql.
--
-- gone_at is when a service was missing from its host's latest services
-- report. NULL means the row was in that report. Grants are unchanged:
-- this is a column on app.services, which deploybot_api already updates.
--
-- Backfill: every report writes the same last_seen_at on the rows it
-- contains, so a host's newest last_seen_at is its latest report. Rows
-- earlier than that were not in it.

ALTER TABLE app.services
    ADD COLUMN gone_at timestamptz NULL;

UPDATE app.services AS s
SET gone_at = s.last_seen_at
WHERE s.last_seen_at < (
    SELECT max(peer.last_seen_at)
    FROM app.services AS peer
    WHERE peer.host_id = s.host_id
);
