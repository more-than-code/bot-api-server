-- Revoked-host service rows (api-v1 v1.10.1). Applied only by
-- `bot-api-server --migrate` (SET ROLE deploybot_owner). The matching
-- rollback is 0012_revoked_host_rows.down.sql. --migrate does not
-- apply *.down.sql.
--
-- A revoked host never sends another services report, so rows from
-- before this version can still have gone_at NULL. Backfill those
-- from the host's revoked_at. No schema change. Grants are unchanged:
-- deploybot_api already updates app.services. Idempotent: a later run
-- matches no row, because gone_at is no longer NULL.

UPDATE app.services AS s
SET gone_at = h.revoked_at
FROM app.hosts AS h
WHERE s.host_id = h.id
  AND h.revoked_at IS NOT NULL
  AND s.gone_at IS NULL;
