-- Hand-run rollback for 0006_invites.sql. --migrate does not apply this file.
-- Drops app.invites and the helper that removes them when a project is
-- soft-deleted. Invite links stop working. Memberships already created by
-- an accept stay.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0006 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0006_invites.sql';

DROP FUNCTION IF EXISTS app.invites_delete_for_project(uuid);
DROP TABLE IF EXISTS app.invites;
