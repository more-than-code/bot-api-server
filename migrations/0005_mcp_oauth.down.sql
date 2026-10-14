-- Hand-run rollback for 0005_mcp_oauth.sql. --migrate does not apply this file.
-- Drops the OAuth tables and the session columns added by 0005, and restores
-- the kind CHECK from 0001. Sessions of kind mcp_access, mcp_refresh, and
-- api_delegated are deleted. Legacy mcp rows stay, still expired by the
-- cut-over; this script does not make them valid again. Clients, grants,
-- codes, and pending requests are lost.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0005 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0005_mcp_oauth.sql';

DELETE FROM app.sessions WHERE kind NOT IN ('console', 'mcp');

ALTER TABLE app.sessions DROP CONSTRAINT sessions_kind_chk;

ALTER TABLE app.sessions
    DROP COLUMN audience,
    DROP COLUMN grant_id,
    DROP COLUMN client_id,
    DROP COLUMN code_id,
    DROP COLUMN rotated_at;

ALTER TABLE app.sessions
    ADD CONSTRAINT sessions_kind_chk CHECK (kind IN ('console', 'mcp'));

DROP TABLE app.oauth_codes;
DROP TABLE app.oauth_requests;
DROP TABLE app.oauth_grants;
DROP TABLE app.oauth_clients;
