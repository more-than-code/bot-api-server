-- Hand-run rollback for 0010_project_files.sql. --migrate does not apply this file.
-- Encrypted file contents are dropped and cannot be rebuilt.
-- Take a dump first. Edit image entries that name these files before this drop.
--
-- Run as deploybot_owner. After this script, delete the applied row before
-- --migrate will run 0010 again:
--
--   DELETE FROM app.schema_migrations WHERE name = '0010_project_files.sql';

DROP TABLE IF EXISTS app.project_files;
