-- Project files (api-v1 v1.9). Applied only by `bot-api-server --migrate`
-- (SET ROLE deploybot_owner). The matching rollback is
-- 0010_project_files.down.sql. --migrate does not apply *.down.sql.
--
-- Secret file content is ciphertext only. The nonce is stored beside each
-- ciphertext. Plain file content is text. A check requires exactly one of
-- those forms. The 64-file project limit is enforced by the server.

CREATE TABLE app.project_files (
    project_id uuid NOT NULL,
    name text NOT NULL,
    is_secret boolean NOT NULL,
    content_plain text,
    nonce bytea,
    content_cipher bytea,
    key_version integer,
    sha256 text NOT NULL,
    size integer NOT NULL,
    updated_by uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, name),
    CONSTRAINT project_files_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE,
    CONSTRAINT project_files_user_fk FOREIGN KEY (updated_by) REFERENCES app.users (id),
    CONSTRAINT project_files_name_chk CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CONSTRAINT project_files_sha_chk CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT project_files_size_chk CHECK (size BETWEEN 1 AND 65536),
    CONSTRAINT project_files_form_chk CHECK (
        (
            NOT is_secret
            AND content_plain IS NOT NULL
            AND octet_length(content_plain) = size
            AND nonce IS NULL
            AND content_cipher IS NULL
            AND key_version IS NULL
        )
        OR (
            is_secret
            AND content_plain IS NULL
            AND octet_length(nonce) = 12
            AND content_cipher IS NOT NULL
            AND octet_length(content_cipher) = size + 16
            AND key_version >= 1
        )
    )
);

REVOKE ALL ON TABLE app.project_files FROM deploybot_api;
GRANT SELECT, INSERT, DELETE ON TABLE app.project_files TO deploybot_api;
GRANT UPDATE (is_secret, content_plain, nonce, content_cipher, key_version, sha256, size, updated_by, updated_at)
    ON TABLE app.project_files TO deploybot_api;
