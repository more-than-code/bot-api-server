package config

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// beforeSecretsOpen runs after the symlink and mode checks and before Open.
// Tests replace the file with a symlink here. Production leaves it nil.
var beforeSecretsOpen func()

// ReadSecretsKey reads BOT_SECRETS_KEY_FILE.
// An empty path means the key is not configured and returns a nil key.
// A set path must be a regular non-symlink file with mode 0600 whose first
// line is standard base64 of exactly 32 bytes. The key and the path are
// never included in an error.
func ReadSecretsKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("BOT_SECRETS_KEY_FILE is missing")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("BOT_SECRETS_KEY_FILE must not be a symlink")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("BOT_SECRETS_KEY_FILE must be mode 0600")
	}
	if beforeSecretsOpen != nil {
		beforeSecretsOpen()
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("BOT_SECRETS_KEY_FILE must not be a symlink")
		}
		return nil, errors.New("BOT_SECRETS_KEY_FILE is missing")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return nil, errors.New("BOT_SECRETS_KEY_FILE must be mode 0600")
	}
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, errors.New("BOT_SECRETS_KEY_FILE is unreadable")
	}
	line := string(buf[:n])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return nil, errors.New("BOT_SECRETS_KEY_FILE is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("BOT_SECRETS_KEY_FILE is invalid")
	}
	return raw, nil
}
