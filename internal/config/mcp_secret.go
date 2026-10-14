package config

import (
	"errors"
	"io"
	"os"
	"strings"
)

// ReadMCPClientSecret reads the first line of path.
// The file must be a regular non-symlink file with mode 0600.
// Only a trailing CR is removed. The line must be at least 32 characters.
// The line is not logged and is never included in an error.
func ReadMCPClientSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is missing")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE must not be a symlink")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE must be mode 0600")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is missing")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE must be mode 0600")
	}
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is unreadable")
	}
	line := string(buf[:n])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is empty")
	}
	if len(line) < 32 {
		return "", errors.New("BOT_API_MCP_CLIENT_SECRET_FILE is too short")
	}
	return line, nil
}
