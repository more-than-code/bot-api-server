package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecretsKey(t *testing.T) {
	key, err := ReadSecretsKey("")
	if err != nil || key != nil {
		t.Fatalf("absent: %v %v", key, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	raw := bytes32()
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	line := base64.StdEncoding.EncodeToString(raw)
	write(line+"\r\n", 0o600)
	got, err := ReadSecretsKey(path)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("read %v %v", got, err)
	}
	write(base64.StdEncoding.EncodeToString(raw[:16])+"\n", 0o600)
	_, err = ReadSecretsKey(path)
	if err == nil || strings.Contains(err.Error(), line) || strings.Contains(err.Error(), path) {
		t.Fatalf("short: %v", err)
	}
	write(line+"\n", 0o644)
	if _, err := ReadSecretsKey(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode %v", err)
	}
	write(line+"\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretsKey(link); err == nil || strings.Contains(err.Error(), path) {
		t.Fatalf("symlink %v", err)
	}
	if _, err := ReadSecretsKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
}

func TestReadSecretsKeyNoFollowAfterStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	other := filepath.Join(dir, "other")
	key := bytes32()
	alt := bytes32()
	alt[0] ^= 0xff
	write := func(name string, raw []byte) {
		t.Helper()
		body := base64.StdEncoding.EncodeToString(raw) + "\n"
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(path, key)
	write(other, alt)
	beforeSecretsOpen = func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeSecretsOpen = nil })
	got, err := ReadSecretsKey(path)
	if err == nil || !strings.Contains(err.Error(), "symlink") || len(got) != 0 {
		t.Fatalf("swapped symlink %v %v", got, err)
	}
}

func bytes32() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}
