package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadMCPClientSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	const long = "0123456789abcdef0123456789abcdef"
	write(long+"\r\n", 0o600)
	got, err := ReadMCPClientSecret(path)
	if err != nil || got != long {
		t.Fatalf("trailing CR: %q %v", got, err)
	}
	write(" "+long[:31]+"\n", 0o600)
	got, err = ReadMCPClientSecret(path)
	if err != nil || got != " "+long[:31] {
		t.Fatalf("leading space: %q %v", got, err)
	}
	short := long[:31] + "\n"
	write(short, 0o600)
	_, err = ReadMCPClientSecret(path)
	if err == nil {
		t.Fatal("short secret was accepted")
	}
	if strings.Contains(err.Error(), long[:31]) {
		t.Fatalf("error includes the secret: %v", err)
	}
	write("\n", 0o600)
	if _, err := ReadMCPClientSecret(path); err == nil {
		t.Fatal("empty file was accepted")
	}
	write(long[:31]+"\n", 0o644)
	_, err = ReadMCPClientSecret(path)
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode 0644: %v", err)
	}
	if _, err := ReadMCPClientSecret(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file was accepted")
	}
	write(long+"\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMCPClientSecret(link); err == nil {
		t.Fatal("symlink was accepted")
	}
	if _, err := ReadMCPClientSecret(dir); err == nil {
		t.Fatal("directory was accepted")
	}
}
