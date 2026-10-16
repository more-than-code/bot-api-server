package seal

import (
	"bytes"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	box, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	aad := EnvAAD("proj", "services", "DB_PASSWORD")
	n1, c1, err := box.Seal(aad, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	n2, c2, err := box.Seal(aad, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) || bytes.Equal(c1, c2) {
		t.Fatal("nonce reused")
	}
	if len(n1) != 12 {
		t.Fatalf("nonce %d", len(n1))
	}
	plain, err := box.Open(aad, n1, c1)
	if err != nil || string(plain) != "secret-value" {
		t.Fatalf("open %q %v", plain, err)
	}
	c1[len(c1)-1] ^= 1
	if _, err := box.Open(aad, n1, c1); err == nil || err.Error() != "decrypt failed" {
		t.Fatalf("tamper %v", err)
	}
	n3, c3, err := box.Seal(aad, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Open(RegistryAAD("proj", "ghcr.io"), n3, c3); err == nil || err.Error() != "decrypt failed" {
		t.Fatalf("aad %v", err)
	}
	if FileAAD("p", "n") != "p|file|n" {
		t.Fatalf("FileAAD %q", FileAAD("p", "n"))
	}
	fa := FileAAD("proj", "site.conf")
	fn, fc, err := box.Seal(fa, []byte("file-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := box.Open(fa, fn, fc); err != nil || string(got) != "file-secret" {
		t.Fatalf("file open %q %v", got, err)
	}
	if _, err := box.Open(EnvAAD("proj", "services", "site.conf"), fn, fc); err == nil || err.Error() != "decrypt failed" {
		t.Fatalf("file aad %v", err)
	}
	fc[0] ^= 1
	if _, err := box.Open(fa, fn, fc); err == nil || err.Error() != "decrypt failed" {
		t.Fatalf("file tamper %v", err)
	}
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key")
	}
	if _, _, err := (*Box)(nil).Seal(aad, []byte("x")); err == nil {
		t.Fatal("nil box sealed")
	}
}
