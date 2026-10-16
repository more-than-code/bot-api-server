package memstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestProjectFilesRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "file-owner")
	home := catalogProject(t, m, owner.ID, "Files", "files", at)
	other := catalogProject(t, m, owner.ID, "Other", "other", at)
	box, err := seal.New(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "SECRET<FILE>CONTENT-do-not-leak-9f3a"
	first := sealFile(t, box, home.ID.String(), "key.json", secret)
	if _, err := m.PutProjectFile(ctx, home.ID, "key.json", first, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	second := sealFile(t, box, home.ID.String(), "key.json", secret+"-next")
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("nonce was reused")
	}
	if _, err := m.PutProjectFile(ctx, home.ID, "key.json", second, owner.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	plain := plainFile("héllo")
	if _, err := m.PutProjectFile(ctx, home.ID, "app.conf", plain, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PutProjectFile(ctx, other.ID, "app.conf", plainFile("other-plain"), owner.ID, at); err != nil {
		t.Fatal(err)
	}

	listed, err := m.ListProjectFiles(ctx, home.ID)
	if err != nil || len(listed) != 2 || listed[0].Name != "app.conf" || listed[1].Name != "key.json" {
		t.Fatalf("list %#v %v", listed, err)
	}
	if listed[0].SHA256 == nil || *listed[0].SHA256 != plain.SHA256 || listed[0].Plain != "" || listed[1].SHA256 != nil || listed[1].Plain != "" || !listed[1].IsSecret {
		t.Fatalf("list leaked %#v", listed)
	}
	got, err := m.GetProjectFile(ctx, home.ID, "app.conf")
	if err != nil || got.Plain != "héllo" || got.SHA256 == nil || *got.SHA256 != plain.SHA256 {
		t.Fatalf("plain get %#v %v", got, err)
	}
	hidden, err := m.GetProjectFile(ctx, home.ID, "key.json")
	if err != nil || hidden.Plain != "" || hidden.SHA256 != nil || hidden.Size != len(secret+"-next") {
		t.Fatalf("secret get %#v %v", hidden, err)
	}
	mats, err := m.ListFileMaterial(ctx, home.ID)
	if err != nil || len(mats) != 2 {
		t.Fatalf("material %d %v", len(mats), err)
	}
	var sealed store.FileMaterial
	for _, mat := range mats {
		if mat.Name == "key.json" {
			sealed = mat
		}
		if strings.Contains(mat.Plain, "SECRET") || bytes.Contains(mat.Ciphertext, []byte("SECRET")) {
			t.Fatal("material held the secret in the clear")
		}
	}
	opened, err := box.Open(seal.FileAAD(home.ID.String(), "key.json"), sealed.Nonce, sealed.Ciphertext)
	if err != nil || string(opened) != secret+"-next" {
		t.Fatalf("open %q %v", opened, err)
	}
	if _, err := box.Open(seal.EnvAAD(home.ID.String(), "services", "key.json"), sealed.Nonce, sealed.Ciphertext); err == nil {
		t.Fatal("wrong AAD opened")
	}
	flipped := append([]byte(nil), sealed.Ciphertext...)
	flipped[len(flipped)-1] ^= 0xff
	if _, err := box.Open(seal.FileAAD(home.ID.String(), "key.json"), sealed.Nonce, flipped); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := m.GetProjectFile(ctx, home.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing %v", err)
	}
	if _, err := m.PutProjectFile(ctx, home.ID, "Bad", plain, owner.ID, at); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad name %v", err)
	}

	for i := 0; i < store.MaxProjectFiles-2; i++ {
		name := "f" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		if _, err := m.PutProjectFile(ctx, home.ID, name, plainFile("x"), owner.ID, at); err != nil {
			t.Fatalf("put %s %v", name, err)
		}
	}
	if _, err := m.PutProjectFile(ctx, home.ID, "extra", plainFile("x"), owner.ID, at); !errors.Is(err, store.ErrTooManyFiles) {
		t.Fatalf("65th %v", err)
	}
	if _, err := m.PutProjectFile(ctx, home.ID, "app.conf", plainFile("replaced"), owner.ID, at); err != nil {
		t.Fatalf("replace at the limit %v", err)
	}
	if n := m.fileCountLocked(home.ID); n != store.MaxProjectFiles {
		t.Fatalf("count %d", n)
	}

	spec := `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`
	img, err := catalog.BuildImage("web", []byte(spec), nil, map[string]struct{}{"app.conf": {}})
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, nil)
	write := store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	}
	if _, err := m.CreateCatalogEntry(ctx, home.ID, write); err != nil {
		t.Fatal(err)
	}
	write.Name = "api"
	if _, err := m.CreateCatalogEntry(ctx, home.ID, write); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "job", Kind: "program", CommandDisplay: "pnpm", Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	err = m.DeleteProjectFile(ctx, home.ID, "app.conf")
	var used *store.FileInUse
	if !errors.As(err, &used) || strings.Join(used.Entries, ",") != "api,web" || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("conflict %v", err)
	}
	if _, err := m.DeleteCatalogEntry(ctx, home.ID, "api"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeleteCatalogEntry(ctx, home.ID, "web"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteProjectFile(ctx, home.ID, "app.conf"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteProjectFile(ctx, home.ID, "app.conf"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete %v", err)
	}
	if _, err := m.DeleteProject(ctx, home.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ListProjectFiles(ctx, home.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted project %v", err)
	}
	for key := range m.projectFiles {
		if strings.HasPrefix(key, home.ID.String()+"/") {
			t.Fatalf("file row survived delete %s", key)
		}
	}
	left, err := m.ListProjectFiles(ctx, other.ID)
	if err != nil || len(left) != 1 || left[0].Name != "app.conf" {
		t.Fatalf("other project %#v %v", left, err)
	}
}

func sealFile(t *testing.T, box *seal.Box, projectID, name, plain string) store.FileWrite {
	t.Helper()
	nonce, ciphertext, err := box.Seal(seal.FileAAD(projectID, name), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(plain))
	return store.FileWrite{
		IsSecret: true, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion,
		SHA256: hex.EncodeToString(sum[:]), Size: len(plain),
	}
}

func plainFile(plain string) store.FileWrite {
	sum := sha256.Sum256([]byte(plain))
	return store.FileWrite{Plain: plain, SHA256: hex.EncodeToString(sum[:]), Size: len(plain)}
}
