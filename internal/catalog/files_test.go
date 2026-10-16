package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestFileNameAndContent(t *testing.T) {
	okName := []string{"a", "1", "a.conf", "key.json", "a.b_c-d", strings.Repeat("a", 64)}
	for _, name := range okName {
		if !ValidFileName(name) {
			t.Fatalf("rejected %q", name)
		}
	}
	badName := []string{"", ".", "..", "A", "a/b", "-a", ".env", "a b", "a\n", "a\x00b", strings.Repeat("a", 65)}
	for _, name := range badName {
		if ValidFileName(name) {
			t.Fatalf("accepted %q", name)
		}
	}
	if !ValidFileContent("a") || !ValidFileContent("héllo") || !ValidFileContent(strings.Repeat("a", MaxFileBytes)) {
		t.Fatal("rejected a legal body")
	}
	badBody := []string{"", strings.Repeat("a", MaxFileBytes+1), "a\x00b", string([]byte{0xff}), string([]byte{'a', 0xff})}
	for _, body := range badBody {
		if ValidFileContent(body) {
			t.Fatalf("accepted body len %d", len(body))
		}
	}
}

func TestEmptyFilesHashMatchesWave2a(t *testing.T) {
	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const canonical = `{"env_keys":{},"kind":"image","spec":{"command":null,"entrypoint":null,"env":{},"env_sets":[],"healthy_after_sec":30,"image":"docker.io/library/nginx:latest","kind":"service","memory_mb":null,"ports":[],"restart":"unless-stopped","secret_env":{},"timeout_sec":0,"user":"","volumes":[]}}`
	sum := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(sum[:])
	if want != "578b58b80ed177e86358709c3a24c704c76e0f70c90fe3ae9fd47ffc025a7e30" {
		t.Fatalf("pinned 2a hash %s", want)
	}
	if CanonicalImage(img, nil) != canonical || ImageHash(img, nil) != want {
		t.Fatalf("hash %s canonical %s", ImageHash(img, nil), CanonicalImage(img, nil))
	}
	if !strings.Contains(SpecJSON(img), `"files":[]`) || strings.Contains(canonical, `"files"`) {
		t.Fatal("stored spec and hash input disagree on an empty files list")
	}
	known := map[string]struct{}{"app.conf": {}}
	with, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`), nil, known)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(CanonicalImage(with, nil), `"files":[{"file":"app.conf","target":"/config/app.conf"}]`) {
		t.Fatal("hash dropped a files row")
	}
	if ImageHash(with, nil) == want {
		t.Fatal("a files row kept the 2a hash")
	}
}

func TestImageFileRules(t *testing.T) {
	known := map[string]struct{}{"app.conf": {}, "key.json": {}, "b.conf": {}}
	build := func(spec string) (Image, error) {
		return BuildImage("web", []byte(spec), nil, known)
	}
	base := `{"kind":"service","image":"nginx"}`
	img, err := build(base)
	if err != nil || img.Files == nil || len(img.Files) != 0 || !strings.Contains(SpecJSON(img), `"files":[]`) {
		t.Fatalf("default files %+v %v", img.Files, err)
	}
	again, err := ParseStored([]byte(SpecJSON(img)))
	if err != nil || len(again.Files) != 0 {
		t.Fatalf("round trip %+v %v", again, err)
	}
	old, err := ParseStored([]byte(`{"kind":"service","image":"nginx"}`))
	if err != nil || old.Files == nil || len(old.Files) != 0 || !strings.Contains(SpecJSON(old), `"files":[]`) {
		t.Fatalf("missing files %+v %v", old.Files, err)
	}
	nullFiles, err := build(`{"kind":"service","image":"nginx","files":null}`)
	if err != nil || len(nullFiles.Files) != 0 {
		t.Fatalf("null files %+v %v", nullFiles.Files, err)
	}

	long := "/" + strings.Repeat("a", 254)
	ok, err := build(`{"kind":"service","image":"nginx","files":[{"file":"b.conf","target":"/data/b.conf"},{"file":"app.conf","target":"` + long + `"},{"file":"key.json","target":"/data/b.conf/extra"}]}`)
	if err != nil || len(ok.Files) != 3 || ok.Files[0].File != "b.conf" || ok.Files[0].Target != "/data/b.conf" || ok.Files[1].Target != long || ok.Files[2].File != "key.json" || ok.Files[2].Target != "/data/b.conf/extra" {
		t.Fatalf("accepted %+v %v", ok.Files, err)
	}
	if ImageHash(img, nil) == ImageHash(ok, nil) {
		t.Fatal("files rows did not change spec_hash")
	}
	same, err := build(`{"kind":"service","image":"nginx","files":[{"file":"b.conf","target":"/data/b.conf"},{"file":"app.conf","target":"` + long + `"},{"file":"key.json","target":"/data/b.conf/extra"}]}`)
	if err != nil || ImageHash(same, nil) != ImageHash(ok, nil) {
		t.Fatal("spec_hash moved without a row change")
	}
	under, err := build(`{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data"}],"files":[{"file":"app.conf","target":"/database"}]}`)
	if err != nil || len(under.Files) != 1 {
		t.Fatalf("/database beside /data %+v %v", under.Files, err)
	}
	for _, spec := range []string{
		`{"kind":"service","image":"nginx","volumes":[{"name":"root","target":"/"}]}`,
		`{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data/"}]}`,
		`{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data//key.json"}]}`,
		`{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data/"}],"files":[{"file":"app.conf","target":"/other/app.conf"}]}`,
	} {
		if _, err := build(spec); err != nil {
			t.Fatalf("volume rule 8 still saves %s: %v", spec, err)
		}
	}
	for _, target := range []string{"/procfoo", "/processing", "/device", "/syscall"} {
		got, err := build(`{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"` + target + `"}]}`)
		if err != nil || len(got.Files) != 1 || got.Files[0].Target != target {
			t.Fatalf("%s %+v %v", target, got.Files, err)
		}
	}

	rows17, names17 := fileRows(17)
	for _, name := range names17 {
		known[name] = struct{}{}
	}
	rows16, _ := fileRows(16)
	if _, err := build(`{"kind":"service","image":"nginx","files":` + rows16 + `}`); err != nil {
		t.Fatalf("16 unique names: %v", err)
	}
	refusals := []struct{ name, spec string }{
		{"count", `{"kind":"service","image":"nginx","files":` + rows17 + `}`},
		{"name", `{"kind":"service","image":"nginx","files":[{"file":"Bad","target":"/config/a"}]}`},
		{"dot", `{"kind":"service","image":"nginx","files":[{"file":".","target":"/config/a"}]}`},
		{"relative", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"config/a"}]}`},
		{"root", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/"}]}`},
		{"trail", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/"}]}`},
		{"empty seg", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config//a"}]}`},
		{"dot seg", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/./a"}]}`},
		{"dotdot", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/../a"}]}`},
		{"nul", "{\"kind\":\"service\",\"image\":\"nginx\",\"files\":[{\"file\":\"app.conf\",\"target\":\"/a\\u0000b\"}]}"},
		{"nl", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/a\nb"}]}`},
		{"long", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/` + strings.Repeat("a", 255) + `"}]}`},
		{"proc", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/proc"}]}`},
		{"proc under", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/proc/self"}]}`},
		{"sys", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/sys"}]}`},
		{"sys under", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/sys/fs"}]}`},
		{"dev", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/dev"}]}`},
		{"dev under", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/dev/null"}]}`},
		{"dup target", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/a"},{"file":"b.conf","target":"/config/a"}]}`},
		{"dup name", `{"kind":"service","image":"nginx","files":[{"file":"b.conf","target":"/data/b.conf"},{"file":"b.conf","target":"/other/b.conf"}]}`},
		{"vol exact", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data"}],"files":[{"file":"app.conf","target":"/data"}]}`},
		{"file under vol", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data"}],"files":[{"file":"app.conf","target":"/data/a"}]}`},
		{"vol under file", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data/a"}],"files":[{"file":"app.conf","target":"/data"}]}`},
		{"vol trail", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data/"}],"files":[{"file":"key.json","target":"/data/key.json"}]}`},
		{"vol root", `{"kind":"service","image":"nginx","volumes":[{"name":"root","target":"/"}],"files":[{"file":"app.conf","target":"/config/a"}]}`},
		{"vol empty seg", `{"kind":"service","image":"nginx","volumes":[{"name":"data","target":"/data//key.json"}],"files":[{"file":"key.json","target":"/data/key.json"}]}`},
		{"extra", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/a","mode":"rw"}]}`},
	}
	for _, tc := range refusals {
		_, err := build(tc.spec)
		if err == nil || err.Error() != "invalid files" {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if strings.Contains(err.Error(), "app.conf") || strings.Contains(err.Error(), "b.conf") || strings.Contains(err.Error(), "/data") || strings.Contains(err.Error(), "Bad") || strings.Contains(err.Error(), "/proc") {
			t.Fatalf("%s echoes a value: %v", tc.name, err)
		}
	}
	_, err = BuildImage("web", []byte(`{"kind":"service","image":"nginx","files":[{"file":"missing.conf","target":"/config/a"}]}`), nil, known)
	if err == nil || err.Error() != "unknown file" || strings.Contains(err.Error(), "missing.conf") {
		t.Fatalf("unknown file %v", err)
	}
	_, err = BuildImage("web", []byte(`{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/a"}]}`), nil, nil)
	if err == nil || err.Error() != "unknown file" {
		t.Fatalf("nil set %v", err)
	}
}

// fileRows builds n rows with distinct names and targets. The count refusal
// must not also trip the duplicate-name rule.
func fileRows(n int) (string, []string) {
	names := make([]string, n)
	parts := make([]string, n)
	for i := range parts {
		names[i] = fmt.Sprintf("f%02d.conf", i)
		parts[i] = `{"file":"` + names[i] + `","target":"/data/` + names[i] + `"}`
	}
	return "[" + strings.Join(parts, ",") + "]", names
}
