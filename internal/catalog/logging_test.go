package catalog

import (
	"errors"
	"strings"
	"testing"
)

func TestLoggingRules(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want string
	}{
		{"low size", `{"kind":"service","image":"nginx","logging":{"max_size_mb":0,"max_files":1}}`, "invalid logging.max_size_mb"},
		{"high size", `{"kind":"service","image":"nginx","logging":{"max_size_mb":101,"max_files":1}}`, "invalid logging.max_size_mb"},
		{"low files", `{"kind":"service","image":"nginx","logging":{"max_size_mb":1,"max_files":0}}`, "invalid logging.max_files"},
		{"high files", `{"kind":"job","image":"nginx","logging":{"max_size_mb":1,"max_files":11}}`, "invalid logging.max_files"},
		{"float size", `{"kind":"service","image":"nginx","logging":{"max_size_mb":10.0,"max_files":3}}`, "invalid logging.max_size_mb"},
		{"string size", `{"kind":"service","image":"nginx","logging":{"max_size_mb":"10","max_files":3}}`, "invalid logging.max_size_mb"},
		{"bool files", `{"kind":"service","image":"nginx","logging":{"max_size_mb":10,"max_files":true}}`, "invalid logging.max_files"},
		{"null size", `{"kind":"service","image":"nginx","logging":{"max_size_mb":null,"max_files":3}}`, "invalid logging.max_size_mb"},
		{"missing size", `{"kind":"service","image":"nginx","logging":{"max_files":3}}`, "invalid logging.max_size_mb"},
		{"missing files", `{"kind":"job","image":"nginx","logging":{"max_size_mb":10}}`, "invalid logging.max_files"},
		{"empty object", `{"kind":"service","image":"nginx","logging":{}}`, "invalid logging.max_size_mb"},
		{"unknown", `{"kind":"service","image":"nginx","logging":{"max_size_mb":10,"max_files":3,"driver":"json-file"}}`, "invalid logging"},
		{"unknown only", `{"kind":"job","image":"nginx","logging":{"driver":"json-file"}}`, "invalid logging"},
		{"not object", `{"kind":"service","image":"nginx","logging":"10m"}`, "invalid logging"},
		{"array", `{"kind":"service","image":"nginx","logging":[10,3]}`, "invalid logging"},
	}
	for _, tc := range cases {
		_, err := BuildImage("web", []byte(tc.spec), nil, nil)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Msg != tc.want || strings.Contains(err.Error(), "nginx") || strings.Contains(err.Error(), "json-file") {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}

	for _, kind := range []string{"service", "job"} {
		ok, err := BuildImage("web", []byte(`{"kind":"`+kind+`","image":"nginx","logging":{"max_size_mb":1,"max_files":1}}`), nil, nil)
		if err != nil || ok.Logging == nil || ok.Logging.MaxSizeMB != 1 || ok.Logging.MaxFiles != 1 {
			t.Fatalf("%s low bound %+v %v", kind, ok.Logging, err)
		}
		top, err := BuildImage("web", []byte(`{"kind":"`+kind+`","image":"nginx","logging":{"max_files":10,"max_size_mb":100}}`), nil, nil)
		if err != nil || top.Logging == nil || top.Logging.MaxSizeMB != 100 || top.Logging.MaxFiles != 10 {
			t.Fatalf("%s high bound %+v %v", kind, top.Logging, err)
		}
		nulled, err := BuildImage("web", []byte(`{"kind":"`+kind+`","image":"nginx","logging":null}`), nil, nil)
		if err != nil || nulled.Logging != nil || strings.Contains(SpecJSON(nulled), "logging") {
			t.Fatalf("%s null %+v %v", kind, nulled.Logging, err)
		}
		bare, err := BuildImage("web", []byte(`{"kind":"`+kind+`","image":"nginx"}`), nil, nil)
		if err != nil || bare.Logging != nil {
			t.Fatalf("%s absent %+v %v", kind, bare.Logging, err)
		}
	}
}

func TestLoggingHash(t *testing.T) {
	bare, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "578b58b80ed177e86358709c3a24c704c76e0f70c90fe3ae9fd47ffc025a7e30"
	if ImageHash(bare, nil) != pinned || strings.Contains(SpecJSON(bare), "logging") || strings.Contains(CanonicalImage(bare, nil), "logging") {
		t.Fatalf("absent logging changed the hash %s", ImageHash(bare, nil))
	}
	img, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","logging":{"max_size_mb":10,"max_files":3}}`), nil, nil)
	if err != nil || img.Logging == nil {
		t.Fatal(err)
	}
	want := `"logging":{"max_files":3,"max_size_mb":10}`
	stored := SpecJSON(img)
	if !strings.Contains(stored, want) || !strings.Contains(CanonicalImage(img, nil), want) {
		t.Fatalf("stored %s", stored)
	}
	kindAt := strings.Index(stored, `"kind"`)
	logAt := strings.Index(stored, `"logging"`)
	memAt := strings.Index(stored, `"memory_mb"`)
	if kindAt < 0 || logAt < kindAt || memAt < logAt {
		t.Fatalf("key order %s", stored)
	}
	if ImageHash(img, nil) == pinned {
		t.Fatal("logging did not change spec_hash")
	}
	again, err := ParseStored([]byte(stored))
	if err != nil || again.Logging == nil || SpecJSON(again) != stored {
		t.Fatalf("round trip %v %s", err, SpecJSON(again))
	}
	changed, err := BuildImage("web", []byte(`{"kind":"service","image":"nginx","logging":{"max_size_mb":10,"max_files":2}}`), nil, nil)
	if err != nil || ImageHash(changed, nil) == ImageHash(img, nil) {
		t.Fatal("max_files did not change spec_hash")
	}
	job, err := BuildImage("batch", []byte(`{"kind":"job","image":"nginx","logging":{"max_size_mb":5,"max_files":2}}`), nil, nil)
	if err != nil || job.Logging == nil || job.Logging.MaxSizeMB != 5 || job.Logging.MaxFiles != 2 {
		t.Fatalf("job %+v %v", job.Logging, err)
	}
	jobBare, err := BuildImage("batch", []byte(`{"kind":"job","image":"nginx"}`), nil, nil)
	if err != nil || ImageHash(job, nil) == ImageHash(jobBare, nil) {
		t.Fatal("job logging did not change spec_hash")
	}
}
