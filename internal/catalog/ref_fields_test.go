package catalog

import (
	"strings"
	"testing"
)

func TestParseImageRefFields(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		in                      string
		host, path, tag, digest string
		tagGiven                bool
	}{
		{"nginx", "docker.io", "library/nginx", "latest", "", false},
		{"nginx:latest", "docker.io", "library/nginx", "latest", "", true},
		{"ghcr.io/joe/app:v1.4.2", "ghcr.io", "joe/app", "v1.4.2", "", true},
		{"localhost:5000/team/app", "localhost:5000", "team/app", "latest", "", false},
		{"ghcr.io/joe/app@" + d, "ghcr.io", "joe/app", "", d, false},
		{"ghcr.io/joe/app:v1@" + d, "ghcr.io", "joe/app", "v1", d, true},
	}
	for _, tc := range cases {
		got, err := ParseImageRef(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got.Host != tc.host || got.Path != tc.path || got.Tag != tc.tag || got.Digest != tc.digest || got.TagGiven != tc.tagGiven {
			t.Fatalf("%q: %+v", tc.in, got)
		}
	}
	if !ValidTag(strings.Repeat("a", 128)) || ValidTag(strings.Repeat("a", 129)) || ValidTag("-x") {
		t.Fatal("ValidTag bounds")
	}
}
