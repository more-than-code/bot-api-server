package catalog

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	const secret = "SENTINELVALUE"
	got, err := ParseDotenv([]byte("\n# comment\nexport FOO=bar\nBAZ='" + secret + "'\nQUOTED=\"a b\"\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Key != "FOO" || got[0].Value != "bar" || got[1].Value != secret || got[2].Value != "a b" {
		t.Fatalf("%#v", got)
	}
	if _, err := ParseDotenv(nil); err != nil {
		t.Fatal(err)
	}
	refusals := []struct{ body, want, absent string }{
		{"FOO=bar\nFOO=baz\n", "line 2: FOO duplicate", "baz"},
		{"FOO=bar\\\n", "line 1: FOO invalid env value", ""},
		{"FOO=\"a\\nb\"\n", "line 1: FOO invalid env value", "nb"},
		{"FOO=$HOME\n", "line 1: FOO invalid env value", "HOME"},
		{"FOO=\"unterminated\n", "line 1: FOO malformed", "unterminated"},
		{"NOT KEY=1\n", "line 1: malformed", "NOT"},
		{"PATH=/tmp/" + secret + "\n", "line 1: PATH is reserved", secret},
		{"NODE_OPTIONS=--x\n", "line 1: NODE_OPTIONS this variable changes what the program runs", "--x"},
		{"FOO=a\x00b\n", "line 1: malformed", "ab"},
		{"DB_PASSWORD=" + secret + "\nDB_PASSWORD=x\n", "line 2: DB_PASSWORD duplicate", secret},
	}
	for _, tc := range refusals {
		_, err := ParseDotenv([]byte(tc.body))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%q: %v", tc.body, err)
		}
		if tc.absent != "" && strings.Contains(err.Error(), tc.absent) {
			t.Fatalf("error echoes a value: %v", err)
		}
	}
	ok, err := ParseDotenv([]byte("DB_PASSWORD=" + secret + "\n"))
	if err != nil || ok[0].Key != "DB_PASSWORD" || ok[0].Value != secret {
		t.Fatalf("secret key refused: %+v %v", ok, err)
	}
	plain, err := ParseDotenv([]byte("FOO=bar # still the value\n"))
	if err != nil || plain[0].Value != "bar # still the value" {
		t.Fatalf("inline comment %#v %v", plain, err)
	}
	big := "A=" + strings.Repeat("x", 4097) + "\n"
	if _, err := ParseDotenv([]byte(big)); err == nil || !strings.Contains(err.Error(), "line 1: A") || strings.Contains(err.Error(), "xxx") {
		t.Fatalf("long value %v", err)
	}
	if _, err := ParseDotenv([]byte{0xff, 0xfe}); err == nil || err.Error() != "invalid dotenv" {
		t.Fatalf("utf8 %v", err)
	}
	if _, err := ParseDotenv(make([]byte, 256*1024+1)); err == nil || err.Error() != "dotenv is too large" {
		t.Fatalf("size %v", err)
	}
	var many strings.Builder
	for i := 0; i < 257; i++ {
		fmt.Fprintf(&many, "K%03d=v\n", i)
	}
	if _, err := ParseDotenv([]byte(many.String())); err == nil || err.Error() != "too many env keys" {
		t.Fatalf("count %v", err)
	}
	var exact strings.Builder
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&exact, "K%03d=v\n", i)
	}
	if pairs, err := ParseDotenv([]byte(exact.String())); err != nil || len(pairs) != 256 {
		t.Fatalf("256 keys: %d %v", len(pairs), err)
	}
}
