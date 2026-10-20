package catalog

import (
	"testing"
	"unicode/utf8"
)

// secretPreviewCases is the v1.13 preview table. Copy this slice.
// Fifteen runes (and fewer) are four bullets. Sixteen runes are the first
// four runes plus U+2026. Bullets are U+2022.
var secretPreviewCases = []struct {
	in, want string
}{
	{"", "••••"},
	{"abcd", "••••"},
	{"123456789012345", "••••"},
	{"1234567890123456", "1234…"},
	{"sekret-env-VALUE-9f3a", "sekr…"},
	{"s3cret-value-1", "••••"},
	{"ééééééééééééééé", "••••"},
	{"éééééééééééééééé", "éééé…"},
	{"😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊", "••••"},
	{"😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊", "😊😊😊😊…"},
}

func TestSecretPreview(t *testing.T) {
	if utf8.RuneCountInString("123456789012345") != 15 || utf8.RuneCountInString("1234567890123456") != 16 {
		t.Fatal("ascii bounds")
	}
	if utf8.RuneCountInString("ééééééééééééééé") != 15 || utf8.RuneCountInString("éééééééééééééééé") != 16 {
		t.Fatal("multibyte bounds")
	}
	if utf8.RuneCountInString("😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊") != 15 || utf8.RuneCountInString("😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊😊") != 16 {
		t.Fatal("emoji bounds")
	}
	if secretPreviewCases[0].want != "\u2022\u2022\u2022\u2022" || secretPreviewCases[3].want != "1234\u2026" {
		t.Fatal("preview markers are not U+2022 and U+2026")
	}
	for _, tc := range secretPreviewCases {
		if got := SecretPreview(tc.in); got != tc.want {
			t.Errorf("SecretPreview(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
