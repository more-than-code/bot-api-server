package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/internal/db"
)

func TestReadTimeoutIsSet(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "ReadTimeout:") || !strings.Contains(text, "30 * time.Second") {
		t.Fatal("REST ReadTimeout of 30s is missing")
	}
}

func TestRunMigrateIsOptIn(t *testing.T) {
	var opened, migrated, served bool
	d := deps{
		open: func(context.Context, string) (*db.DB, error) {
			opened = true
			return nil, errors.New("database connection failed")
		},
		migrate: func(context.Context, string) error {
			migrated = true
			return nil
		},
		serve: func(string, http.Handler, func()) error {
			served = true
			return nil
		},
	}
	getenv := func(k string) string {
		switch k {
		case "BOT_API_LISTEN":
			return "127.0.0.1:0"
		case "DATABASE_URL":
			return "postgres://example.invalid/deploybot"
		case "BOT_API_GOOGLE_CLIENT_ID":
			return "dummy-google-client-id"
		case "BOT_API_GOOGLE_CLIENT_SECRET":
			return "dummy-google-client-secret"
		case "BOT_API_DEVICE_VERIFICATION_URI":
			return "http://127.0.0.1/device"
		case "BOT_API_AGENT_WS_URL":
			return "ws://127.0.0.1/agent/v1/ws"
		case "BOT_API_OAUTH_REDIRECT_URIS":
			return "http://127.0.0.1/callback"
		default:
			return ""
		}
	}
	if err := run(nil, getenv, d); err == nil {
		t.Fatal("expected open to fail")
	}
	if !opened || migrated || served {
		t.Fatalf("opened=%v migrated=%v served=%v", opened, migrated, served)
	}

	opened, migrated, served = false, false, false
	err := run([]string{"--migrate"}, func(k string) string {
		if k == "BOT_API_MIGRATE_DATABASE_URL" {
			return "postgres://example.invalid/deploybot"
		}
		return ""
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	if opened || !migrated || served {
		t.Fatalf("opened=%v migrated=%v served=%v", opened, migrated, served)
	}
}

func walkGo(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "vendor") {
			return filepath.SkipDir
		}
		// Test files quote SQL phrases when they assert on migration text.
		// They are not a server path that runs DDL.
		if !info.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func containsAny(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestNoDDLInGo(t *testing.T) {
	// The phrases are split so this file does not contain them.
	needles := []string{"CREATE " + "TABLE", "create_" + "hypertable"}
	root := "../.."
	entries, err := walkGo(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range entries {
		if containsAny(path, "migrations/") {
			continue
		}
		body := readFile(t, path)
		for _, n := range needles {
			if containsAny(body, n) {
				t.Errorf("%s contains %s", path, n)
			}
		}
	}
}
