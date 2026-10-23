package config

import "testing"

func TestRegistryAllowPrivate(t *testing.T) {
	for val, want := range map[string]bool{"": false, "0": false, "true": false, "1": true, " 1 ": true} {
		env := map[string]string{"BOT_API_MIGRATE_DATABASE_URL": "postgres://x", "BOT_API_REGISTRY_ALLOW_PRIVATE": val}
		cfg, err := FromEnv(func(k string) string { return env[k] }, true)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RegistryAllowPrivate != want {
			t.Fatalf("%q: %v", val, cfg.RegistryAllowPrivate)
		}
	}
}
