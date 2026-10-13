package api

import (
	"context"
	"net/http"
	"testing"
)

func TestInstallCommandExact(t *testing.T) {
	const (
		token = "known-token-value"
		url   = "wss://api.example/agent/v1/ws"
		want  = "printf '%s' 'known-token-value' | sudo -u bot-agent bot-agent init --server 'wss://api.example/agent/v1/ws' --join-token-stdin"
	)
	if got := installCommand(url, token); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestJoinCreateInstallCommand(t *testing.T) {
	w := newWorld(t)
	const url = "wss://api.example/agent/v1/ws"
	w.srv.AgentWSURL = url
	owner := w.user("owner@ex.com", "Owner")
	project, err := w.mem.CreateProject(context.Background(), owner.ID, "Proj", "proj", w.now)
	if err != nil {
		t.Fatal(err)
	}
	code, env := w.do(w.token(owner.ID), http.MethodPost, "/v1/projects/"+project.ID.String()+"/join-tokens", `{}`)
	if code != http.StatusCreated {
		t.Fatalf("status %d %#v", code, env)
	}
	payload, ok := env.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload %T", env.Payload)
	}
	token, _ := payload["token"].(string)
	got, _ := payload["install_command"].(string)
	if token == "" || got != installCommand(url, token) {
		t.Fatalf("token %q command %q", token, got)
	}
	if got != "printf '%s' '"+token+"' | sudo -u bot-agent bot-agent init --server '"+url+"' --join-token-stdin" {
		t.Fatalf("command %q", got)
	}
}
