package api

import (
	"net/http"
	"testing"
)

// TestRoleEnforcementHTTP checks every mutating project route on the real mux.
// Design §2 lets a viewer run snapshot and probe. Those two are 200.
// Every other mutation is 403 for a viewer. Admin follows §2.
// A non-member is 404. Each cell uses a fresh project because success mutates.
func TestRoleEnforcementHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	outsider := w.user("out@ex.com", "Out")
	tok := map[string]string{
		"owner":    w.token(owner.ID),
		"admin":    w.token(admin.ID),
		"viewer":   w.token(viewer.ID),
		"outsider": w.token(outsider.ID),
	}

	type route struct {
		name                 string
		method               string
		path                 func(scene) string
		body                 func(scene) string
		owner, admin, viewer int
		live                 bool
	}
	health := `{"checks":[{"protocol":"http","port":8080,"path":"/"}]}`
	probe := `{"protocol":"http","port":8080,"path":"/"}`
	routes := []route{
		{"rename", http.MethodPatch, func(s scene) string { return "/v1/projects/" + s.project.ID.String() },
			func(scene) string { return `{"name":"Renamed"}` }, 200, 403, 403, false},
		{"delete project", http.MethodDelete, func(s scene) string { return "/v1/projects/" + s.project.ID.String() },
			func(scene) string { return "" }, 200, 403, 403, false},
		{"add member", http.MethodPost, func(s scene) string { return "/v1/projects/" + s.project.ID.String() + "/members" },
			func(s scene) string { return `{"email":"` + s.extra.Email + `","role":"viewer"}` }, 201, 201, 403, false},
		{"change role", http.MethodPatch, func(s scene) string {
			return "/v1/projects/" + s.project.ID.String() + "/members/" + s.spare.ID.String()
		}, func(scene) string { return `{"role":"admin"}` }, 200, 200, 403, false},
		{"remove member", http.MethodDelete, func(s scene) string {
			return "/v1/projects/" + s.project.ID.String() + "/members/" + s.spare.ID.String()
		}, func(scene) string { return "" }, 200, 200, 403, false},
		{"transfer", http.MethodPost, func(s scene) string { return "/v1/projects/" + s.project.ID.String() + "/transfer-ownership" },
			func(s scene) string { return `{"user_id":"` + admin.ID.String() + `"}` }, 200, 403, 403, false},
		{"create join token", http.MethodPost, func(s scene) string { return "/v1/projects/" + s.project.ID.String() + "/join-tokens" },
			func(scene) string { return `{}` }, 201, 201, 403, false},
		{"revoke join token", http.MethodDelete, func(s scene) string {
			return "/v1/projects/" + s.project.ID.String() + "/join-tokens/" + s.join.ID.String()
		}, func(scene) string { return "" }, 200, 200, 403, false},
		{"revoke host", http.MethodDelete, func(s scene) string { return "/v1/hosts/" + s.host.ID.String() + "/credential" },
			func(scene) string { return "" }, 200, 200, 403, false},
		{"replace health checks", http.MethodPut, func(s scene) string { return "/v1/services/" + s.svc.ID.String() + "/health-checks" },
			func(scene) string { return health }, 200, 200, 403, false},
		{"snapshot", http.MethodPost, func(s scene) string { return "/v1/hosts/" + s.host.ID.String() + "/snapshot" },
			func(scene) string { return "" }, 200, 200, 200, true},
		{"probe", http.MethodPost, func(s scene) string { return "/v1/services/" + s.svc.ID.String() + "/probe" },
			func(scene) string { return probe }, 200, 200, 200, true},
	}
	actors := []struct {
		name string
		want func(route) int
	}{
		{"owner", func(r route) int { return r.owner }},
		{"admin", func(r route) int { return r.admin }},
		{"viewer", func(r route) int { return r.viewer }},
		{"outsider", func(route) int { return http.StatusNotFound }},
	}
	for _, rt := range routes {
		for _, act := range actors {
			sc := w.scene(owner, admin, viewer, spare, extra)
			want := act.want(rt)
			if rt.live && want == http.StatusOK {
				answerTasks(w.hello(sc))
			}
			code, env := w.do(tok[act.name], rt.method, rt.path(sc), rt.body(sc))
			if code != want {
				t.Fatalf("%s/%s: status %d %s, want %d", rt.name, act.name, code, env.Code, want)
			}
			switch want {
			case http.StatusOK, http.StatusCreated:
				if env.Code != "ok" {
					t.Fatalf("%s/%s: code %s", rt.name, act.name, env.Code)
				}
			case http.StatusForbidden:
				if env.Code != "forbidden" {
					t.Fatalf("%s/%s: code %s", rt.name, act.name, env.Code)
				}
			case http.StatusNotFound:
				if env.Code != "not_found" {
					t.Fatalf("%s/%s: code %s", rt.name, act.name, env.Code)
				}
			default:
				t.Fatalf("%s/%s: unhandled want %d", rt.name, act.name, want)
			}
		}
	}
}
