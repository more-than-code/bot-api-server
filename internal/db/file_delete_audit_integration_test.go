package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/api"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// TestFileDeleteAudit is the Postgres twin of api.TestFileDeleteAudit.
// The handler writes the row; this checks the same detail survives InsertAudit.
func TestFileDeleteAudit(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Open(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	defer d.Close()
	var dbName string
	if err := d.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal("database name lookup failed")
	}
	if dbName != "deploybot_test" {
		t.Fatalf("refusing database %s", dbName)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const content = "exact-delete-audit-body-9f3a"
	sum := sha256.Sum256([]byte(content))
	contentHash := hex.EncodeToString(sum[:])
	at := time.Now().UTC().Truncate(time.Microsecond)
	owner := catalogUser(t, d, ctx, "filedelaudit", at)
	project := catalogProject(t, d, ctx, owner.ID, "File delete audit", "filedelaudit", at)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		_, _ = d.pool.Exec(cctx, `DELETE FROM app.audit_log WHERE project_id = $1::uuid`, project.ID.String())
		_, _ = d.DeleteProject(cctx, project.ID, time.Now().UTC())
	})
	if _, err := d.PutProjectFile(ctx, project.ID, "key.json", store.FileWrite{
		Plain: content, SHA256: contentHash, Size: len(content),
	}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`), nil, map[string]struct{}{"key.json": {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateCatalogEntry(ctx, project.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	plain, tokenHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateSession(ctx, owner.ID, tokenHash, store.KindConsole, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := func() time.Time { return at }
	h := (&api.Server{
		Store: d,
		Auth:  auth.New(d, config.Config{}, clock),
		Audit: audit.Writer{Store: d, Log: log, Now: clock},
		Log:   log,
		Now:   clock,
	}).Handler()
	base := "/v1/projects/" + project.ID.String() + "/files"

	status, body := deleteFile(t, h, plain, base+"/missing.conf")
	if status != http.StatusNotFound || !strings.Contains(body, `"not_found"`) {
		t.Fatalf("missing %d %s", status, body)
	}
	if deletes := fileDeleteAudits(t, d, ctx, project.ID); len(deletes) != 0 {
		t.Fatalf("missing name audited %#v", deletes)
	}

	status, body = deleteFile(t, h, plain, base+"/key.json")
	if status != http.StatusConflict || !strings.Contains(body, "referenced by web") || strings.Contains(body, content) || strings.Contains(body, contentHash) {
		t.Fatalf("conflict %d %s", status, body)
	}
	got, err := d.GetProjectFile(ctx, project.ID, "key.json")
	if err != nil || got.Plain != content {
		t.Fatalf("conflict removed the file %#v %v", got, err)
	}
	deletes := fileDeleteAudits(t, d, ctx, project.ID)
	if len(deletes) != 1 || !postgresFileDeleteDetail(deletes[0], "key.json", "conflict", content, contentHash) {
		t.Fatalf("conflict audit %#v", deletes)
	}

	if _, err := d.DeleteCatalogEntry(ctx, project.ID, "web"); err != nil {
		t.Fatal(err)
	}
	status, body = deleteFile(t, h, plain, base+"/key.json")
	if status != http.StatusOK || strings.Contains(body, content) || strings.Contains(body, contentHash) {
		t.Fatalf("delete %d %s", status, body)
	}
	if _, err := d.GetProjectFile(ctx, project.ID, "key.json"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete left the file %v", err)
	}
	deletes = fileDeleteAudits(t, d, ctx, project.ID)
	if len(deletes) != 2 || !postgresFileDeleteDetail(findPostgresFileDelete(deletes, "deleted"), "key.json", "deleted", content, contentHash) || !postgresFileDeleteDetail(findPostgresFileDelete(deletes, "conflict"), "key.json", "conflict", content, contentHash) {
		t.Fatalf("delete audit %#v", deletes)
	}
	status, body = deleteFile(t, h, plain, base+"/key.json")
	if status != http.StatusNotFound {
		t.Fatalf("second delete %d %s", status, body)
	}
	if again := fileDeleteAudits(t, d, ctx, project.ID); len(again) != 2 {
		t.Fatalf("missing name after delete audited %#v", again)
	}
}

func deleteFile(t *testing.T, h http.Handler, token, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func fileDeleteAudits(t *testing.T, d *DB, ctx context.Context, projectID uuid.UUID) []string {
	t.Helper()
	rows, _, err := d.ListAudit(ctx, projectID, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, row := range rows {
		if row.Action != audit.ActionFileDelete {
			continue
		}
		if row.Decision != audit.DecisionAllowed {
			t.Fatalf("file.delete decision %s", row.Decision)
		}
		out = append(out, string(row.Detail))
	}
	return out
}

func findPostgresFileDelete(details []string, outcome string) string {
	for _, detail := range details {
		var row map[string]any
		if json.Unmarshal([]byte(detail), &row) == nil && row["outcome"] == outcome {
			return detail
		}
	}
	return ""
}

func postgresFileDeleteDetail(detail, name, outcome, content, contentHash string) bool {
	var row map[string]any
	if json.Unmarshal([]byte(detail), &row) != nil || len(row) != 2 {
		return false
	}
	if row["name"] != name || row["outcome"] != outcome {
		return false
	}
	return !strings.Contains(detail, content) && !strings.Contains(detail, contentHash)
}
