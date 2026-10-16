package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type fileRec struct {
	ProjectID  uuid.UUID
	Name       string
	IsSecret   bool
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
	SHA256     string
	Size       int
	UpdatedAt  time.Time
	UpdatedBy  uuid.UUID
}

func (m *Mem) ListProjectFiles(_ context.Context, projectID uuid.UUID) ([]store.ProjectFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return nil, store.ErrNotFound
	}
	out := []store.ProjectFile{}
	for _, rec := range m.projectFiles {
		if !fileOf(projectID, rec) {
			continue
		}
		out = append(out, fileMeta(rec, false))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Mem) GetProjectFile(_ context.Context, projectID uuid.UUID, name string) (store.ProjectFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.ProjectFile{}, store.ErrNotFound
	}
	rec, ok := m.projectFiles[envKey(projectID, name)]
	if !ok {
		return store.ProjectFile{}, store.ErrNotFound
	}
	return fileMeta(rec, true), nil
}

func (m *Mem) PutProjectFile(_ context.Context, projectID uuid.UUID, name string, in store.FileWrite, actor uuid.UUID, at time.Time) (store.ProjectFile, error) {
	if !fileWriteOK(name, in) {
		return store.ProjectFile{}, store.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.ProjectFile{}, store.ErrNotFound
	}
	key := envKey(projectID, name)
	if _, exists := m.projectFiles[key]; !exists && m.fileCountLocked(projectID) >= store.MaxProjectFiles {
		return store.ProjectFile{}, store.ErrTooManyFiles
	}
	rec := fileRec{
		ProjectID: projectID, Name: name, IsSecret: in.IsSecret, Plain: in.Plain,
		Nonce: cloneBytes(in.Nonce), Ciphertext: cloneBytes(in.Ciphertext),
		KeyVersion: in.KeyVersion, SHA256: in.SHA256, Size: in.Size,
		UpdatedAt: at, UpdatedBy: actor,
	}
	if rec.IsSecret {
		rec.Plain = ""
	}
	m.projectFiles[key] = rec
	return fileMeta(rec, false), nil
}

func (m *Mem) DeleteProjectFile(_ context.Context, projectID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.ErrNotFound
	}
	key := envKey(projectID, name)
	if _, ok := m.projectFiles[key]; !ok {
		return store.ErrNotFound
	}
	if used := m.fileUsersLocked(projectID, name); len(used) > 0 {
		return &store.FileInUse{Entries: used}
	}
	delete(m.projectFiles, key)
	return nil
}

func (m *Mem) ListFileMaterial(_ context.Context, projectID uuid.UUID) ([]store.FileMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return nil, store.ErrNotFound
	}
	out := []store.FileMaterial{}
	for _, rec := range m.projectFiles {
		if !fileOf(projectID, rec) {
			continue
		}
		out = append(out, store.FileMaterial{
			Name: rec.Name, IsSecret: rec.IsSecret, Plain: rec.Plain,
			Nonce: cloneBytes(rec.Nonce), Ciphertext: cloneBytes(rec.Ciphertext),
			KeyVersion: rec.KeyVersion, SHA256: rec.SHA256, Size: rec.Size,
			UpdatedAt: rec.UpdatedAt, UpdatedBy: rec.UpdatedBy,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fileOf(projectID uuid.UUID, rec fileRec) bool {
	return rec.ProjectID == projectID
}

func (m *Mem) fileCountLocked(projectID uuid.UUID) int {
	n := 0
	prefix := projectID.String() + "/"
	for key := range m.projectFiles {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}

func (m *Mem) fileUsersLocked(projectID uuid.UUID, name string) []string {
	var used []string
	for _, entry := range m.entries {
		if entry.ProjectID != projectID || entry.Kind != "image" {
			continue
		}
		img, err := catalog.ParseStored(entry.ImageRaw)
		if err != nil {
			continue
		}
		for _, file := range img.Files {
			if file.File == name {
				used = append(used, entry.Name)
				break
			}
		}
	}
	sort.Strings(used)
	return used
}

func fileMeta(rec fileRec, withPlain bool) store.ProjectFile {
	item := store.ProjectFile{
		Name: rec.Name, IsSecret: rec.IsSecret, Size: rec.Size,
		UpdatedAt: rec.UpdatedAt, UpdatedBy: rec.UpdatedBy,
	}
	if !rec.IsSecret {
		sum := rec.SHA256
		item.SHA256 = &sum
		if withPlain {
			item.Plain = rec.Plain
		}
	}
	return item
}

func fileWriteOK(name string, in store.FileWrite) bool {
	if !catalog.ValidFileName(name) || !shaHex(in.SHA256) {
		return false
	}
	if in.Size < 1 || in.Size > catalog.MaxFileBytes {
		return false
	}
	if in.IsSecret {
		return in.Plain == "" && len(in.Nonce) == 12 && len(in.Ciphertext) == in.Size+16 && in.KeyVersion >= 1
	}
	return catalog.ValidFileContent(in.Plain) && len(in.Plain) == in.Size && len(in.Nonce) == 0 && len(in.Ciphertext) == 0 && in.KeyVersion == 0
}

func shaHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
