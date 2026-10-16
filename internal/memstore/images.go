package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type envSetRec struct {
	Name      string
	UpdatedAt time.Time
	UpdatedBy uuid.UUID
}

type envValueRec struct {
	Key        string
	IsSecret   bool
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

type registryRec struct {
	Host       string
	Username   string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
	UpdatedAt  time.Time
	UpdatedBy  uuid.UUID
}

type imageDeployRec = store.ImageDeploy

func envKey(projectID uuid.UUID, name string) string {
	return projectID.String() + "/" + name
}

func (m *Mem) projectAliveLocked(projectID uuid.UUID) bool {
	p, ok := m.projects[projectID]
	return ok && p.DeletedAt == nil
}

func (m *Mem) BeginImageOp(ctx context.Context, entryID, hostID uuid.UUID, specHash string, by uuid.UUID, via string, at, until time.Time) (store.ImageDeploy, error) {
	if err := ctx.Err(); err != nil {
		return store.ImageDeploy{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[entryID]; !ok {
		return store.ImageDeploy{}, store.ErrNotFound
	}
	if _, ok := m.hosts[hostID]; !ok {
		return store.ImageDeploy{}, store.ErrNotFound
	}
	for id, row := range m.imageDeploys {
		if !row.InFlight || row.EntryID != entryID || row.HostID != hostID {
			continue
		}
		if row.InFlightUntil.After(at) {
			return store.ImageDeploy{}, store.ErrConflict
		}
		finished := at
		row.Outcome = "timeout"
		row.FinishedAt = &finished
		row.InFlight = false
		m.imageDeploys[id] = row
		break
	}
	row := store.ImageDeploy{
		ID: uuid.New(), EntryID: entryID, HostID: hostID, SpecHash: specHash,
		Outcome: "in_flight", StartedAt: at, By: by, Via: via, InFlight: true,
		InFlightUntil: until,
	}
	m.imageDeploys[row.ID] = row
	return row, nil
}

func (m *Mem) FinishImageDeploy(ctx context.Context, id uuid.UUID, outcome string, digest *string, exitCode *int, at time.Time) (store.ImageDeploy, error) {
	if err := ctx.Err(); err != nil {
		return store.ImageDeploy{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.imageDeploys[id]
	if !ok || !row.InFlight {
		return store.ImageDeploy{}, store.ErrNotFound
	}
	row.Outcome = outcome
	if digest != nil && !catalog.ValidDigest(*digest) {
		digest = nil
	}
	row.Digest = cloneString(digest)
	if exitCode != nil {
		n := *exitCode
		row.ExitCode = &n
	}
	finished := at
	row.FinishedAt = &finished
	row.InFlight = false
	m.imageDeploys[id] = row
	return row, nil
}

func (m *Mem) ReleaseImageOp(ctx context.Context, id uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.imageDeploys[id]
	if !ok || !row.InFlight {
		return nil
	}
	delete(m.imageDeploys, id)
	return nil
}

func (m *Mem) ListImageDeploys(_ context.Context, entryID, hostID uuid.UUID) ([]store.ImageDeploy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[entryID]; !ok {
		return nil, store.ErrNotFound
	}
	out := make([]store.ImageDeploy, 0)
	for _, row := range m.imageDeploys {
		if row.EntryID == entryID && row.HostID == hostID && !row.InFlight {
			out = append(out, copyDeploy(row))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FinishedAt.After(*out[j].FinishedAt)
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out, nil
}

func (m *Mem) RollbackDigests(_ context.Context, entryID, hostID uuid.UUID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make([]store.ImageDeploy, 0)
	for _, row := range m.imageDeploys {
		if row.EntryID != entryID || row.HostID != hostID || row.InFlight || row.Digest == nil {
			continue
		}
		if row.Outcome != "succeeded" && row.Outcome != "unchanged" {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].FinishedAt.After(*rows[j].FinishedAt)
	})
	seen := map[string]bool{}
	out := make([]string, 0, 3)
	for _, row := range rows {
		if seen[*row.Digest] {
			continue
		}
		seen[*row.Digest] = true
		out = append(out, *row.Digest)
		if len(out) == 3 {
			break
		}
	}
	return out, nil
}

func copyDeploy(row store.ImageDeploy) store.ImageDeploy {
	row.Digest = cloneString(row.Digest)
	if row.ExitCode != nil {
		n := *row.ExitCode
		row.ExitCode = &n
	}
	if row.FinishedAt != nil {
		t := *row.FinishedAt
		row.FinishedAt = &t
	}
	return row
}

func (m *Mem) ListEnvKeyNames(_ context.Context, projectID uuid.UUID) (map[string][]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return nil, store.ErrNotFound
	}
	return m.envKeyNamesLocked(projectID), nil
}

func (m *Mem) envKeyNamesLocked(projectID uuid.UUID) map[string][]string {
	out := map[string][]string{}
	prefix := projectID.String() + "/"
	for key, set := range m.envSets {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			out[set.Name] = []string{}
		}
	}
	for key, values := range m.envValues {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		name := key[len(prefix):]
		keys := make([]string, 0, len(values))
		for _, v := range values {
			keys = append(keys, v.Key)
		}
		sort.Strings(keys)
		out[name] = keys
	}
	return out
}

func (m *Mem) ListEnvSets(_ context.Context, projectID uuid.UUID) ([]store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return nil, store.ErrNotFound
	}
	out := make([]store.EnvSet, 0)
	for key, set := range m.envSets {
		if key != envKey(projectID, set.Name) {
			continue
		}
		out = append(out, m.envSetViewLocked(projectID, set))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Mem) GetEnvSet(_ context.Context, projectID uuid.UUID, name string) (store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.envSets[envKey(projectID, name)]
	if !ok {
		return store.EnvSet{}, store.ErrNotFound
	}
	return m.envSetViewLocked(projectID, set), nil
}

func (m *Mem) envSetViewLocked(projectID uuid.UUID, set envSetRec) store.EnvSet {
	values := append([]envValueRec(nil), m.envValues[envKey(projectID, set.Name)]...)
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	keys := make([]store.EnvKey, 0, len(values))
	for _, v := range values {
		item := store.EnvKey{Key: v.Key, IsSecret: v.IsSecret}
		if !v.IsSecret {
			plain := v.Plain
			item.Value = &plain
		}
		keys = append(keys, item)
	}
	return store.EnvSet{Name: set.Name, Keys: keys, UpdatedAt: set.UpdatedAt, UpdatedBy: set.UpdatedBy}
}

func (m *Mem) PutEnvSet(_ context.Context, projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time) (store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.EnvSet{}, store.ErrNotFound
	}
	if !catalog.ValidName(name) {
		return store.EnvSet{}, store.ErrInvalid
	}
	rec := envSetRec{Name: name, UpdatedAt: at, UpdatedBy: actor}
	m.envSets[envKey(projectID, name)] = rec
	values := make([]envValueRec, 0, len(keys))
	for _, k := range keys {
		values = append(values, envValueRec{
			Key: k.Key, IsSecret: true,
			Nonce: append([]byte(nil), k.Nonce...), Ciphertext: append([]byte(nil), k.Ciphertext...),
			KeyVersion: k.KeyVersion,
		})
	}
	m.envValues[envKey(projectID, name)] = values
	m.rehashSetLocked(projectID, name, at)
	return m.envSetViewLocked(projectID, rec), nil
}

func (m *Mem) PatchEnvKey(_ context.Context, projectID uuid.UUID, name, key string, in store.EnvKeyPatch, actor uuid.UUID, at time.Time) (store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.envSets[envKey(projectID, name)]
	if !ok {
		return store.EnvSet{}, store.ErrNotFound
	}
	values := m.envValues[envKey(projectID, name)]
	found := false
	for i := range values {
		if values[i].Key != key {
			continue
		}
		found = true
		values[i].IsSecret = in.IsSecret
		if in.IsSecret {
			values[i].Plain = ""
			values[i].Nonce = append([]byte(nil), in.Nonce...)
			values[i].Ciphertext = append([]byte(nil), in.Ciphertext...)
			values[i].KeyVersion = in.KeyVersion
		} else {
			values[i].Plain = in.Plain
			values[i].Nonce = nil
			values[i].Ciphertext = nil
			values[i].KeyVersion = 0
		}
	}
	if !found {
		return store.EnvSet{}, store.ErrNotFound
	}
	m.envValues[envKey(projectID, name)] = values
	set.UpdatedAt = at
	set.UpdatedBy = actor
	m.envSets[envKey(projectID, name)] = set
	return m.envSetViewLocked(projectID, set), nil
}

func (m *Mem) DeleteEnvSet(_ context.Context, projectID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.envSets[envKey(projectID, name)]; !ok {
		return store.ErrNotFound
	}
	if m.setReferencedLocked(projectID, name) {
		return store.ErrConflict
	}
	delete(m.envSets, envKey(projectID, name))
	delete(m.envValues, envKey(projectID, name))
	return nil
}

func (m *Mem) setReferencedLocked(projectID uuid.UUID, name string) bool {
	for _, e := range m.entries {
		if e.ProjectID != projectID || e.Kind != "image" {
			continue
		}
		img, err := catalog.ParseStored(e.ImageRaw)
		if err != nil {
			continue
		}
		if catalog.ReferencesSet(img, name) {
			return true
		}
	}
	return false
}

func (m *Mem) rehashSetLocked(projectID uuid.UUID, set string, at time.Time) {
	names := m.envKeyNamesLocked(projectID)
	for id, e := range m.entries {
		if e.ProjectID != projectID || e.Kind != "image" {
			continue
		}
		img, err := catalog.ParseStored(e.ImageRaw)
		if err != nil || !catalog.ReferencesSet(img, set) {
			continue
		}
		digests := map[string]string{}
		for _, ref := range catalog.ReferencedSets(img) {
			digests[ref] = catalog.EnvKeyDigest(names[ref])
		}
		next := catalog.ImageHash(img, digests)
		if next == e.SpecHash {
			continue
		}
		e.SpecHash = next
		e.UpdatedAt = at
		m.entries[id] = e
		m.deleteApprovalsLocked(id)
	}
}

func (m *Mem) ListEnvMaterial(_ context.Context, projectID uuid.UUID, name string) ([]store.EnvMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.envSets[envKey(projectID, name)]; !ok {
		return nil, store.ErrNotFound
	}
	values := m.envValues[envKey(projectID, name)]
	out := make([]store.EnvMaterial, 0, len(values))
	for _, v := range values {
		out = append(out, store.EnvMaterial{
			Key: v.Key, IsSecret: v.IsSecret, Plain: v.Plain,
			Nonce: append([]byte(nil), v.Nonce...), Ciphertext: append([]byte(nil), v.Ciphertext...),
			KeyVersion: v.KeyVersion,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (m *Mem) ListRegistries(_ context.Context, projectID uuid.UUID) ([]store.Registry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return nil, store.ErrNotFound
	}
	out := make([]store.Registry, 0)
	for key, rec := range m.registries {
		if key != envKey(projectID, rec.Host) {
			continue
		}
		out = append(out, store.Registry{Host: rec.Host, Username: rec.Username, UpdatedAt: rec.UpdatedAt, UpdatedBy: rec.UpdatedBy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func (m *Mem) PutRegistry(_ context.Context, projectID uuid.UUID, host string, in store.RegistryWrite, actor uuid.UUID, at time.Time) (store.Registry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.Registry{}, store.ErrNotFound
	}
	if !catalog.ValidRegistryHost(host) {
		return store.Registry{}, store.ErrInvalid
	}
	m.registries[envKey(projectID, host)] = registryRec{
		Host: host, Username: in.Username,
		Nonce: append([]byte(nil), in.Nonce...), Ciphertext: append([]byte(nil), in.Ciphertext...),
		KeyVersion: in.KeyVersion, UpdatedAt: at, UpdatedBy: actor,
	}
	return store.Registry{Host: host, Username: in.Username, UpdatedAt: at, UpdatedBy: actor}, nil
}

func (m *Mem) DeleteRegistry(_ context.Context, projectID uuid.UUID, host string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.registries[envKey(projectID, host)]; !ok {
		return store.ErrNotFound
	}
	delete(m.registries, envKey(projectID, host))
	return nil
}

func (m *Mem) GetRegistryMaterial(_ context.Context, projectID uuid.UUID, host string) (store.RegistryMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.registries[envKey(projectID, host)]
	if !ok {
		return store.RegistryMaterial{}, store.ErrNotFound
	}
	return store.RegistryMaterial{
		Host: rec.Host, Username: rec.Username,
		Nonce: append([]byte(nil), rec.Nonce...), Ciphertext: append([]byte(nil), rec.Ciphertext...),
		KeyVersion: rec.KeyVersion,
	}, nil
}

func (m *Mem) deleteDeploysLocked(entryID uuid.UUID) {
	for id, row := range m.imageDeploys {
		if row.EntryID == entryID {
			delete(m.imageDeploys, id)
		}
	}
}

func (m *Mem) deleteSecretsLocked(projectID uuid.UUID) {
	prefix := projectID.String() + "/"
	for key := range m.envSets {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(m.envSets, key)
		}
	}
	for key := range m.envValues {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(m.envValues, key)
		}
	}
	for key := range m.registries {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(m.registries, key)
		}
	}
	for key := range m.projectFiles {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(m.projectFiles, key)
		}
	}
}
