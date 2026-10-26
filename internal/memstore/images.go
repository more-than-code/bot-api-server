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
	actor := by
	row := store.ImageDeploy{
		ID: uuid.New(), EntryID: entryID, HostID: hostID, SpecHash: specHash,
		Outcome: "in_flight", StartedAt: at, By: &actor, Via: via, InFlight: true,
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
	manual := make([]store.ImageDeploy, 0)
	auto := make([]store.ImageDeploy, 0)
	for _, row := range m.imageDeploys {
		if row.EntryID != entryID || row.HostID != hostID || row.InFlight {
			continue
		}
		if row.Via == "agent" {
			auto = append(auto, copyDeploy(row))
		} else {
			manual = append(manual, copyDeploy(row))
		}
	}
	sortDeploys(manual)
	sortDeploys(auto)
	if len(manual) > 50 {
		manual = manual[:50]
	}
	out := manual
	added := 0
	for _, row := range auto {
		if added == 20 {
			break
		}
		if len(manual) > 0 && !row.FinishedAt.After(*manual[len(manual)-1].FinishedAt) {
			break
		}
		out = append(out, row)
		added++
	}
	sortDeploys(out)
	return out, nil
}

// sortDeploys orders finished rows newest first, then by id, as the DB does.
func sortDeploys(rows []store.ImageDeploy) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].FinishedAt.Equal(*rows[j].FinishedAt) {
			return rows[i].FinishedAt.After(*rows[j].FinishedAt)
		}
		return rows[i].ID.String() > rows[j].ID.String()
	})
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

func (m *Mem) AutoActionTarget(ctx context.Context, hostID uuid.UUID, projectSlug, entry string) (store.AutoTarget, error) {
	if err := ctx.Err(); err != nil {
		return store.AutoTarget{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	projectID, ok := m.lookupCatalogLocked(projectSlug, entry, "image")
	if !ok {
		return store.AutoTarget{}, store.ErrNotFound
	}
	h, ok := m.hosts[hostID]
	if !ok {
		return store.AutoTarget{}, store.ErrNotFound
	}
	if h.ProjectID != projectID {
		sh, shared := m.shares[shareKey(hostID, projectID)]
		if !shared || sh.Level != "deploy" {
			return store.AutoTarget{}, store.ErrNotFound
		}
	}
	entryID := m.entryByName[entryKey(projectID, entry)]
	deployed := false
	for _, row := range m.imageDeploys {
		if row.EntryID == entryID && row.HostID == hostID && !row.InFlight && (row.Outcome == "succeeded" || row.Outcome == "unchanged") {
			deployed = true
			break
		}
	}
	raw := append([]byte(nil), m.entries[entryID].ImageRaw...)
	return store.AutoTarget{ProjectID: projectID, EntryID: entryID, ImageRaw: raw, Deployed: deployed}, nil
}

func (m *Mem) RecordAutoAction(ctx context.Context, in store.AutoAction) (store.ImageDeploy, bool, error) {
	if err := ctx.Err(); err != nil {
		return store.ImageDeploy{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.autoActions[in.ID]; ok {
		return store.ImageDeploy{}, false, nil
	}
	entry, ok := m.entries[in.EntryID]
	if !ok {
		return store.ImageDeploy{}, false, store.ErrNotFound
	}
	if _, ok := m.hosts[in.HostID]; !ok {
		return store.ImageDeploy{}, false, store.ErrNotFound
	}
	since := in.At.Add(-time.Hour)
	recent := 0
	var last, lastDigest *store.ImageDeploy
	for _, row := range m.imageDeploys {
		if row.EntryID != in.EntryID || row.HostID != in.HostID || row.InFlight {
			continue
		}
		r := row
		if r.Via == "agent" && r.FinishedAt.After(since) {
			recent++
		}
		if last == nil || r.FinishedAt.After(*last.FinishedAt) {
			last = &r
		}
		inheritable := r.Via != "agent" && (r.Outcome == "succeeded" || r.Outcome == "unchanged")
		if r.Digest != nil && inheritable && (lastDigest == nil || r.FinishedAt.After(*lastDigest.FinishedAt)) {
			lastDigest = &r
		}
	}
	if recent >= store.AutoActionsPerHour {
		return store.ImageDeploy{}, false, store.ErrAutoActionLimit
	}
	specHash := entry.SpecHash
	if last != nil {
		specHash = last.SpecHash
	}
	digest := in.Digest
	if digest != nil && !catalog.ValidDigest(*digest) {
		digest = nil
	}
	if digest == nil && lastDigest != nil {
		digest = lastDigest.Digest
	}
	if in.Outcome == "auto_failed" {
		digest = nil
	}
	at := in.At
	row := store.ImageDeploy{
		ID: uuid.New(), EntryID: in.EntryID, HostID: in.HostID, Digest: cloneString(digest),
		SpecHash: specHash, Outcome: in.Outcome, StartedAt: at, FinishedAt: &at, Via: "agent",
	}
	m.imageDeploys[row.ID] = row
	m.autoActions[in.ID] = struct{}{}
	return copyDeploy(row), true, nil
}

func copyDeploy(row store.ImageDeploy) store.ImageDeploy {
	row.Digest = cloneString(row.Digest)
	if row.By != nil {
		by := *row.By
		row.By = &by
	}
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

func (m *Mem) PutEnvSet(_ context.Context, projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time, newKeysSecret bool) (store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.putEnvSetLocked(projectID, name, keys, actor, at, newKeysSecret)
}

func (m *Mem) putEnvSetLocked(projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time, newKeysSecret bool) (store.EnvSet, error) {
	if !m.projectAliveLocked(projectID) {
		return store.EnvSet{}, store.ErrNotFound
	}
	if !catalog.ValidName(name) {
		return store.EnvSet{}, store.ErrInvalid
	}
	id := envKey(projectID, name)
	kept := map[string]bool{}
	for _, v := range m.envValues[id] {
		kept[v.Key] = v.IsSecret
	}
	rec := envSetRec{Name: name, UpdatedAt: at, UpdatedBy: actor}
	m.envSets[id] = rec
	values := make([]envValueRec, 0, len(keys))
	for _, k := range keys {
		secret := newKeysSecret
		if was, ok := kept[k.Key]; ok {
			secret = was
		}
		row := envValueRec{Key: k.Key, IsSecret: secret}
		if secret {
			row.Nonce = append([]byte(nil), k.Nonce...)
			row.Ciphertext = append([]byte(nil), k.Ciphertext...)
			row.KeyVersion = k.KeyVersion
		} else {
			row.Plain = k.Plain
		}
		values = append(values, row)
	}
	m.envValues[id] = values
	m.rehashSetLocked(projectID, name, at)
	return m.envSetViewLocked(projectID, rec), nil
}

func (m *Mem) CreateEnvSet(_ context.Context, projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time, newKeysSecret bool) (store.EnvSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.envSets[envKey(projectID, name)]; exists {
		return store.EnvSet{}, store.ErrConflict
	}
	return m.putEnvSetLocked(projectID, name, keys, actor, at, newKeysSecret)
}

func (m *Mem) MergeEnvSet(_ context.Context, projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time, newKeysSecret bool) (store.EnvSet, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.EnvSet{}, nil, store.ErrNotFound
	}
	if !catalog.ValidName(name) {
		return store.EnvSet{}, nil, store.ErrInvalid
	}
	id := envKey(projectID, name)
	set, ok := m.envSets[id]
	if !ok {
		return store.EnvSet{}, nil, store.ErrNotFound
	}
	values := append([]envValueRec(nil), m.envValues[id]...)
	index := map[string]int{}
	for i, v := range values {
		index[v.Key] = i
	}
	for _, k := range keys {
		if i, ok := index[k.Key]; ok && values[i].IsSecret && k.Plain == "" {
			return store.EnvSet{}, nil, store.ErrSecretEmpty
		}
	}
	created := []string{}
	for _, k := range keys {
		i, exists := index[k.Key]
		secret := newKeysSecret
		if exists {
			secret = values[i].IsSecret
		}
		row := envValueRec{Key: k.Key, IsSecret: secret}
		if secret {
			row.Nonce = append([]byte(nil), k.Nonce...)
			row.Ciphertext = append([]byte(nil), k.Ciphertext...)
			row.KeyVersion = k.KeyVersion
		} else {
			row.Plain = k.Plain
		}
		if exists {
			values[i] = row
			continue
		}
		index[k.Key] = len(values)
		values = append(values, row)
		created = append(created, k.Key)
	}
	set.UpdatedAt = at
	set.UpdatedBy = actor
	m.envSets[id] = set
	m.envValues[id] = values
	m.rehashSetLocked(projectID, name, at)
	sort.Strings(created)
	return m.envSetViewLocked(projectID, set), created, nil
}

func (m *Mem) PutEnvKey(_ context.Context, projectID uuid.UUID, name string, in store.EnvKeyPut, actor uuid.UUID, at time.Time) (store.EnvKey, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.projectAliveLocked(projectID) {
		return store.EnvKey{}, false, store.ErrNotFound
	}
	if !catalog.ValidName(name) {
		return store.EnvKey{}, false, store.ErrInvalid
	}
	if err := catalog.ValidateEnvKey(in.Key); err != nil {
		return store.EnvKey{}, false, store.ErrInvalid
	}
	id := envKey(projectID, name)
	set, exists := m.envSets[id]
	if !exists {
		set = envSetRec{Name: name}
	}
	set.UpdatedAt = at
	set.UpdatedBy = actor
	values := append([]envValueRec(nil), m.envValues[id]...)
	idx := -1
	for i := range values {
		if values[i].Key == in.Key {
			idx = i
			break
		}
	}
	created := idx < 0
	secret := true
	if created {
		if in.Secret != nil {
			secret = *in.Secret
		}
	} else {
		secret = values[idx].IsSecret
		if in.Secret != nil && *in.Secret != secret {
			return store.EnvKey{}, false, store.ErrSecretFixed
		}
		if secret && in.Plain == "" {
			return store.EnvKey{}, false, store.ErrSecretEmpty
		}
	}
	row := envValueRec{Key: in.Key, IsSecret: secret}
	if secret {
		row.Nonce = append([]byte(nil), in.Nonce...)
		row.Ciphertext = append([]byte(nil), in.Ciphertext...)
		row.KeyVersion = in.KeyVersion
	} else {
		row.Plain = in.Plain
	}
	if created {
		values = append(values, row)
	} else {
		values[idx] = row
	}
	m.envSets[id] = set
	m.envValues[id] = values
	if created {
		m.rehashSetLocked(projectID, name, at)
	}
	return storedEnvKey(in.Key, secret, in.Plain), created, nil
}

func (m *Mem) DeleteEnvKey(_ context.Context, projectID uuid.UUID, name, key string, actor uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := envKey(projectID, name)
	set, ok := m.envSets[id]
	if !ok {
		return store.ErrNotFound
	}
	values := m.envValues[id]
	idx := -1
	for i := range values {
		if values[i].Key == key {
			idx = i
			break
		}
	}
	if idx < 0 {
		return store.ErrNotFound
	}
	next := append([]envValueRec(nil), values[:idx]...)
	next = append(next, values[idx+1:]...)
	m.envValues[id] = next
	set.UpdatedAt = at
	set.UpdatedBy = actor
	m.envSets[id] = set
	m.rehashSetLocked(projectID, name, at)
	return nil
}

func (m *Mem) MakeEnvKeysSecret(_ context.Context, projectID uuid.UUID, name string, keys []string, seal store.EnvSealer, actor uuid.UUID, at time.Time) (store.EnvSet, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := envKey(projectID, name)
	set, ok := m.envSets[id]
	if !ok {
		return store.EnvSet{}, nil, store.ErrNotFound
	}
	values := append([]envValueRec(nil), m.envValues[id]...)
	index := map[string]int{}
	for i, v := range values {
		index[v.Key] = i
	}
	for _, key := range keys {
		if _, ok := index[key]; !ok {
			return store.EnvSet{}, nil, &store.MissingEnvKeyError{Key: key}
		}
	}
	changed := []string{}
	for _, key := range keys {
		i := index[key]
		if values[i].IsSecret {
			continue
		}
		sealed, err := seal(key, values[i].Plain)
		if err != nil {
			return store.EnvSet{}, nil, err
		}
		values[i] = envValueRec{
			Key: key, IsSecret: true,
			Nonce: append([]byte(nil), sealed.Nonce...), Ciphertext: append([]byte(nil), sealed.Ciphertext...),
			KeyVersion: sealed.KeyVersion,
		}
		changed = append(changed, key)
	}
	if len(changed) > 0 {
		set.UpdatedAt = at
		set.UpdatedBy = actor
		m.envSets[id] = set
		m.envValues[id] = values
	}
	sort.Strings(changed)
	return m.envSetViewLocked(projectID, set), changed, nil
}

func storedEnvKey(key string, secret bool, plain string) store.EnvKey {
	item := store.EnvKey{Key: key, IsSecret: secret}
	if !secret {
		value := plain
		item.Value = &value
	}
	return item
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
