package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// serviceColumns is the Service scan list shared by host and project lists.
// display_name and owner_user stay in this list so every Service JSON has them.
const serviceColumns = `
s.id::text, s.host_id::text, s.project_id::text, s.name, s.source, s.kind, s.ports,
s.systemd_unit, s.systemd_scope, s.container_name, s.image_digest, s.process_match,
s.display_name, s.owner_user, s.catalog_entry,
s.first_seen_at, s.last_seen_at, s.gone_at,
hr.time, hr.result, hr.latency_ms, hr.protocol`

// serviceHealthJoin chooses the health row for a service.
// A docker row at or after the cutoff wins. Otherwise the latest non-docker
// row wins, including a null protocol. A stale docker row is excluded.
func serviceHealthJoin(cutoff string) string {
	return `
LEFT JOIN LATERAL (
    SELECT time, result, latency_ms, protocol
    FROM metrics.health_results
    WHERE service_id = s.id
      AND (
        (protocol = 'docker' AND time >= ` + cutoff + `)
        OR protocol IS DISTINCT FROM 'docker'
      )
    ORDER BY CASE WHEN protocol = 'docker' THEN 0 ELSE 1 END, time DESC
    LIMIT 1
) hr ON true`
}

// projectIDsArg is nil when every project is visible. Otherwise it is a
// text[] of ids. pgx sends a Go string slice as text[], and text[] does not
// cast to uuid[], so queries compare project_id::text = ANY($n::text[]).
// An empty slice matches no rows.
func projectIDsArg(ids []uuid.UUID) any {
	if ids == nil {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func (d *DB) ListServices(ctx context.Context, hostID uuid.UUID, projects []uuid.UUID, now time.Time) ([]store.Service, error) {
	rows, err := d.pool.Query(ctx, `
SELECT `+serviceColumns+`
FROM app.services s
`+serviceHealthJoin("$3")+`
WHERE s.host_id = $1::uuid
  AND (
    CAST($2 AS text[]) IS NULL
    OR s.project_id::text = ANY(CAST($2 AS text[]))
  )
ORDER BY s.name COLLATE "C" ASC
LIMIT 500
`, hostID.String(), projectIDsArg(projects), now.Add(-store.HealthStale))
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Service{}
	for rows.Next() {
		svc, err := scanService(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) GetService(ctx context.Context, id uuid.UUID, now time.Time) (store.Service, error) {
	return scanService(d.pool.QueryRow(ctx, `
SELECT `+serviceColumns+`
FROM app.services s
`+serviceHealthJoin("$2")+`
WHERE s.id = $1::uuid
`, id.String(), now.Add(-store.HealthStale)), now)
}

func (d *DB) SetServiceDisplayName(ctx context.Context, id uuid.UUID, name *string, now time.Time) (store.Service, error) {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.services SET display_name = $2 WHERE id = $1::uuid
`, id.String(), optString(name))
	if err != nil {
		return store.Service{}, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.Service{}, store.ErrNotFound
	}
	return d.GetService(ctx, id, now)
}

func (d *DB) ListProjectServices(ctx context.Context, projectID uuid.UUID, q store.ServiceListQuery, now time.Time) (store.ServicePage, error) {
	if q.HostID != nil {
		ok, err := d.projectHostReached(ctx, projectID, *q.HostID)
		if err != nil {
			return store.ServicePage{}, err
		}
		if !ok {
			return store.ServicePage{}, store.ErrInvalid
		}
	}
	where, args := projectServiceWhere(projectID, q)
	var total int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*)
FROM app.services s
JOIN app.hosts h ON h.id = s.host_id
JOIN app.projects sp ON sp.id = s.project_id
`+where, args...).Scan(&total); err != nil {
		return store.ServicePage{}, mapErr(err)
	}
	limit := q.Limit
	if limit < 1 {
		limit = 50
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	pageArgs := append(append([]any{}, args...), now.Add(-store.HealthStale), limit, offset)
	cutoff := len(args) + 1
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`
SELECT `+serviceColumns+`,
       h.name, h.always_on, h.revoked_at, sp.name,
       `+nameSortKey+` AS sort_name,
       CASE
         WHEN hr.time IS NOT NULL AND hr.time >= $%d AND hr.result = 'success' THEN 0
         WHEN hr.time IS NOT NULL AND hr.time >= $%d THEN 1
         ELSE 2
       END AS health_rank
FROM app.services s
JOIN app.hosts h ON h.id = s.host_id
JOIN app.projects sp ON sp.id = s.project_id
`+serviceHealthJoin("$%d")+`
%s
ORDER BY %s
LIMIT $%d OFFSET $%d
`, cutoff, cutoff, cutoff, where, projectServiceOrder(q.Sort, q.Dir), cutoff+1, cutoff+2), pageArgs...)
	if err != nil {
		return store.ServicePage{}, mapErr(err)
	}
	defer rows.Close()
	items := []store.ProjectService{}
	for rows.Next() {
		item, err := scanProjectService(rows, now)
		if err != nil {
			return store.ServicePage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return store.ServicePage{}, mapErr(err)
	}
	return store.ServicePage{Items: items, Total: total}, nil
}

func (d *DB) projectHostReached(ctx context.Context, projectID, hostID uuid.UUID) (bool, error) {
	var ok bool
	err := d.pool.QueryRow(ctx, `
SELECT
    EXISTS (
        SELECT 1 FROM app.hosts h
        WHERE h.id = $1::uuid AND h.project_id = $2::uuid
    )
    OR EXISTS (
        SELECT 1 FROM app.host_shares hs
        WHERE hs.host_id = $1::uuid
          AND hs.project_id = $2::uuid
          AND hs.level = 'deploy'
    )
`, hostID.String(), projectID.String()).Scan(&ok)
	if err != nil {
		return false, mapErr(err)
	}
	return ok, nil
}

// projectServiceWhere is the v1.3 row rule plus optional host and search.
// Search parameters are bound. % _ and \ in q match literally.
func projectServiceWhere(projectID uuid.UUID, q store.ServiceListQuery) (string, []any) {
	args := []any{projectID.String()}
	hostPred := "TRUE"
	if q.HostID != nil {
		args = append(args, q.HostID.String())
		hostPred = fmt.Sprintf("s.host_id = $%d::uuid", len(args))
	}
	where := `
WHERE (
    h.project_id = $1::uuid
    OR (
        s.project_id = $1::uuid
        AND EXISTS (
            SELECT 1 FROM app.host_shares hs
            WHERE hs.host_id = h.id
              AND hs.project_id = $1::uuid
              AND hs.level = 'deploy'
        )
    )
)
AND ` + hostPred
	if q.Q != "" {
		args = append(args, likeContains(q.Q))
		p := fmt.Sprintf("$%d", len(args))
		where += fmt.Sprintf(`
AND (
    s.display_name ILIKE %s ESCAPE '\'
    OR s.name ILIKE %s ESCAPE '\'
    OR s.kind ILIKE %s ESCAPE '\'
    OR h.name ILIKE %s ESCAPE '\'
    OR s.owner_user ILIKE %s ESCAPE '\'
    OR EXISTS (
        SELECT 1 FROM unnest(s.ports) AS port_num(n)
        WHERE port_num.n::text ILIKE %s ESCAPE '\'
    )
)`, p, p, p, p, p, p)
	}
	if pred := serviceViewSQL(q.View); pred != "" {
		where += "\nAND " + pred
	}
	return where, args
}

// deploybotRowsSQL is the v1.8.2 deploybot row set: declared rows, and owned
// rows unless they are gone and their catalog entry was deleted (nothing can
// start them again). The revoked-host filter is applied in serviceViewSQL,
// outside this expression, so it also covers discovered rows.
const deploybotRowsSQL = `(s.source = 'declared' OR (s.source = 'owned' AND (
    s.gone_at IS NULL OR s.catalog_entry IS NULL OR EXISTS (
        SELECT 1 FROM app.catalog_entries c
        WHERE c.project_id = s.project_id AND c.name = s.catalog_entry))))`

// serviceViewSQL is a fixed fragment. view is allowlisted by the HTTP
// handler. Anything else, including empty, is the v1.3 row set (all).
// v1.10.1 excludes revoked hosts from both deploybot views. The predicate
// is outside the OR so a discovered row on a revoked host is excluded too.
func serviceViewSQL(view string) string {
	switch view {
	case "deploybot":
		return deploybotRowsSQL + " AND h.revoked_at IS NULL"
	case "deploybot_and_discovered":
		return "(" + deploybotRowsSQL + " OR (s.source = 'discovered' AND s.gone_at IS NULL)) AND h.revoked_at IS NULL"
	default:
		return ""
	}
}

// nameSortKey is the lowercased label in byte order. ORDER BY inlines it.
// PostgreSQL treats only a bare output alias as an output column, so
// "sort_name COLLATE ..." would look for an input column and fail.
const nameSortKey = `lower(coalesce(s.display_name, s.name)) COLLATE "C"`

// projectServiceOrder is a fixed fragment. sort and dir are allowlisted
// by the caller; anything else sorts by name ascending.
// Text keys use COLLATE "C" (byte order), the same order as Go's string
// compare. last_seen is a timestamp and is not collated.
func projectServiceOrder(sortKey, dir string) string {
	direction := "ASC"
	if dir == "desc" {
		direction = "DESC"
	}
	text := func(expr string) string {
		return expr + " " + direction + " NULLS LAST"
	}
	switch sortKey {
	case "host":
		return text(`h.name COLLATE "C"`) + ", s.id ASC"
	case "kind":
		return text(`s.kind COLLATE "C"`) + ", s.id ASC"
	case "last_seen":
		return text("s.last_seen_at") + ", s.id ASC"
	case "status":
		// Present rows stay ahead of gone rows in both directions.
		// dir reverses health_rank and the name only.
		return "(s.gone_at IS NOT NULL) ASC, " + text("health_rank") + ", " + text(nameSortKey) + ", s.id ASC"
	default:
		return text(nameSortKey) + ", s.id ASC"
	}
}

// likeContains escapes LIKE wildcards so the bound pattern is a substring.
func likeContains(q string) string {
	var b strings.Builder
	b.Grow(len(q) + 2)
	b.WriteByte('%')
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteByte(q[i])
	}
	b.WriteByte('%')
	return b.String()
}

func (d *DB) UpsertDiscovered(ctx context.Context, hostID uuid.UUID, items []store.Discovered, at time.Time, complete bool, presence bool) error {
	if !complete {
		return nil
	}
	var exists bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.hosts WHERE id = $1::uuid)`, hostID.String()).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if !exists {
		return store.ErrNotFound
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	var hostProject string
	if err := tx.QueryRow(ctx, `SELECT project_id::text FROM app.hosts WHERE id = $1::uuid`, hostID.String()).Scan(&hostProject); err != nil {
		return mapErr(err)
	}
	ownerProject, err := parseID(hostProject)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		name, source, projectID, catalogEntry := store.PlaceDiscovered(item, ownerProject, func(slug, entry, kind string) (uuid.UUID, bool) {
			return d.catalogLookup(ctx, tx, slug, entry, kind)
		})
		names = append(names, name)
		if err := exec(ctx, tx, `
INSERT INTO app.services (
    id, host_id, name, source, kind, ports,
    systemd_unit, systemd_scope, container_name, image_digest, process_match,
    first_seen_at, last_seen_at, project_id, owner_user, catalog_entry
) VALUES (
    $1::uuid, $2::uuid, $3, $4, $5, $6::integer[],
    $7, $8, $9, $10, $11,
    $12, $12, $13::uuid, $14, $15
)
ON CONFLICT (host_id, name) DO UPDATE SET
    last_seen_at = EXCLUDED.last_seen_at,
    gone_at = NULL,
    owner_user = EXCLUDED.owner_user,
    source = CASE
        WHEN app.services.source = 'declared' THEN app.services.source
        WHEN EXCLUDED.source = 'owned' THEN 'owned'
        WHEN app.services.source = 'owned' AND EXCLUDED.source = 'discovered' THEN 'discovered'
        ELSE app.services.source
    END,
    project_id = CASE
        WHEN app.services.source = 'declared' THEN app.services.project_id
        WHEN EXCLUDED.source = 'owned' THEN EXCLUDED.project_id
        WHEN app.services.source = 'owned' AND EXCLUDED.source = 'discovered' THEN EXCLUDED.project_id
        ELSE app.services.project_id
    END,
    catalog_entry = CASE
        WHEN app.services.source = 'declared' THEN app.services.catalog_entry
        WHEN EXCLUDED.source = 'owned' THEN EXCLUDED.catalog_entry
        WHEN app.services.source = 'owned' AND EXCLUDED.source = 'discovered' THEN NULL::text
        ELSE app.services.catalog_entry
    END,
    kind = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.kind ELSE app.services.kind END,
    ports = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.ports ELSE app.services.ports END,
    systemd_unit = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.systemd_unit ELSE app.services.systemd_unit END,
    systemd_scope = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.systemd_scope ELSE app.services.systemd_scope END,
    container_name = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.container_name ELSE app.services.container_name END,
    image_digest = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.image_digest ELSE app.services.image_digest END,
    process_match = CASE WHEN app.services.source <> 'declared' THEN EXCLUDED.process_match ELSE app.services.process_match END
`, uuid.New().String(), hostID.String(), name, source, item.Kind, intsTo32(item.Ports),
			optString(item.SystemdUnit), optString(item.SystemdScope), optString(item.ContainerName), optString(item.ImageDigest), optString(item.ProcessName),
			at, projectID.String(), optString(store.NormalizeOwnerUser(item.OwnerUser)), optString(catalogEntry)); err != nil {
			return mapErr(err)
		}
	}
	if presence {
		if err := exec(ctx, tx, `
UPDATE app.services
SET gone_at = $2
WHERE host_id = $1::uuid
  AND gone_at IS NULL
  AND NOT (name = ANY(CAST($3 AS text[])))
`, hostID.String(), at, names); err != nil {
			return mapErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) ReplaceHealthChecks(ctx context.Context, serviceID uuid.UUID, checks []store.HealthCheckInput) ([]store.HealthCheck, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer tx.Rollback(ctx)
	if err := lockService(ctx, tx, serviceID); err != nil {
		return nil, err
	}
	out, err := insertHealthChecks(ctx, tx, serviceID, checks)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// lockService locks one service row for the rest of the transaction.
// A missing row is ErrNotFound. Console replace and confirm share this lock.
func lockService(ctx context.Context, tx queryer, serviceID uuid.UUID) error {
	var id string
	err := tx.QueryRow(ctx, `
SELECT id::text FROM app.services WHERE id = $1::uuid FOR UPDATE
`, serviceID.String()).Scan(&id)
	return mapErr(err)
}

func insertHealthChecks(ctx context.Context, tx queryer, serviceID uuid.UUID, checks []store.HealthCheckInput) ([]store.HealthCheck, error) {
	if err := exec(ctx, tx, `DELETE FROM app.health_checks WHERE service_id = $1::uuid`, serviceID.String()); err != nil {
		return nil, mapErr(err)
	}
	out := make([]store.HealthCheck, 0, len(checks))
	for _, in := range checks {
		c := store.HealthCheck{
			ID:              uuid.New(),
			ServiceID:       serviceID,
			Protocol:        in.Protocol,
			Port:            in.Port,
			Path:            in.Path,
			IntervalSec:     in.IntervalSec,
			ExpectStatusMin: in.ExpectStatusMin,
			ExpectStatusMax: in.ExpectStatusMax,
			Enabled:         in.Enabled,
		}
		if err := exec(ctx, tx, `
INSERT INTO app.health_checks (
    id, service_id, protocol, port, path, interval_sec, expect_status_min, expect_status_max, enabled
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
`, c.ID.String(), serviceID.String(), c.Protocol, c.Port, optString(c.Path), c.IntervalSec, c.ExpectStatusMin, c.ExpectStatusMax, c.Enabled); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, c)
	}
	return out, nil
}

func listHealthChecksTx(ctx context.Context, tx queryer, serviceID uuid.UUID) ([]store.HealthCheck, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, service_id::text, protocol, port, path, interval_sec, expect_status_min, expect_status_max, enabled
FROM app.health_checks
WHERE service_id = $1::uuid
ORDER BY id ASC
`, serviceID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.HealthCheck{}
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) ListHealthChecks(ctx context.Context, serviceID uuid.UUID) ([]store.HealthCheck, error) {
	rows, err := d.pool.Query(ctx, `
SELECT id::text, service_id::text, protocol, port, path, interval_sec, expect_status_min, expect_status_max, enabled
FROM app.health_checks
WHERE service_id = $1::uuid
ORDER BY id ASC
`, serviceID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.HealthCheck{}
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) ListHealthChecksForServices(ctx context.Context, serviceIDs []string) (map[string][]store.HealthCheck, error) {
	out := map[string][]store.HealthCheck{}
	if len(serviceIDs) == 0 {
		return out, nil
	}
	// uuid[] rather than the usual ::text match, so an index on service_id is usable.
	rows, err := d.pool.Query(ctx, `
SELECT id::text, service_id::text, protocol, port, path, interval_sec, expect_status_min, expect_status_max, enabled
FROM app.health_checks
WHERE service_id = ANY(CAST($1 AS uuid[]))
ORDER BY service_id, id
`, serviceIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		key := c.ServiceID.String()
		out[key] = append(out[key], c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) HealthChecksForHost(ctx context.Context, hostID uuid.UUID) ([]store.AgentCheck, error) {
	rows, err := d.pool.Query(ctx, `
SELECT c.id::text, s.name, c.protocol, c.port, c.path, c.interval_sec, c.expect_status_min, c.expect_status_max
FROM app.health_checks c
JOIN app.services s ON s.id = c.service_id
WHERE s.host_id = $1::uuid AND c.enabled
ORDER BY s.name ASC, c.id ASC
`, hostID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.AgentCheck{}
	for rows.Next() {
		var c store.AgentCheck
		var id string
		if err := rows.Scan(&id, &c.Service, &c.Protocol, &c.Port, &c.Path, &c.IntervalSec, &c.ExpectStatusMin, &c.ExpectStatusMax); err != nil {
			return nil, mapErr(err)
		}
		if c.ID, err = parseID(id); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func scanService(row pgx.Row, now time.Time) (store.Service, error) {
	s, err := scanServiceInto(row, now, nil)
	if err != nil {
		return store.Service{}, err
	}
	return s.Service, nil
}

func scanProjectService(row pgx.Row, now time.Time) (store.ProjectService, error) {
	var extra projectServiceExtra
	return scanServiceInto(row, now, &extra)
}

// projectServiceExtra is scanned after the shared service columns and the
// sort expressions, which are discarded.
type projectServiceExtra struct {
	hostName    string
	alwaysOn    bool
	revokedAt   *time.Time
	projectName string
	sortName    string
	healthRank  int
}

func scanServiceInto(row pgx.Row, now time.Time, extra *projectServiceExtra) (store.ProjectService, error) {
	var s store.Service
	var id, hostID, projectID string
	var ports []int32
	var checked *time.Time
	var result *string
	var latency *float64
	var protocol *string
	dest := []any{
		&id, &hostID, &projectID, &s.Name, &s.Source, &s.Kind, &ports,
		&s.SystemdUnit, &s.SystemdScope, &s.ContainerName, &s.ImageDigest, &s.ProcessName,
		&s.DisplayName, &s.OwnerUser, &s.CatalogEntry,
		&s.FirstSeenAt, &s.LastSeenAt, &s.GoneAt,
		&checked, &result, &latency, &protocol,
	}
	if extra != nil {
		dest = append(dest,
			&extra.hostName, &extra.alwaysOn, &extra.revokedAt, &extra.projectName,
			&extra.sortName, &extra.healthRank,
		)
	}
	if err := row.Scan(dest...); err != nil {
		return store.ProjectService{}, mapErr(err)
	}
	var err error
	if s.ID, err = parseID(id); err != nil {
		return store.ProjectService{}, err
	}
	if s.HostID, err = parseID(hostID); err != nil {
		return store.ProjectService{}, err
	}
	if s.ProjectID, err = parseID(projectID); err != nil {
		return store.ProjectService{}, err
	}
	s.Ports = intsFrom32(ports)
	var latest *store.HealthPoint
	if checked != nil {
		p := store.HealthPoint{T: *checked, LatencyMS: latency}
		if result != nil {
			p.Result = *result
		}
		if protocol != nil {
			p.Protocol = *protocol
		}
		latest = &p
	}
	s.Health = store.DeriveHealth(latest, now)
	out := store.ProjectService{Service: s}
	if extra != nil {
		out.HostName = extra.hostName
		out.HostAlwaysOn = extra.alwaysOn
		out.HostRevokedAt = extra.revokedAt
		out.ProjectName = extra.projectName
	}
	return out, nil
}

func scanCheck(row pgx.Row) (store.HealthCheck, error) {
	var c store.HealthCheck
	var id, serviceID string
	if err := row.Scan(&id, &serviceID, &c.Protocol, &c.Port, &c.Path, &c.IntervalSec, &c.ExpectStatusMin, &c.ExpectStatusMax, &c.Enabled); err != nil {
		return store.HealthCheck{}, mapErr(err)
	}
	var err error
	if c.ID, err = parseID(id); err != nil {
		return store.HealthCheck{}, err
	}
	if c.ServiceID, err = parseID(serviceID); err != nil {
		return store.HealthCheck{}, err
	}
	return c, nil
}

func intsTo32(in []int) []int32 {
	out := make([]int32, len(in))
	for i, n := range in {
		out[i] = int32(n)
	}
	return out
}

func intsFrom32(in []int32) []int {
	out := make([]int, len(in))
	for i, n := range in {
		out[i] = int(n)
	}
	return out
}

func floatOrZero(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}
