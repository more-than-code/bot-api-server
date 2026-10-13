package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) ListServices(ctx context.Context, hostID uuid.UUID, now time.Time) ([]store.Service, error) {
	rows, err := d.pool.Query(ctx, `
SELECT s.id::text, s.host_id::text, s.name, s.source, s.kind, s.ports,
       s.systemd_unit, s.systemd_scope, s.container_name, s.process_match,
       s.first_seen_at, s.last_seen_at,
       hr.time, hr.result, hr.latency_ms
FROM app.services s
LEFT JOIN LATERAL (
    SELECT time, result, latency_ms
    FROM metrics.health_results
    WHERE service_id = s.id
    ORDER BY time DESC
    LIMIT 1
) hr ON true
WHERE s.host_id = $1::uuid
ORDER BY s.name ASC
LIMIT 500
`, hostID.String())
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
SELECT s.id::text, s.host_id::text, s.name, s.source, s.kind, s.ports,
       s.systemd_unit, s.systemd_scope, s.container_name, s.process_match,
       s.first_seen_at, s.last_seen_at,
       hr.time, hr.result, hr.latency_ms
FROM app.services s
LEFT JOIN LATERAL (
    SELECT time, result, latency_ms
    FROM metrics.health_results
    WHERE service_id = s.id
    ORDER BY time DESC
    LIMIT 1
) hr ON true
WHERE s.id = $1::uuid
`, id.String()), now)
}

func (d *DB) UpsertDiscovered(ctx context.Context, hostID uuid.UUID, items []store.Discovered, at time.Time) error {
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
	for _, item := range items {
		if err := exec(ctx, tx, `
INSERT INTO app.services (
    id, host_id, name, source, kind, ports,
    systemd_unit, systemd_scope, container_name, process_match,
    first_seen_at, last_seen_at
) VALUES (
    $1::uuid, $2::uuid, $3, 'discovered', $4, $5::integer[],
    $6, $7, $8, $9,
    $10, $10
)
ON CONFLICT (host_id, name) DO UPDATE SET
    last_seen_at = EXCLUDED.last_seen_at,
    kind = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.kind ELSE app.services.kind END,
    ports = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.ports ELSE app.services.ports END,
    systemd_unit = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.systemd_unit ELSE app.services.systemd_unit END,
    systemd_scope = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.systemd_scope ELSE app.services.systemd_scope END,
    container_name = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.container_name ELSE app.services.container_name END,
    process_match = CASE WHEN app.services.source = 'discovered' THEN EXCLUDED.process_match ELSE app.services.process_match END
`, uuid.New().String(), hostID.String(), item.Name, item.Kind, intsTo32(item.Ports),
			optString(item.SystemdUnit), optString(item.SystemdScope), optString(item.ContainerName), optString(item.ProcessName),
			at); err != nil {
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
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.services WHERE id = $1::uuid)`, serviceID.String()).Scan(&exists); err != nil {
		return nil, mapErr(err)
	}
	if !exists {
		return nil, store.ErrNotFound
	}
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
	if err := tx.Commit(ctx); err != nil {
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
	var s store.Service
	var id, hostID string
	var ports []int32
	var checked *time.Time
	var result *string
	var latency *float64
	if err := row.Scan(
		&id, &hostID, &s.Name, &s.Source, &s.Kind, &ports,
		&s.SystemdUnit, &s.SystemdScope, &s.ContainerName, &s.ProcessName,
		&s.FirstSeenAt, &s.LastSeenAt,
		&checked, &result, &latency,
	); err != nil {
		return store.Service{}, mapErr(err)
	}
	var err error
	if s.ID, err = parseID(id); err != nil {
		return store.Service{}, err
	}
	if s.HostID, err = parseID(hostID); err != nil {
		return store.Service{}, err
	}
	s.Ports = intsFrom32(ports)
	var latest *store.HealthPoint
	if checked != nil {
		p := store.HealthPoint{T: *checked, LatencyMS: floatOrZero(latency)}
		if result != nil {
			p.Result = *result
		}
		latest = &p
	}
	s.Health = store.DeriveHealth(latest, now)
	return s, nil
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
