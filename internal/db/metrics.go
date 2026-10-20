package db

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) InsertBatch(ctx context.Context, hostID, batchID uuid.UUID, samples []store.Sample, at time.Time) (bool, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return false, mapErr(err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
INSERT INTO metrics.ingest_batches (host_id, batch_id, received_at)
VALUES ($1::uuid, $2::uuid, $3)
ON CONFLICT DO NOTHING
`, hostID.String(), batchID.String(), at)
	if err != nil {
		return false, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	cache := map[string]*uuid.UUID{}
	for _, sample := range samples {
		var serviceID *uuid.UUID
		if sample.M == "process" || sample.M == "health" {
			serviceID, err = lookupServiceID(ctx, tx, hostID, sample.Tags["service"], cache)
			if err != nil {
				return false, err
			}
		}
		if err := insertSample(ctx, tx, hostID, serviceID, sample); err != nil {
			return false, mapErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, mapErr(err)
	}
	return true, nil
}

func lookupServiceID(ctx context.Context, q queryer, hostID uuid.UUID, name string, cache map[string]*uuid.UUID) (*uuid.UUID, error) {
	if name == "" {
		return nil, nil
	}
	if id, ok := cache[name]; ok {
		return id, nil
	}
	var text string
	err := q.QueryRow(ctx, `
SELECT id::text FROM app.services WHERE host_id = $1::uuid AND name = $2
`, hostID.String(), name).Scan(&text)
	if errors.Is(err, pgx.ErrNoRows) {
		cache[name] = nil
		return nil, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	id, err := parseID(text)
	if err != nil {
		return nil, err
	}
	cache[name] = &id
	return cache[name], nil
}

func insertSample(ctx context.Context, q queryer, hostID uuid.UUID, serviceID *uuid.UUID, s store.Sample) error {
	switch s.M {
	case "cpu":
		return exec(ctx, q, `
INSERT INTO metrics.host_cpu (time, host_id, cpu, usage_user, usage_system, usage_idle, usage_iowait)
VALUES ($1, $2::uuid, $3, $4, $5, $6, $7)
`, s.T, hostID.String(), s.Tags["cpu"], optFloat(s.Floats, "usage_user"), optFloat(s.Floats, "usage_system"), optFloat(s.Floats, "usage_idle"), optFloat(s.Floats, "usage_iowait"))
	case "mem":
		return exec(ctx, q, `
INSERT INTO metrics.host_mem (time, host_id, total, available, used, used_percent)
VALUES ($1, $2::uuid, $3, $4, $5, $6)
`, s.T, hostID.String(), optInt(s.Ints, "total"), optInt(s.Ints, "available"), optInt(s.Ints, "used"), optFloat(s.Floats, "used_percent"))
	case "disk":
		return exec(ctx, q, `
INSERT INTO metrics.host_disk (time, host_id, path, fstype, total, used, free, used_percent)
VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8)
`, s.T, hostID.String(), s.Tags["path"], s.Tags["fstype"], optInt(s.Ints, "total"), optInt(s.Ints, "used"), optInt(s.Ints, "free"), optFloat(s.Floats, "used_percent"))
	case "diskio":
		return exec(ctx, q, `
INSERT INTO metrics.host_diskio (time, host_id, name, read_bytes, write_bytes)
VALUES ($1, $2::uuid, $3, $4, $5)
`, s.T, hostID.String(), s.Tags["name"], optInt(s.Ints, "read_bytes"), optInt(s.Ints, "write_bytes"))
	case "net":
		return exec(ctx, q, `
INSERT INTO metrics.host_net (time, host_id, interface, bytes_recv, bytes_sent)
VALUES ($1, $2::uuid, $3, $4, $5)
`, s.T, hostID.String(), s.Tags["interface"], optInt(s.Ints, "bytes_recv"), optInt(s.Ints, "bytes_sent"))
	case "system":
		return exec(ctx, q, `
INSERT INTO metrics.host_system (time, host_id, load1, load5, load15, uptime, n_cpus)
VALUES ($1, $2::uuid, $3, $4, $5, $6, $7)
`, s.T, hostID.String(), optFloat(s.Floats, "load1"), optFloat(s.Floats, "load5"), optFloat(s.Floats, "load15"), optInt(s.Ints, "uptime"), optInt32(s.Ints, "n_cpus"))
	case "temp":
		return exec(ctx, q, `
INSERT INTO metrics.host_temp (time, host_id, sensor, celsius)
VALUES ($1, $2::uuid, $3, $4)
`, s.T, hostID.String(), s.Tags["sensor"], optFloat(s.Floats, "celsius"))
	case "process":
		pid, err := strconv.Atoi(s.Tags["pid"])
		if err != nil {
			return err
		}
		started, err := parseStarted(s.Strs["started_at"])
		if err != nil {
			return err
		}
		return exec(ctx, q, `
INSERT INTO metrics.process_samples (
    time, host_id, service_id, pid, process_name, "user", cmdline,
    cpu_usage, memory_rss, memory_usage, num_threads, started_at
) VALUES (
    $1, $2::uuid, $3::uuid, $4, $5, $6, $7,
    $8, $9, $10, $11, $12
)
`, s.T, hostID.String(), optUUID(serviceID), int32(pid), s.Tags["process_name"], s.Tags["user"], s.Tags["cmdline"],
			optFloat(s.Floats, "cpu_usage"), optInt(s.Ints, "memory_rss"), optFloat(s.Floats, "memory_usage"), optInt32(s.Ints, "num_threads"), started)
	case "health":
		var check any
		if raw := s.Tags["check_id"]; raw != "" {
			if _, err := uuid.Parse(raw); err != nil {
				return err
			}
			check = raw
		}
		var port any
		if raw := s.Tags["port"]; raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return err
			}
			port = int32(n)
		}
		var httpStatus any
		if !s.Nulls["http_status"] {
			httpStatus = optInt32(s.Ints, "http_status")
		}
		return exec(ctx, q, `
INSERT INTO metrics.health_results (
    time, host_id, service_id, check_id, protocol, port, result, http_status, latency_ms
) VALUES (
    $1, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9
)
`, s.T, hostID.String(), optUUID(serviceID), check, s.Tags["protocol"], port, s.Strs["result"], httpStatus, optFloat(s.Floats, "latency_ms"))
	default:
		return errors.New("unknown measurement")
	}
}

func parseStarted(raw string) (any, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, err
		}
	}
	return t.UTC(), nil
}

func optFloat(m map[string]float64, key string) any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	return v
}

func optInt(m map[string]int64, key string) any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	return v
}

func optInt32(m map[string]int64, key string) any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	return int32(v)
}

func (d *DB) LoadMetric(ctx context.Context, hostID uuid.UUID, measurement string, from, to time.Time) ([]store.Sample, error) {
	switch measurement {
	case "cpu":
		return d.loadCPU(ctx, hostID, from, to)
	case "mem":
		return d.loadMem(ctx, hostID, from, to)
	case "disk":
		return d.loadDisk(ctx, hostID, from, to)
	case "diskio":
		return d.loadDiskIO(ctx, hostID, from, to)
	case "net":
		return d.loadNet(ctx, hostID, from, to)
	case "system":
		return d.loadSystem(ctx, hostID, from, to)
	case "temp":
		return d.loadTemp(ctx, hostID, from, to)
	case "process":
		return d.loadProcess(ctx, hostID, from, to)
	case "health":
		return d.loadHealth(ctx, hostID, from, to)
	default:
		return []store.Sample{}, nil
	}
}

func (d *DB) loadCPU(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, cpu, usage_user, usage_system, usage_idle, usage_iowait
FROM metrics.host_cpu
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var cpu string
		var user, system, idle, iowait *float64
		if err := rows.Scan(&t, &cpu, &user, &system, &idle, &iowait); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "cpu", t)
		s.Tags["cpu"] = cpu
		putFloat(s.Floats, "usage_user", user)
		putFloat(s.Floats, "usage_system", system)
		putFloat(s.Floats, "usage_idle", idle)
		putFloat(s.Floats, "usage_iowait", iowait)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadMem(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, total, available, used, used_percent
FROM metrics.host_mem
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var total, available, used *int64
		var pct *float64
		if err := rows.Scan(&t, &total, &available, &used, &pct); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "mem", t)
		putInt(s.Ints, "total", total)
		putInt(s.Ints, "available", available)
		putInt(s.Ints, "used", used)
		putFloat(s.Floats, "used_percent", pct)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadDisk(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, path, fstype, total, used, free, used_percent
FROM metrics.host_disk
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var path, fstype string
		var total, used, free *int64
		var pct *float64
		if err := rows.Scan(&t, &path, &fstype, &total, &used, &free, &pct); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "disk", t)
		s.Tags["path"] = path
		s.Tags["fstype"] = fstype
		putInt(s.Ints, "total", total)
		putInt(s.Ints, "used", used)
		putInt(s.Ints, "free", free)
		putFloat(s.Floats, "used_percent", pct)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadDiskIO(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, name, read_bytes, write_bytes
FROM metrics.host_diskio
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var name string
		var readB, writeB *int64
		if err := rows.Scan(&t, &name, &readB, &writeB); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "diskio", t)
		s.Tags["name"] = name
		putInt(s.Ints, "read_bytes", readB)
		putInt(s.Ints, "write_bytes", writeB)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadNet(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, interface, bytes_recv, bytes_sent
FROM metrics.host_net
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var iface string
		var recv, sent *int64
		if err := rows.Scan(&t, &iface, &recv, &sent); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "net", t)
		s.Tags["interface"] = iface
		putInt(s.Ints, "bytes_recv", recv)
		putInt(s.Ints, "bytes_sent", sent)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadSystem(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, load1, load5, load15, uptime, n_cpus
FROM metrics.host_system
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var load1, load5, load15 *float64
		var uptime *int64
		var ncpus *int32
		if err := rows.Scan(&t, &load1, &load5, &load15, &uptime, &ncpus); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "system", t)
		putFloat(s.Floats, "load1", load1)
		putFloat(s.Floats, "load5", load5)
		putFloat(s.Floats, "load15", load15)
		putInt(s.Ints, "uptime", uptime)
		putInt32(s.Ints, "n_cpus", ncpus)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadTemp(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, sensor, celsius
FROM metrics.host_temp
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var sensor string
		var celsius *float64
		if err := rows.Scan(&t, &sensor, &celsius); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "temp", t)
		s.Tags["sensor"] = sensor
		putFloat(s.Floats, "celsius", celsius)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadProcess(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, service_id::text, pid, process_name, "user", cmdline,
       cpu_usage, memory_rss, memory_usage, num_threads, started_at
FROM metrics.process_samples
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var serviceText *string
		var pid int32
		var name, user, cmdline string
		var cpu, mem *float64
		var rss *int64
		var threads *int32
		var started *time.Time
		if err := rows.Scan(&t, &serviceText, &pid, &name, &user, &cmdline, &cpu, &rss, &mem, &threads, &started); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "process", t)
		if s.ServiceID, err = parseOptID(serviceText); err != nil {
			return nil, err
		}
		s.Tags["pid"] = strconv.Itoa(int(pid))
		s.Tags["process_name"] = name
		s.Tags["user"] = user
		s.Tags["cmdline"] = cmdline
		putFloat(s.Floats, "cpu_usage", cpu)
		putInt(s.Ints, "memory_rss", rss)
		putFloat(s.Floats, "memory_usage", mem)
		putInt32(s.Ints, "num_threads", threads)
		if started != nil {
			s.Strs["started_at"] = started.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) loadHealth(ctx context.Context, hostID uuid.UUID, from, to time.Time) ([]store.Sample, error) {
	rows, err := d.pool.Query(ctx, `
SELECT time, service_id::text, check_id::text, protocol, port, result, http_status, latency_ms
FROM metrics.health_results
WHERE host_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time ASC
`, hostID.String(), from, to)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Sample{}
	for rows.Next() {
		var t time.Time
		var serviceText, checkText, protocol, result *string
		var port, httpStatus *int32
		var latency *float64
		if err := rows.Scan(&t, &serviceText, &checkText, &protocol, &port, &result, &httpStatus, &latency); err != nil {
			return nil, mapErr(err)
		}
		s := newSample(hostID, "health", t)
		if s.ServiceID, err = parseOptID(serviceText); err != nil {
			return nil, err
		}
		if checkText != nil {
			s.Tags["check_id"] = *checkText
		}
		if protocol != nil {
			s.Tags["protocol"] = *protocol
		}
		if port != nil {
			s.Tags["port"] = strconv.Itoa(int(*port))
		}
		if result != nil {
			s.Strs["result"] = *result
		}
		if httpStatus == nil {
			s.Nulls["http_status"] = true
		} else {
			s.Ints["http_status"] = int64(*httpStatus)
		}
		putFloat(s.Floats, "latency_ms", latency)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func newSample(hostID uuid.UUID, measurement string, t time.Time) store.Sample {
	return store.Sample{
		HostID: hostID,
		M:      measurement,
		T:      t,
		Tags:   map[string]string{},
		Floats: map[string]float64{},
		Ints:   map[string]int64{},
		Strs:   map[string]string{},
		Nulls:  map[string]bool{},
	}
}

func putFloat(m map[string]float64, key string, v *float64) {
	if v != nil {
		m[key] = *v
	}
}

func putInt(m map[string]int64, key string, v *int64) {
	if v != nil {
		m[key] = *v
	}
}

func putInt32(m map[string]int64, key string, v *int32) {
	if v != nil {
		m[key] = int64(*v)
	}
}

func (d *DB) LatestProcesses(ctx context.Context, hostID uuid.UUID, since time.Time, sortKey string, limit int) (*time.Time, []store.ProcessItem, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	if sortKey != "memory" {
		sortKey = "cpu"
	}
	var maxT *time.Time
	if err := d.pool.QueryRow(ctx, `
SELECT max(time) FROM metrics.process_samples
WHERE host_id = $1::uuid AND time >= $2
`, hostID.String(), since).Scan(&maxT); err != nil {
		return nil, nil, mapErr(err)
	}
	if maxT == nil {
		return nil, []store.ProcessItem{}, nil
	}
	window := maxT.Add(-2 * time.Second)
	rows, err := d.pool.Query(ctx, `
SELECT pid, process_name, "user", cmdline, service_id::text,
       cpu_usage, memory_rss, memory_usage, num_threads, started_at
FROM (
    SELECT DISTINCT ON (pid)
           pid, process_name, "user", cmdline, service_id,
           cpu_usage, memory_rss, memory_usage, num_threads, started_at, time
    FROM metrics.process_samples
    WHERE host_id = $1::uuid AND time >= $2 AND time <= $3
    ORDER BY pid, time DESC
) latest
ORDER BY
    CASE WHEN $4 = 'memory' THEN memory_rss END DESC NULLS LAST,
    CASE WHEN $4 <> 'memory' THEN cpu_usage END DESC NULLS LAST,
    pid
LIMIT $5
`, hostID.String(), window, *maxT, sortKey, limit)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.ProcessItem{}
	for rows.Next() {
		var item store.ProcessItem
		var pid int32
		var serviceText *string
		var cpu, mem *float64
		var rss *int64
		var threads *int32
		if err := rows.Scan(&pid, &item.ProcessName, &item.User, &item.Cmdline, &serviceText, &cpu, &rss, &mem, &threads, &item.StartedAt); err != nil {
			return nil, nil, mapErr(err)
		}
		item.PID = int(pid)
		if item.ServiceID, err = parseOptID(serviceText); err != nil {
			return nil, nil, err
		}
		item.CPUUsage = floatOrZero(cpu)
		if rss != nil {
			item.MemoryRSS = *rss
		}
		item.MemoryUsage = floatOrZero(mem)
		if threads != nil {
			item.NumThreads = int(*threads)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return maxT, items, nil
}

func (d *DB) HealthHistory(ctx context.Context, serviceID uuid.UUID, from, to time.Time, limit int) ([]store.HealthPoint, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := d.pool.Query(ctx, `
SELECT time, check_id::text, protocol, port, result, http_status, latency_ms
FROM metrics.health_results
WHERE service_id = $1::uuid AND time >= $2 AND time < $3
ORDER BY time DESC
LIMIT $4
`, serviceID.String(), from, to, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.HealthPoint{}
	for rows.Next() {
		var p store.HealthPoint
		var checkText, protocol, result *string
		var port *int32
		var httpStatus *int32
		var latency *float64
		if err := rows.Scan(&p.T, &checkText, &protocol, &port, &result, &httpStatus, &latency); err != nil {
			return nil, mapErr(err)
		}
		if checkText != nil {
			id, err := parseID(*checkText)
			if err != nil {
				return nil, err
			}
			p.CheckID = &id
		}
		if protocol != nil {
			p.Protocol = *protocol
		}
		if port != nil {
			n := int(*port)
			p.Port = &n
		}
		if result != nil {
			p.Result = *result
		}
		if httpStatus != nil {
			n := int(*httpStatus)
			p.HTTPStatus = &n
		}
		p.LatencyMS = latency
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) InsertAudit(ctx context.Context, row store.AuditRow) error {
	if err := exec(ctx, d.pool, `
INSERT INTO app.audit_log (
    at, actor_user_id, via, project_id, host_id, service_id,
    action, decision, task_id, result, error_code, detail
) VALUES (
    $1, $2::uuid, $3, $4::uuid, $5::uuid, $6::uuid,
    $7, $8, $9::uuid, $10, $11, $12::jsonb
)
`, row.At, optUUID(row.ActorUserID), row.Via, optUUID(row.ProjectID), optUUID(row.HostID), optUUID(row.ServiceID),
		row.Action, row.Decision, optUUID(row.TaskID), optString(row.Result), optString(row.ErrorCode), auditDetail(row.Detail)); err != nil {
		return mapErr(err)
	}
	return nil
}

func auditDetail(detail map[string]any) []byte {
	if detail == nil {
		return []byte(`{}`)
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return []byte(`{}`)
	}
	return raw
}

func (d *DB) ListAudit(ctx context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.AuditEntry, *store.Cursor, error) {
	lim := pageLimit(limit)
	hasCursor := cursor != nil
	var cursorAt time.Time
	var cursorID int64
	if cursor != nil {
		cursorAt = cursor.At
		cursorID, _ = strconv.ParseInt(cursor.ID, 10, 64)
	}
	rows, err := d.pool.Query(ctx, `
SELECT id, at, actor_user_id::text, via, project_id::text, host_id::text, service_id::text,
       action, decision, task_id::text, result, error_code, detail
FROM app.audit_log
WHERE project_id = $1::uuid
  AND ($2::boolean = false OR (at, id) < ($3::timestamptz, $4::bigint))
ORDER BY at DESC, id DESC
LIMIT $5
`, projectID.String(), hasCursor, cursorAt, cursorID, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.AuditEntry{}
	for rows.Next() {
		var entry store.AuditEntry
		var id int64
		var actor, project, host, service, task *string
		var detail []byte
		if err := rows.Scan(
			&id, &entry.At, &actor, &entry.Via, &project, &host, &service,
			&entry.Action, &entry.Decision, &task, &entry.Result, &entry.ErrorCode, &detail,
		); err != nil {
			return nil, nil, mapErr(err)
		}
		entry.ID = strconv.FormatInt(id, 10)
		if entry.ActorUserID, err = parseOptID(actor); err != nil {
			return nil, nil, err
		}
		if entry.ProjectID, err = parseOptID(project); err != nil {
			return nil, nil, err
		}
		if entry.HostID, err = parseOptID(host); err != nil {
			return nil, nil, err
		}
		if entry.ServiceID, err = parseOptID(service); err != nil {
			return nil, nil, err
		}
		if entry.TaskID, err = parseOptID(task); err != nil {
			return nil, nil, err
		}
		if detail == nil {
			detail = []byte(`{}`)
		}
		entry.Detail = json.RawMessage(detail)
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return cutPage(items, lim, func(a store.AuditEntry) time.Time { return a.At }, func(a store.AuditEntry) string { return a.ID })
}
