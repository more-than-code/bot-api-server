-- Phase 1 metrics schema. TimescaleDB hypertables, 1-day chunks, 7-day raw retention.
-- Hourly continuous aggregates are intentionally not created in wave 1.
-- Schema metrics and the timescaledb extension are created by
-- migrations/roles.sql.example before this file. --migrate checks the
-- extension and does not create it.

-- Seen batch ids. Not a hypertable. Rows older than 48 h are deleted by the
-- API, which needs DELETE on this table only.
CREATE TABLE metrics.ingest_batches (
    host_id uuid NOT NULL REFERENCES app.hosts (id),
    batch_id uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, batch_id)
);

GRANT DELETE ON TABLE metrics.ingest_batches TO deploybot_api;

CREATE TABLE metrics.host_cpu (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    cpu text NOT NULL,
    usage_user double precision,
    usage_system double precision,
    usage_idle double precision,
    usage_iowait double precision
);

SELECT create_hypertable('metrics.host_cpu', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_cpu', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_cpu_host_time_idx ON metrics.host_cpu (host_id, time DESC);

CREATE TABLE metrics.host_mem (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    total bigint,
    available bigint,
    used bigint,
    used_percent double precision
);

SELECT create_hypertable('metrics.host_mem', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_mem', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_mem_host_time_idx ON metrics.host_mem (host_id, time DESC);

CREATE TABLE metrics.host_disk (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    path text NOT NULL,
    fstype text NOT NULL,
    total bigint,
    used bigint,
    free bigint,
    used_percent double precision
);

SELECT create_hypertable('metrics.host_disk', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_disk', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_disk_host_time_idx ON metrics.host_disk (host_id, time DESC);

CREATE TABLE metrics.host_diskio (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    name text NOT NULL,
    read_bytes bigint,
    write_bytes bigint
);

SELECT create_hypertable('metrics.host_diskio', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_diskio', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_diskio_host_time_idx ON metrics.host_diskio (host_id, time DESC);

CREATE TABLE metrics.host_net (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    interface text NOT NULL,
    bytes_recv bigint,
    bytes_sent bigint
);

SELECT create_hypertable('metrics.host_net', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_net', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_net_host_time_idx ON metrics.host_net (host_id, time DESC);

CREATE TABLE metrics.host_system (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    load1 double precision,
    load5 double precision,
    load15 double precision,
    uptime bigint,
    n_cpus integer
);

SELECT create_hypertable('metrics.host_system', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_system', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_system_host_time_idx ON metrics.host_system (host_id, time DESC);

CREATE TABLE metrics.host_temp (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    sensor text NOT NULL,
    celsius double precision
);

SELECT create_hypertable('metrics.host_temp', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.host_temp', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX host_temp_host_time_idx ON metrics.host_temp (host_id, time DESC);

CREATE TABLE metrics.process_samples (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    service_id uuid,
    pid integer NOT NULL,
    process_name text NOT NULL,
    "user" text NOT NULL,
    cmdline text NOT NULL,
    cpu_usage double precision,
    memory_rss bigint,
    memory_usage double precision,
    num_threads integer,
    started_at timestamptz
);

SELECT create_hypertable('metrics.process_samples', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.process_samples', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX process_samples_host_time_idx ON metrics.process_samples (host_id, time DESC);

CREATE TABLE metrics.health_results (
    time timestamptz NOT NULL,
    host_id uuid NOT NULL,
    service_id uuid,
    check_id uuid,
    protocol text,
    port integer,
    result text,
    http_status integer,
    latency_ms double precision
);

SELECT create_hypertable('metrics.health_results', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

SELECT add_retention_policy('metrics.health_results', INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX health_results_service_time_idx ON metrics.health_results (service_id, time DESC);

CREATE INDEX health_results_host_time_idx ON metrics.health_results (host_id, time DESC);
