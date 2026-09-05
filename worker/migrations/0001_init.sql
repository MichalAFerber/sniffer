-- LAN map produced by netmapd. Times are ISO-8601 TEXT (UTC).
-- Empty string, not NULL, for optional MAC/IP so UNIQUE works in SQLite.

CREATE TABLE sensors (
  id         TEXT PRIMARY KEY,
  hostname   TEXT NOT NULL DEFAULT '',
  os         TEXT NOT NULL DEFAULT '',
  arch       TEXT NOT NULL DEFAULT '',
  version    TEXT NOT NULL DEFAULT '',
  iface      TEXT NOT NULL DEFAULT '',
  last_seen  TEXT NOT NULL,
  hosts      INTEGER NOT NULL DEFAULT 0,
  services   INTEGER NOT NULL DEFAULT 0,
  flows      INTEGER NOT NULL DEFAULT 0,
  names      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE hosts (
  sensor_id  TEXT NOT NULL,
  mac        TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  ipv6       TEXT NOT NULL DEFAULT '',
  hostname   TEXT NOT NULL DEFAULT '',
  vendor     TEXT NOT NULL DEFAULT '',
  sources    TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (sensor_id, mac, ip)
);

CREATE INDEX idx_hosts_last ON hosts (last_seen);
CREATE INDEX idx_hosts_ip ON hosts (ip);

CREATE TABLE services (
  sensor_id  TEXT NOT NULL,
  ip         TEXT NOT NULL,
  port       INTEGER NOT NULL,
  proto      TEXT NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  banner     TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (sensor_id, ip, port, proto)
);

CREATE INDEX idx_services_ip ON services (ip);

CREATE TABLE flows (
  sensor_id    TEXT NOT NULL,
  src_ip       TEXT NOT NULL,
  dst_ip       TEXT NOT NULL,
  src_port     INTEGER NOT NULL DEFAULT 0,
  dst_port     INTEGER NOT NULL DEFAULT 0,
  proto        TEXT NOT NULL,
  packets      INTEGER NOT NULL DEFAULT 0,
  bytes        INTEGER NOT NULL DEFAULT 0,
  window_start TEXT NOT NULL,
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  PRIMARY KEY (sensor_id, src_ip, dst_ip, src_port, dst_port, proto, window_start)
);

CREATE INDEX idx_flows_window ON flows (window_start);

CREATE TABLE names (
  sensor_id  TEXT NOT NULL,
  qname      TEXT NOT NULL,
  qtype      TEXT NOT NULL DEFAULT '',
  answer     TEXT NOT NULL DEFAULT '',
  client_ip  TEXT NOT NULL DEFAULT '',
  count      INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (sensor_id, qname, qtype, answer)
);

CREATE INDEX idx_names_qname ON names (qname);

CREATE TABLE ingest_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  sensor_id     TEXT NOT NULL,
  received_at   TEXT NOT NULL,
  host_count    INTEGER NOT NULL DEFAULT 0,
  service_count INTEGER NOT NULL DEFAULT 0,
  flow_count    INTEGER NOT NULL DEFAULT 0,
  name_count    INTEGER NOT NULL DEFAULT 0
);
