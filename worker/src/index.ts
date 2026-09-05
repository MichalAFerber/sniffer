const MAX_BODY = 1_048_576;
const BATCH_CHUNK = 200;

type Sensor = {
  id: string;
  hostname?: string;
  os?: string;
  arch?: string;
  version?: string;
  iface?: string;
};

type Host = {
  mac?: string;
  ip?: string;
  ipv6?: string;
  hostname?: string;
  vendor?: string;
  sources?: string[];
  first_seen: string;
  last_seen: string;
};

type Service = {
  ip: string;
  port: number;
  proto: string;
  name?: string;
  banner?: string;
  first_seen: string;
  last_seen: string;
};

type Flow = {
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  proto: string;
  packets: number;
  bytes: number;
  window_start: string;
  first_seen: string;
  last_seen: string;
};

type Name = {
  qname: string;
  qtype?: string;
  answer?: string;
  client_ip?: string;
  count: number;
  first_seen: string;
  last_seen: string;
};

type Batch = {
  sensor: Sensor;
  sent_at?: string;
  hosts?: Host[];
  services?: Service[];
  flows?: Flow[];
  names?: Name[];
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await handle(request, env, ctx);
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown";
      console.error(JSON.stringify({ message: "unhandled", error: message }));
      return json({ error: "internal" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;

async function handle(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/health") {
    return json({ ok: true, service: "sniffer" });
  }

  const tokenOK = await authorized(request, env);
  if (!tokenOK) {
    return json({ error: "unauthorized" }, 401);
  }

  if (request.method === "POST" && url.pathname === "/v1/ingest") {
    return ingest(request, env);
  }
  if (request.method === "POST" && url.pathname === "/v1/heartbeat") {
    return heartbeat(request, env);
  }
  if (request.method === "GET" && url.pathname === "/v1/hosts") {
    return listHosts(env, url);
  }
  if (request.method === "GET" && url.pathname === "/v1/services") {
    return listServices(env, url);
  }
  if (request.method === "GET" && url.pathname === "/v1/map") {
    return networkMap(env, url);
  }
  return json({ error: "not found" }, 404);
}

async function authorized(request: Request, env: Env): Promise<boolean> {
  const expected = env.INGEST_TOKEN;
  if (!expected) {
    return false;
  }
  const hdr = request.headers.get("Authorization") ?? "";
  const provided = hdr.toLowerCase().startsWith("bearer ") ? hdr.slice(7) : hdr;
  return timingEqual(provided, expected);
}

async function timingEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

async function ingest(request: Request, env: Env): Promise<Response> {
  const len = Number(request.headers.get("content-length") ?? "0");
  if (len > MAX_BODY) {
    return json({ error: "payload too large" }, 413);
  }
  const raw = await request.arrayBuffer();
  if (raw.byteLength > MAX_BODY) {
    return json({ error: "payload too large" }, 413);
  }
  let batch: Batch;
  try {
    batch = JSON.parse(new TextDecoder().decode(raw)) as Batch;
  } catch {
    return json({ error: "invalid json" }, 400);
  }
  if (!batch.sensor?.id) {
    return json({ error: "sensor.id required" }, 400);
  }
  const sid = batch.sensor.id;
  const now = new Date().toISOString();
  const stmts: D1PreparedStatement[] = [];

  stmts.push(
    env.DB.prepare(
      `INSERT INTO sensors (id, hostname, os, arch, version, iface, last_seen, hosts, services, flows, names)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
         version=excluded.version, iface=excluded.iface, last_seen=excluded.last_seen,
         hosts=excluded.hosts, services=excluded.services, flows=excluded.flows, names=excluded.names`,
    ).bind(
      sid,
      batch.sensor.hostname ?? "",
      batch.sensor.os ?? "",
      batch.sensor.arch ?? "",
      batch.sensor.version ?? "",
      batch.sensor.iface ?? "",
      now,
      batch.hosts?.length ?? 0,
      batch.services?.length ?? 0,
      batch.flows?.length ?? 0,
      batch.names?.length ?? 0,
    ),
  );

  for (const h of batch.hosts ?? []) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO hosts (sensor_id, mac, ip, ipv6, hostname, vendor, sources, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(sensor_id, mac, ip) DO UPDATE SET
           ipv6=CASE WHEN excluded.ipv6!='' THEN excluded.ipv6 ELSE hosts.ipv6 END,
           hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hosts.hostname END,
           vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE hosts.vendor END,
           sources=excluded.sources,
           last_seen=excluded.last_seen,
           first_seen=MIN(hosts.first_seen, excluded.first_seen)`,
      ).bind(
        sid,
        h.mac ?? "",
        h.ip ?? "",
        h.ipv6 ?? "",
        h.hostname ?? "",
        h.vendor ?? "",
        JSON.stringify(h.sources ?? []),
        h.first_seen,
        h.last_seen,
      ),
    );
  }
  for (const s of batch.services ?? []) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO services (sensor_id, ip, port, proto, name, banner, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(sensor_id, ip, port, proto) DO UPDATE SET
           name=CASE WHEN excluded.name!='' THEN excluded.name ELSE services.name END,
           banner=CASE WHEN excluded.banner!='' THEN excluded.banner ELSE services.banner END,
           last_seen=excluded.last_seen,
           first_seen=MIN(services.first_seen, excluded.first_seen)`,
      ).bind(sid, s.ip, s.port, s.proto, s.name ?? "", s.banner ?? "", s.first_seen, s.last_seen),
    );
  }
  for (const f of batch.flows ?? []) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO flows (sensor_id, src_ip, dst_ip, src_port, dst_port, proto, packets, bytes, window_start, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(sensor_id, src_ip, dst_ip, src_port, dst_port, proto, window_start) DO UPDATE SET
           packets=flows.packets + excluded.packets,
           bytes=flows.bytes + excluded.bytes,
           last_seen=excluded.last_seen`,
      ).bind(
        sid,
        f.src_ip,
        f.dst_ip,
        f.src_port ?? 0,
        f.dst_port ?? 0,
        f.proto,
        f.packets,
        f.bytes,
        f.window_start,
        f.first_seen,
        f.last_seen,
      ),
    );
  }
  for (const n of batch.names ?? []) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO names (sensor_id, qname, qtype, answer, client_ip, count, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(sensor_id, qname, qtype, answer) DO UPDATE SET
           count=names.count + excluded.count,
           last_seen=excluded.last_seen,
           client_ip=CASE WHEN excluded.client_ip!='' THEN excluded.client_ip ELSE names.client_ip END`,
      ).bind(
        sid,
        n.qname,
        n.qtype ?? "",
        n.answer ?? "",
        n.client_ip ?? "",
        n.count,
        n.first_seen,
        n.last_seen,
      ),
    );
  }
  stmts.push(
    env.DB.prepare(
      `INSERT INTO ingest_log (sensor_id, received_at, host_count, service_count, flow_count, name_count)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      sid,
      now,
      batch.hosts?.length ?? 0,
      batch.services?.length ?? 0,
      batch.flows?.length ?? 0,
      batch.names?.length ?? 0,
    ),
  );

  for (let i = 0; i < stmts.length; i += BATCH_CHUNK) {
    await env.DB.batch(stmts.slice(i, i + BATCH_CHUNK));
  }
  console.log(
    JSON.stringify({
      message: "ingest",
      sensor: sid,
      hosts: batch.hosts?.length ?? 0,
      services: batch.services?.length ?? 0,
      flows: batch.flows?.length ?? 0,
      names: batch.names?.length ?? 0,
    }),
  );
  return new Response(null, { status: 204 });
}

async function heartbeat(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as {
    sensor?: Sensor;
    hosts?: number;
    services?: number;
    flows?: number;
    names?: number;
  };
  if (!body.sensor?.id) {
    return json({ error: "sensor.id required" }, 400);
  }
  const s = body.sensor;
  await env.DB.prepare(
    `INSERT INTO sensors (id, hostname, os, arch, version, iface, last_seen, hosts, services, flows, names)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
       version=excluded.version, iface=excluded.iface, last_seen=excluded.last_seen,
       hosts=excluded.hosts, services=excluded.services, flows=excluded.flows, names=excluded.names`,
  )
    .bind(
      s.id,
      s.hostname ?? "",
      s.os ?? "",
      s.arch ?? "",
      s.version ?? "",
      s.iface ?? "",
      new Date().toISOString(),
      body.hosts ?? 0,
      body.services ?? 0,
      body.flows ?? 0,
      body.names ?? 0,
    )
    .run();
  return new Response(null, { status: 204 });
}

async function listHosts(env: Env, url: URL): Promise<Response> {
  const sensor = url.searchParams.get("sensor");
  const sql = sensor
    ? `SELECT * FROM hosts WHERE sensor_id = ? ORDER BY last_seen DESC LIMIT 500`
    : `SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 500`;
  const stmt = sensor ? env.DB.prepare(sql).bind(sensor) : env.DB.prepare(sql);
  const { results } = await stmt.all();
  return json({ hosts: results });
}

async function listServices(env: Env, url: URL): Promise<Response> {
  const sensor = url.searchParams.get("sensor");
  const sql = sensor
    ? `SELECT * FROM services WHERE sensor_id = ? ORDER BY last_seen DESC LIMIT 500`
    : `SELECT * FROM services ORDER BY last_seen DESC LIMIT 500`;
  const stmt = sensor ? env.DB.prepare(sql).bind(sensor) : env.DB.prepare(sql);
  const { results } = await stmt.all();
  return json({ services: results });
}

async function networkMap(env: Env, url: URL): Promise<Response> {
  const sensor = url.searchParams.get("sensor");
  const hostSQL = sensor
    ? `SELECT * FROM hosts WHERE sensor_id = ? ORDER BY last_seen DESC LIMIT 500`
    : `SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 500`;
  const svcSQL = sensor
    ? `SELECT * FROM services WHERE sensor_id = ? ORDER BY last_seen DESC LIMIT 500`
    : `SELECT * FROM services ORDER BY last_seen DESC LIMIT 500`;
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const flowSQL = sensor
    ? `SELECT src_ip, dst_ip, proto, SUM(packets) AS packets, SUM(bytes) AS bytes
       FROM flows WHERE sensor_id = ? AND window_start >= ?
       GROUP BY src_ip, dst_ip, proto LIMIT 1000`
    : `SELECT src_ip, dst_ip, proto, SUM(packets) AS packets, SUM(bytes) AS bytes
       FROM flows WHERE window_start >= ?
       GROUP BY src_ip, dst_ip, proto LIMIT 1000`;
  const sensorSQL = `SELECT * FROM sensors ORDER BY last_seen DESC`;
  const hostStmt = sensor ? env.DB.prepare(hostSQL).bind(sensor) : env.DB.prepare(hostSQL);
  const svcStmt = sensor ? env.DB.prepare(svcSQL).bind(sensor) : env.DB.prepare(svcSQL);
  const flowStmt = sensor ? env.DB.prepare(flowSQL).bind(sensor, since) : env.DB.prepare(flowSQL).bind(since);
  const [hosts, services, edges, sensors] = await env.DB.batch([
    hostStmt,
    svcStmt,
    flowStmt,
    env.DB.prepare(sensorSQL),
  ]);
  return json({
    sensors: sensors.results,
    hosts: hosts.results,
    services: services.results,
    edges: edges.results,
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
