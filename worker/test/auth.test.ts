// Auth matrix for the two-token split (issue #10). One predicate must still
// run before routing (a stranger gets 401 everywhere and cannot enumerate
// routes), but it now returns a capability: INGEST_TOKEN admits everything,
// READ_TOKEN admits only the GET /v1/* routes, and a POST with READ_TOKEN
// must come back 401 — not 403, not 404 — so the response never reveals that
// the token was valid-but-insufficient.
//
// Runs against the real Worker in workerd (not a mock), because the token
// comparison uses crypto.subtle.timingSafeEqual, a workerd-only primitive
// plain Node does not implement.

import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, describe, expect, test } from "vitest";

const INGEST_TOKEN = "test-ingest-token";
const READ_TOKEN = "test-read-token";

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});

function req(method: string, path: string, token?: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (token !== undefined) {
    headers.Authorization = `Bearer ${token}`;
  }
  return new Request(`https://sniffer.test${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const READ_ROUTES = ["/v1/hosts", "/v1/services", "/v1/map"];
const WRITE_ROUTES: Array<[string, unknown]> = [
  ["/v1/ingest", { sensor: { id: "s1" }, hosts: [] }],
  ["/v1/heartbeat", { sensor: { id: "s1" } }],
];

test("/health stays open, no token", async () => {
  const res = await SELF.fetch(req("GET", "/health"));
  expect(res.status).toBe(200);
});

describe("INGEST_TOKEN admits every GET read route", () => {
  for (const path of READ_ROUTES) {
    test(path, async () => {
      const res = await SELF.fetch(req("GET", path, INGEST_TOKEN));
      expect(res.status).toBe(200);
    });
  }
});

describe("INGEST_TOKEN admits both write routes", () => {
  for (const [path, body] of WRITE_ROUTES) {
    test(path, async () => {
      const res = await SELF.fetch(req("POST", path, INGEST_TOKEN, body));
      expect(res.status).toBe(204);
    });
  }
});

describe("READ_TOKEN admits every GET read route", () => {
  for (const path of READ_ROUTES) {
    test(path, async () => {
      const res = await SELF.fetch(req("GET", path, READ_TOKEN));
      expect(res.status).toBe(200);
    });
  }
});

describe("READ_TOKEN is refused (401) on both write routes", () => {
  for (const [path, body] of WRITE_ROUTES) {
    test(path, async () => {
      const res = await SELF.fetch(req("POST", path, READ_TOKEN, body));
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "unauthorized" });
    });
  }
});

describe("a wrong token is refused everywhere", () => {
  for (const path of READ_ROUTES) {
    test(`GET ${path}`, async () => {
      const res = await SELF.fetch(req("GET", path, "wrong"));
      expect(res.status).toBe(401);
    });
  }
  for (const [path, body] of WRITE_ROUTES) {
    test(`POST ${path}`, async () => {
      const res = await SELF.fetch(req("POST", path, "wrong", body));
      expect(res.status).toBe(401);
    });
  }
});

describe("no token is refused everywhere", () => {
  for (const path of READ_ROUTES) {
    test(`GET ${path}`, async () => {
      const res = await SELF.fetch(req("GET", path));
      expect(res.status).toBe(401);
    });
  }
  for (const [path, body] of WRITE_ROUTES) {
    test(`POST ${path}`, async () => {
      const res = await SELF.fetch(req("POST", path, undefined, body));
      expect(res.status).toBe(401);
    });
  }
});

test("READ_TOKEN unset: INGEST_TOKEN alone still does everything", async () => {
  const savedRead = env.READ_TOKEN;
  // @ts-expect-error - simulating the secret being unset in production
  env.READ_TOKEN = undefined;
  try {
    for (const path of READ_ROUTES) {
      const res = await SELF.fetch(req("GET", path, INGEST_TOKEN));
      expect(res.status).toBe(200);
    }
    for (const [path, body] of WRITE_ROUTES) {
      const res = await SELF.fetch(req("POST", path, INGEST_TOKEN, body));
      expect(res.status).toBe(204);
    }
    // an unset READ_TOKEN never matches an absent bearer
    const res = await SELF.fetch(req("GET", "/v1/hosts"));
    expect(res.status).toBe(401);
  } finally {
    env.READ_TOKEN = savedRead;
  }
});
