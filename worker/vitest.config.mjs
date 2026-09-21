import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsPath = path.join(__dirname, "migrations");
const migrations = await readD1Migrations(migrationsPath);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // The workerd bundled with this vitest-pool-workers release trails
        // wrangler.jsonc's compatibility_date; pin the test runtime to what
        // it supports. Production still deploys with wrangler.jsonc's date.
        compatibilityDate: "2026-08-22",
        // Secrets (not in wrangler.jsonc — normally set via `wrangler secret put`).
        bindings: {
          INGEST_TOKEN: "test-ingest-token",
          READ_TOKEN: "test-read-token",
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  ],
});
