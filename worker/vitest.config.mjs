import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsPath = path.join(__dirname, "migrations");
const migrations = await readD1Migrations(migrationsPath);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
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
