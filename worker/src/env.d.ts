// Secrets are not in wrangler.jsonc. Merged with `wrangler types` Env.
interface Env {
  INGEST_TOKEN: string;
  // Optional: read-only bearer for the GET /v1/* routes. Unset means only
  // INGEST_TOKEN is accepted, so the Worker keeps working without it.
  READ_TOKEN?: string;
}
