import type { Pool } from 'pg';

/**
 * Schema migrations.
 *
 * They are TypeScript constants rather than `.sql` files so that the compiled output is
 * self-contained: no build step has to remember to copy them, and no container image can
 * ship a binary whose migrations were left behind.
 *
 * Migrations are append-only. An applied migration is never edited; a correction is a new
 * entry. The SQL stays within PostgreSQL 12 syntax, which is the oldest version the
 * project supports.
 */

export interface Migration {
  readonly id: string;
  readonly sql: string;
}

export const MIGRATIONS: readonly Migration[] = [
  {
    id: '0001_initial',
    sql: /* sql */ `
      -- One row per OIDC login attempt. Consumed exactly once by the launch callback.
      CREATE TABLE launch_states (
        state           TEXT PRIMARY KEY,
        nonce           TEXT NOT NULL,
        issuer          TEXT NOT NULL,
        client_id       TEXT NOT NULL,
        target_link_uri TEXT,
        expires_at      TIMESTAMPTZ NOT NULL
      );
      CREATE INDEX launch_states_expires_at_idx ON launch_states (expires_at);

      -- Nonces already seen, so a captured id_token cannot be paired with a fresh state.
      CREATE TABLE used_nonces (
        issuer     TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (issuer, nonce)
      );
      CREATE INDEX used_nonces_expires_at_idx ON used_nonces (expires_at);

      -- One row per pending Canvas OAuth2 authorisation. Holds the PKCE verifier, sealed,
      -- and the launch context the callback must be tied back to.
      CREATE TABLE oauth_flows (
        state             TEXT PRIMARY KEY,
        sealed_verifier   TEXT NOT NULL,
        issuer            TEXT NOT NULL,
        client_id         TEXT NOT NULL,
        deployment_id     TEXT NOT NULL,
        subject           TEXT NOT NULL,
        canvas_course_id  TEXT,
        expires_at        TIMESTAMPTZ NOT NULL
      );
      CREATE INDEX oauth_flows_expires_at_idx ON oauth_flows (expires_at);

      -- One refresh token per (Canvas instance, deployment, user). The uniqueness is the
      -- primary key: a user cannot accumulate credentials for the same deployment.
      CREATE TABLE canvas_tokens (
        issuer        TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        subject       TEXT NOT NULL,
        sealed_token  TEXT NOT NULL,
        key_version   TEXT NOT NULL,
        scope         TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        refreshed_at  TIMESTAMPTZ,
        PRIMARY KEY (issuer, deployment_id, subject)
      );
      CREATE INDEX canvas_tokens_key_version_idx ON canvas_tokens (key_version);
    `,
  },
  {
    id: '0002_tool_keys',
    sql: /* sql */ `
      -- The tool's own key pair, published as a JWK Set. Canvas will not accept a
      -- developer key without one, even for a tool that calls no LTI Advantage service.
      CREATE TABLE tool_keys (
        kid            TEXT PRIMARY KEY,
        sealed_private TEXT NOT NULL,
        public_jwk     TEXT NOT NULL,
        active         BOOLEAN NOT NULL DEFAULT true,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX tool_keys_active_idx ON tool_keys (active, created_at DESC);
    `,
  },
];

const ADVISORY_LOCK_KEY = 8_271_553_019_447_216n % 9_223_372_036_854_775_807n;

/**
 * Applies any migration this database has not seen.
 *
 * A session-level advisory lock serialises the whole run, so several instances starting at
 * once cannot apply the same migration twice. Each migration runs in its own transaction:
 * one that fails leaves the ones before it applied and the schema in a known state.
 */
export async function migrate(pool: Pool): Promise<string[]> {
  const client = await pool.connect();
  const applied: string[] = [];

  try {
    await client.query('SELECT pg_advisory_lock($1)', [ADVISORY_LOCK_KEY.toString()]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id          TEXT PRIMARY KEY,
        applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const { rows } = await client.query<{ id: string }>('SELECT id FROM schema_migrations');
    const done = new Set(rows.map((row) => row.id));

    for (const migration of MIGRATIONS) {
      if (done.has(migration.id)) continue;
      await client.query('BEGIN');
      try {
        await client.query(migration.sql);
        await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [migration.id]);
        await client.query('COMMIT');
        applied.push(migration.id);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
    return applied;
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_KEY.toString()]);
    client.release();
  }
}
