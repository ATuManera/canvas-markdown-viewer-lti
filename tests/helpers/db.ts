import { randomBytes } from 'node:crypto';
import { createPool, type DbPool } from '../../src/db/pool.ts';
import { migrate } from '../../src/db/migrations.ts';
import { KeyRing } from '../../src/crypto/envelope.ts';

/**
 * Integration tests need a real PostgreSQL: the behaviour under test — `DELETE ...
 * RETURNING` serialising two callers, `SELECT ... FOR UPDATE` blocking a second
 * transaction — is the database's, and a fake would only test the fake.
 *
 * They run when `TEST_DATABASE_URL` is set, and are skipped otherwise so that a clone
 * without a database still has a green suite. CI sets it.
 */
export const TEST_DATABASE_URL = process.env['TEST_DATABASE_URL'];
export const hasDatabase = Boolean(TEST_DATABASE_URL);

/**
 * Each test file asks for its own schema, so files running in parallel cannot truncate
 * one another's rows. The schema is recreated from scratch at the start of the file.
 */
export async function setupDatabase(schema: string): Promise<DbPool> {
  if (!TEST_DATABASE_URL) throw new Error('TEST_DATABASE_URL is not set');

  const admin = createPool({ connectionString: TEST_DATABASE_URL, max: 1 });
  try {
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.query(`CREATE SCHEMA ${schema}`);
  } finally {
    await admin.end();
  }

  const pool = createPool({ connectionString: TEST_DATABASE_URL, max: 6, schema });
  await migrate(pool);
  return pool;
}

export async function truncateAll(pool: DbPool): Promise<void> {
  await pool.query('TRUNCATE launch_states, used_nonces, oauth_flows, canvas_tokens, tool_keys');
}

export function testKeyRing(...versions: string[]): KeyRing {
  const entries = (versions.length > 0 ? versions : ['1']).map((version) => ({
    version,
    key: randomBytes(32),
  }));
  return new KeyRing(entries);
}

/** Distinct owners per test, so one test's rows cannot satisfy another's assertion. */
export function uniqueBinding(label = 'user') {
  const suffix = randomBytes(6).toString('hex');
  return {
    issuer: 'https://canvas.test.edu',
    deploymentId: `1:deployment-${suffix}`,
    subject: `${label}-${suffix}`,
  };
}
