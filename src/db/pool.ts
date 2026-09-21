import pg from 'pg';

const { Pool } = pg;

export type DbPool = pg.Pool;
export type DbClient = pg.PoolClient;

export interface PoolOptions {
  readonly connectionString: string;
  readonly max?: number;
  readonly connectionTimeoutMillis?: number;
  readonly idleTimeoutMillis?: number;
  /**
   * PostgreSQL schema every connection is pinned to. Production leaves it unset and uses
   * `public`; the integration tests give each test file its own schema so two files
   * running in parallel cannot truncate each other's rows.
   */
  readonly schema?: string;
}

export function createPool(options: PoolOptions): DbPool {
  if (options.schema !== undefined && !/^[a-z_][a-z0-9_]*$/.test(options.schema)) {
    throw new Error(`invalid schema name: ${options.schema}`);
  }
  return new Pool({
    connectionString: options.connectionString,
    ...(options.schema === undefined ? {} : { options: `-c search_path=${options.schema}` }),
    max: options.max ?? 10,
    connectionTimeoutMillis: options.connectionTimeoutMillis ?? 5_000,
    idleTimeoutMillis: options.idleTimeoutMillis ?? 30_000,
    // `pg` would otherwise keep the process alive while idle connections linger.
    allowExitOnIdle: true,
  });
}

/**
 * Runs `fn` inside a transaction, committing on success and rolling back on any throw.
 * The client is always returned to the pool, including when the rollback itself fails.
 */
export async function withTransaction<T>(
  pool: DbPool,
  fn: (client: DbClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // The original error is the one worth reporting; a failed rollback usually means
      // the connection is already gone, and releasing it below will discard it.
    }
    throw error;
  } finally {
    client.release();
  }
}
