import type { DbPool } from '../db/pool.ts';
import type { LaunchStateRecord, LaunchStateStore } from './state-store.ts';

/**
 * PostgreSQL implementation of {@link LaunchStateStore}.
 *
 * Unlike the in-memory store, this one survives a restart and is correct across several
 * instances — a launch that returns to a different process than the one that started it
 * still finds its state.
 */
export class PostgresLaunchStateStore implements LaunchStateStore {
  constructor(private readonly pool: DbPool) {}

  async create(record: LaunchStateRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO launch_states (state, nonce, issuer, client_id, target_link_uri, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        record.state,
        record.nonce,
        record.issuer,
        record.clientId,
        record.targetLinkUri ?? null,
        record.expiresAt,
      ],
    );
  }

  /**
   * `DELETE ... RETURNING` is the whole anti-replay mechanism: PostgreSQL serialises the
   * delete, so of two concurrent callers exactly one receives the row.
   */
  async consume(state: string): Promise<LaunchStateRecord | undefined> {
    const { rows } = await this.pool.query<{
      state: string;
      nonce: string;
      issuer: string;
      client_id: string;
      target_link_uri: string | null;
      expires_at: Date;
    }>(`DELETE FROM launch_states WHERE state = $1 RETURNING *`, [state]);

    const row = rows[0];
    if (!row) return undefined;
    if (row.expires_at.getTime() <= Date.now()) return undefined;

    return {
      state: row.state,
      nonce: row.nonce,
      issuer: row.issuer,
      clientId: row.client_id,
      targetLinkUri: row.target_link_uri ?? undefined,
      expiresAt: row.expires_at,
    };
  }

  /**
   * Inserts the nonce, or takes over a row whose memory window has already passed.
   * A live row means the nonce has been used, and the caller is looking at a replay.
   */
  async markNonceUsed(issuer: string, nonce: string, expiresAt: Date): Promise<boolean> {
    const { rows } = await this.pool.query(
      `INSERT INTO used_nonces (issuer, nonce, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (issuer, nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at
         WHERE used_nonces.expires_at <= now()
       RETURNING nonce`,
      [issuer, nonce, expiresAt],
    );
    return rows.length > 0;
  }

  async prune(now: Date = new Date()): Promise<void> {
    await this.pool.query('DELETE FROM launch_states WHERE expires_at <= $1', [now]);
    await this.pool.query('DELETE FROM used_nonces WHERE expires_at <= $1', [now]);
    await this.pool.query('DELETE FROM oauth_flows WHERE expires_at <= $1', [now]);
  }
}
