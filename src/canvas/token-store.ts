import { open, rewrap, seal, sealedKeyVersion, type KeyRing } from '../crypto/envelope.ts';
import type { SecretBinding } from '../crypto/envelope.ts';
import { withTransaction, type DbClient, type DbPool } from '../db/pool.ts';

/**
 * Storage for the users' Canvas refresh tokens.
 *
 * Tokens are held sealed (see `src/crypto/envelope.ts`) and are bound cryptographically to
 * the triple that owns them, so this class never handles a plaintext token outside the
 * narrow window between `open` and the HTTP call that uses it.
 *
 * Refreshes are serialised per owner with `SELECT ... FOR UPDATE`. Without it, two requests
 * arriving together would both call Canvas; with a platform that rotates refresh tokens
 * — Canvas does not today, but a compatible one might — the slower of the two would then
 * persist a token the platform had already invalidated.
 */

export interface StoredToken {
  readonly refreshToken: string;
  readonly scope: string | undefined;
  readonly keyVersion: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly refreshedAt: Date | undefined;
}

interface TokenRow {
  sealed_token: string;
  key_version: string;
  scope: string | null;
  created_at: Date;
  updated_at: Date;
  refreshed_at: Date | null;
}

export class TokenStore {
  constructor(
    private readonly pool: DbPool,
    private readonly keyRing: KeyRing,
  ) {}

  /**
   * Stores a refresh token, replacing any the user already had for this deployment.
   * The primary key is (issuer, deployment, subject), so a user cannot accumulate
   * credentials for the same place.
   */
  async save(binding: SecretBinding, refreshToken: string, scope?: string): Promise<void> {
    const sealed = seal(refreshToken, binding, this.keyRing);
    await this.pool.query(
      `INSERT INTO canvas_tokens
         (issuer, deployment_id, subject, sealed_token, key_version, scope)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (issuer, deployment_id, subject) DO UPDATE
         SET sealed_token = EXCLUDED.sealed_token,
             key_version  = EXCLUDED.key_version,
             scope        = EXCLUDED.scope,
             updated_at   = now()`,
      [
        binding.issuer,
        binding.deploymentId,
        binding.subject,
        sealed,
        this.keyRing.activeVersion,
        scope ?? null,
      ],
    );
  }

  /** Returns the stored token, opened. `undefined` when the user has not authorised yet. */
  async load(binding: SecretBinding): Promise<StoredToken | undefined> {
    const { rows } = await this.pool.query<TokenRow>(
      `SELECT sealed_token, key_version, scope, created_at, updated_at, refreshed_at
         FROM canvas_tokens
        WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
      [binding.issuer, binding.deploymentId, binding.subject],
    );
    const row = rows[0];
    return row ? toStoredToken(row, binding, this.keyRing) : undefined;
  }

  async has(binding: SecretBinding): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT 1 FROM canvas_tokens WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
      [binding.issuer, binding.deploymentId, binding.subject],
    );
    return rows.length > 0;
  }

  /**
   * Deletes the user's token. Idempotent; returns whether a row was actually removed, so a
   * caller can tell "revoked" from "there was nothing to revoke".
   */
  async revoke(binding: SecretBinding): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM canvas_tokens WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
      [binding.issuer, binding.deploymentId, binding.subject],
    );
    return (rowCount ?? 0) > 0;
  }

  /** Deletes every token for one Canvas instance. For decommissioning an integration. */
  async revokeIssuer(issuer: string): Promise<number> {
    const { rowCount } = await this.pool.query(`DELETE FROM canvas_tokens WHERE issuer = $1`, [
      issuer,
    ]);
    return rowCount ?? 0;
  }

  /**
   * Holds an exclusive lock on the owner's row for the duration of `fn`, so only one
   * refresh for that user is ever in flight against the database.
   *
   * `fn` receives the current token and returns the one to store. Returning `undefined`
   * keeps what is already there — the correct behaviour when a platform answers a refresh
   * without supplying a replacement, as Canvas does.
   */
  async withRefreshLock<T>(
    binding: SecretBinding,
    fn: (current: StoredToken) => Promise<{ refreshToken?: string | undefined; result: T }>,
  ): Promise<T> {
    return withTransaction(this.pool, async (client: DbClient) => {
      const { rows } = await client.query<TokenRow>(
        `SELECT sealed_token, key_version, scope, created_at, updated_at, refreshed_at
           FROM canvas_tokens
          WHERE issuer = $1 AND deployment_id = $2 AND subject = $3
          FOR UPDATE`,
        [binding.issuer, binding.deploymentId, binding.subject],
      );

      const row = rows[0];
      if (!row) throw new MissingTokenError();

      const current = toStoredToken(row, binding, this.keyRing);
      const { refreshToken, result } = await fn(current);

      if (refreshToken !== undefined && refreshToken !== current.refreshToken) {
        // A platform that rotates refresh tokens handed us a replacement.
        await client.query(
          `UPDATE canvas_tokens
              SET sealed_token = $4, key_version = $5, updated_at = now(), refreshed_at = now()
            WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
          [
            binding.issuer,
            binding.deploymentId,
            binding.subject,
            seal(refreshToken, binding, this.keyRing),
            this.keyRing.activeVersion,
          ],
        );
      } else {
        await client.query(
          `UPDATE canvas_tokens
              SET refreshed_at = now()
            WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
          [binding.issuer, binding.deploymentId, binding.subject],
        );
      }

      return result;
    });
  }

  /**
   * Re-seals one user's token under the active key. Part of a key rotation: add the new
   * key, make it active, re-wrap, then drop the old key from the ring.
   */
  async rewrapOne(binding: SecretBinding): Promise<boolean> {
    return withTransaction(this.pool, async (client) => {
      const { rows } = await client.query<Pick<TokenRow, 'sealed_token'>>(
        `SELECT sealed_token FROM canvas_tokens
          WHERE issuer = $1 AND deployment_id = $2 AND subject = $3
          FOR UPDATE`,
        [binding.issuer, binding.deploymentId, binding.subject],
      );
      const row = rows[0];
      if (!row) return false;

      const resealed = rewrap(row.sealed_token, binding, this.keyRing);
      if (!resealed) return false;

      await client.query(
        `UPDATE canvas_tokens
            SET sealed_token = $4, key_version = $5, updated_at = now()
          WHERE issuer = $1 AND deployment_id = $2 AND subject = $3`,
        [
          binding.issuer,
          binding.deploymentId,
          binding.subject,
          resealed,
          this.keyRing.activeVersion,
        ],
      );
      return true;
    });
  }

  /** Owners whose token is still sealed under a key other than the active one. */
  async listStale(limit = 100): Promise<SecretBinding[]> {
    const { rows } = await this.pool.query<{
      issuer: string;
      deployment_id: string;
      subject: string;
    }>(
      `SELECT issuer, deployment_id, subject
         FROM canvas_tokens
        WHERE key_version <> $1
        LIMIT $2`,
      [this.keyRing.activeVersion, limit],
    );
    return rows.map((row) => ({
      issuer: row.issuer,
      deploymentId: row.deployment_id,
      subject: row.subject,
    }));
  }
}

export class MissingTokenError extends Error {
  override readonly name = 'MissingTokenError';
  constructor() {
    super('no Canvas authorisation stored for this user');
  }
}

function toStoredToken(row: TokenRow, binding: SecretBinding, keyRing: KeyRing): StoredToken {
  return {
    refreshToken: open(row.sealed_token, binding, keyRing),
    scope: row.scope ?? undefined,
    keyVersion: sealedKeyVersion(row.sealed_token) ?? row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    refreshedAt: row.refreshed_at ?? undefined,
  };
}
