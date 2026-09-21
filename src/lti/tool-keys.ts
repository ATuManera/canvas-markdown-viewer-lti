import { randomUUID } from 'node:crypto';
import {
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importPKCS8,
  type JWK,
  type KeyObject,
} from 'jose';
import { open, seal, type KeyRing } from '../crypto/envelope.ts';
import type { DbPool } from '../db/pool.ts';

/**
 * The tool's own key pair, published as a JWK Set.
 *
 * Canvas requires a developer key to carry either `public_jwk` or `public_jwk_url`: it is
 * the key a tool would use for the `client_credentials` grant when calling LTI Advantage
 * services (Canvas `doc/api/lti_dev_key_config.md`).
 *
 * **This tool calls no LTI Advantage service.** It reads files through the Canvas REST API
 * with the user's own OAuth2 token, so the private key here is never used to sign anything
 * today. It exists because Canvas will not accept a registration without one, and because
 * having it means a future feature that does need AGS or NRPS costs no migration.
 *
 * The pair is generated once, on first start, and the private half is sealed with the same
 * envelope as the users' refresh tokens. Publishing a URL rather than the key itself means
 * a rotation reaches Canvas without anyone editing a developer key by hand.
 */

const BINDING = { issuer: 'tool', deploymentId: 'tool', subject: 'jwks' } as const;

export interface ToolKey {
  readonly kid: string;
  readonly publicJwk: JWK;
}

interface ToolKeyRow {
  kid: string;
  sealed_private: string;
  public_jwk: string;
}

/** Returns the active key, generating one the first time the tool starts. */
export async function ensureToolKey(pool: DbPool, keyRing: KeyRing): Promise<ToolKey> {
  const existing = await pool.query<ToolKeyRow>(
    'SELECT kid, sealed_private, public_jwk FROM tool_keys WHERE active ORDER BY created_at DESC LIMIT 1',
  );

  const row = existing.rows[0];
  if (row) {
    return { kid: row.kid, publicJwk: JSON.parse(row.public_jwk) as JWK };
  }

  const kid = randomUUID();
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const publicJwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const sealed = seal(await exportPKCS8(privateKey), BINDING, keyRing);

  // Another instance starting at the same moment may win the race; either key is valid,
  // and the conflict clause makes the loser fall through to a read below.
  await pool.query(
    `INSERT INTO tool_keys (kid, sealed_private, public_jwk, active)
     VALUES ($1, $2, $3, true)
     ON CONFLICT (kid) DO NOTHING`,
    [kid, sealed, JSON.stringify(publicJwk)],
  );

  const stored = await pool.query<ToolKeyRow>(
    'SELECT kid, sealed_private, public_jwk FROM tool_keys WHERE active ORDER BY created_at DESC LIMIT 1',
  );
  const chosen = stored.rows[0];
  if (!chosen) throw new Error('tool key could not be stored');
  return { kid: chosen.kid, publicJwk: JSON.parse(chosen.public_jwk) as JWK };
}

/** Every published key, so a rotation can overlap rather than cut over. */
export async function publishedKeys(pool: DbPool): Promise<JWK[]> {
  const { rows } = await pool.query<{ public_jwk: string }>(
    'SELECT public_jwk FROM tool_keys WHERE active ORDER BY created_at DESC',
  );
  return rows.map((row) => JSON.parse(row.public_jwk) as JWK);
}

/**
 * Loads the private half. Unused today; present so that the key is demonstrably a real,
 * usable pair rather than a placeholder, and covered by a test that signs with it.
 */
export async function loadPrivateKey(
  pool: DbPool,
  keyRing: KeyRing,
  kid: string,
): Promise<KeyObject | CryptoKey | undefined> {
  const { rows } = await pool.query<ToolKeyRow>(
    'SELECT kid, sealed_private, public_jwk FROM tool_keys WHERE kid = $1',
    [kid],
  );
  const row = rows[0];
  if (!row) return undefined;
  return importPKCS8(open(row.sealed_private, BINDING, keyRing), 'RS256');
}
