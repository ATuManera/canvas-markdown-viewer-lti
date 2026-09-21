import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { migrate, MIGRATIONS } from '../../src/db/migrations.ts';
import { PostgresLaunchStateStore } from '../../src/lti/pg-state-store.ts';
import { MissingTokenError, TokenStore } from '../../src/canvas/token-store.ts';
import { KeyRing, open, sealedKeyVersion } from '../../src/crypto/envelope.ts';
import type { DbPool } from '../../src/db/pool.ts';
import {
  hasDatabase,
  setupDatabase,
  testKeyRing,
  truncateAll,
  uniqueBinding,
} from '../helpers/db.ts';
import { expectPublicJwk, privateParametersIn } from '../helpers/jwk.ts';
import { randomBytes } from 'node:crypto';

const suite = hasDatabase ? describe : describe.skip;

let pool: DbPool;

beforeAll(async () => {
  if (hasDatabase) pool = await setupDatabase('test_stores');
});

afterAll(async () => {
  if (hasDatabase) await pool.end();
});

beforeEach(async () => {
  if (hasDatabase) await truncateAll(pool);
});

suite('migrations', () => {
  it('are idempotent', async () => {
    const applied = await migrate(pool);
    expect(applied).toEqual([]);
  });

  it('record every migration they apply', async () => {
    const { rows } = await pool.query<{ id: string }>('SELECT id FROM schema_migrations');
    expect(rows.map((r) => r.id).sort()).toEqual(MIGRATIONS.map((m) => m.id).sort());
  });

  it('can run concurrently without applying anything twice', async () => {
    const results = await Promise.all([migrate(pool), migrate(pool), migrate(pool)]);
    expect(results.flat()).toEqual([]);
  });
});

suite('PostgresLaunchStateStore', () => {
  const record = (overrides: Record<string, unknown> = {}) => ({
    state: `state-${randomBytes(6).toString('hex')}`,
    nonce: `nonce-${randomBytes(6).toString('hex')}`,
    issuer: 'https://canvas.test.edu',
    clientId: 'client-1',
    targetLinkUri: 'https://md.test.edu/lti/launch',
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  });

  it('returns a stored record exactly once', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const row = record();
    await store.create(row);

    expect(await store.consume(row.state)).toMatchObject({ nonce: row.nonce });
    expect(await store.consume(row.state)).toBeUndefined();
  });

  it('preserves the launch context across the round trip', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const row = record();
    await store.create(row);

    const consumed = await store.consume(row.state);
    expect(consumed?.issuer).toBe('https://canvas.test.edu');
    expect(consumed?.clientId).toBe('client-1');
    expect(consumed?.targetLinkUri).toBe('https://md.test.edu/lti/launch');
  });

  it('serves exactly one of several concurrent consumers', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const row = record();
    await store.create(row);

    const results = await Promise.all([
      store.consume(row.state),
      store.consume(row.state),
      store.consume(row.state),
      store.consume(row.state),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('refuses an expired record', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const row = record({ expiresAt: new Date(Date.now() - 1_000) });
    await store.create(row);

    expect(await store.consume(row.state)).toBeUndefined();
  });

  it('accepts a nonce once and refuses it afterwards', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const expiry = new Date(Date.now() + 60_000);

    expect(await store.markNonceUsed('https://canvas.test.edu', 'n1', expiry)).toBe(true);
    expect(await store.markNonceUsed('https://canvas.test.edu', 'n1', expiry)).toBe(false);
  });

  it('accepts a nonce for one issuer that another has already used', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const expiry = new Date(Date.now() + 60_000);

    expect(await store.markNonceUsed('https://a.test.edu', 'shared', expiry)).toBe(true);
    expect(await store.markNonceUsed('https://b.test.edu', 'shared', expiry)).toBe(true);
  });

  it('accepts exactly one of several concurrent claims on the same nonce', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const expiry = new Date(Date.now() + 60_000);

    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        store.markNonceUsed('https://canvas.test.edu', 'race', expiry),
      ),
    );

    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('lets a nonce be claimed again once its memory window has passed', async () => {
    const store = new PostgresLaunchStateStore(pool);

    expect(
      await store.markNonceUsed('https://canvas.test.edu', 'n2', new Date(Date.now() - 1_000)),
    ).toBe(true);
    expect(
      await store.markNonceUsed('https://canvas.test.edu', 'n2', new Date(Date.now() + 60_000)),
    ).toBe(true);
  });

  it('prunes only what has expired', async () => {
    const store = new PostgresLaunchStateStore(pool);
    const fresh = record();
    const stale = record({ expiresAt: new Date(Date.now() - 1_000) });
    await store.create(fresh);
    await store.create(stale);

    await store.prune();

    const { rows } = await pool.query<{ state: string }>('SELECT state FROM launch_states');
    expect(rows.map((r) => r.state)).toEqual([fresh.state]);
  });
});

suite('TokenStore', () => {
  const REFRESH = 'canvas-refresh-token-value';

  it('stores and returns a token', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();

    await store.save(binding, REFRESH, 'url:GET|/api/v1/courses/:course_id/files');
    const stored = await store.load(binding);

    expect(stored?.refreshToken).toBe(REFRESH);
    expect(stored?.scope).toBe('url:GET|/api/v1/courses/:course_id/files');
  });

  it('returns undefined for a user who has not authorised', async () => {
    const store = new TokenStore(pool, testKeyRing());
    expect(await store.load(uniqueBinding())).toBeUndefined();
    expect(await store.has(uniqueBinding())).toBe(false);
  });

  it('never writes the token in the clear', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();
    await store.save(binding, REFRESH);

    const { rows } = await pool.query<{ sealed_token: string }>(
      'SELECT sealed_token FROM canvas_tokens',
    );
    expect(rows[0]?.sealed_token).not.toContain(REFRESH);
    expect(rows[0]?.sealed_token).not.toContain('canvas-refresh');
  });

  it('replaces the token rather than accumulating rows', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();

    await store.save(binding, 'first');
    await store.save(binding, 'second');

    const { rows } = await pool.query('SELECT 1 FROM canvas_tokens');
    expect(rows).toHaveLength(1);
    expect((await store.load(binding))?.refreshToken).toBe('second');
  });

  it('keeps users apart', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const alice = uniqueBinding('alice');
    const bob = uniqueBinding('bob');

    await store.save(alice, 'alice-token');
    await store.save(bob, 'bob-token');

    expect((await store.load(alice))?.refreshToken).toBe('alice-token');
    expect((await store.load(bob))?.refreshToken).toBe('bob-token');
  });

  it('refuses to open a row moved onto another user', async () => {
    const keyRing = testKeyRing();
    const store = new TokenStore(pool, keyRing);
    const alice = uniqueBinding('alice');
    const bob = uniqueBinding('bob');

    await store.save(alice, 'alice-token');
    await store.save(bob, 'bob-token');

    // Simulate a database-level tamper: Alice's ciphertext written onto Bob's row.
    const { rows } = await pool.query<{ sealed_token: string }>(
      'SELECT sealed_token FROM canvas_tokens WHERE subject = $1',
      [alice.subject],
    );
    await pool.query('UPDATE canvas_tokens SET sealed_token = $1 WHERE subject = $2', [
      rows[0]?.sealed_token,
      bob.subject,
    ]);

    await expect(store.load(bob)).rejects.toThrow(/authentication_failed/);
  });

  it('revokes a token and reports whether there was one', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();

    await store.save(binding, REFRESH);
    expect(await store.revoke(binding)).toBe(true);
    expect(await store.revoke(binding)).toBe(false);
    expect(await store.load(binding)).toBeUndefined();
  });

  it('revokes every token of one Canvas instance', async () => {
    const store = new TokenStore(pool, testKeyRing());
    await store.save(uniqueBinding('a'), 'one');
    await store.save(uniqueBinding('b'), 'two');

    expect(await store.revokeIssuer('https://canvas.test.edu')).toBe(2);
    expect((await pool.query('SELECT 1 FROM canvas_tokens')).rows).toHaveLength(0);
  });
});

suite('TokenStore — refresh races', () => {
  it('serialises two refreshes of the same token', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();
    await store.save(binding, 'refresh-1');

    let inFlight = 0;
    let maxInFlight = 0;
    const order: string[] = [];

    const refresh = (label: string) =>
      store.withRefreshLock(binding, async (current) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        order.push(`${label}:saw:${current.refreshToken}`);
        await new Promise((resolve) => setTimeout(resolve, 120));
        inFlight -= 1;
        return { refreshToken: `${current.refreshToken}+${label}`, result: label };
      });

    await Promise.all([refresh('a'), refresh('b')]);

    expect(maxInFlight).toBe(1);
    // The second caller sees what the first one wrote, never the original value twice.
    expect(order[1]).not.toBe(order[0]);
    expect(order[1]).toMatch(/saw:refresh-1\+[ab]$/);
  });

  it('lets refreshes for different users proceed together', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const alice = uniqueBinding('alice');
    const bob = uniqueBinding('bob');
    await store.save(alice, 'a-1');
    await store.save(bob, 'b-1');

    let concurrent = 0;
    let maxConcurrent = 0;

    const refresh = (binding: ReturnType<typeof uniqueBinding>) =>
      store.withRefreshLock(binding, async () => {
        concurrent += 1;
        maxConcurrent = Math.max(maxConcurrent, concurrent);
        await new Promise((resolve) => setTimeout(resolve, 120));
        concurrent -= 1;
        return { result: true };
      });

    await Promise.all([refresh(alice), refresh(bob)]);

    expect(maxConcurrent).toBe(2);
  });

  it('keeps the existing token when the platform supplies no replacement', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();
    await store.save(binding, 'original');

    // Canvas answers a refresh without a new refresh_token; the stored one must survive.
    await store.withRefreshLock(binding, () =>
      Promise.resolve({ refreshToken: undefined, result: null }),
    );

    const stored = await store.load(binding);
    expect(stored?.refreshToken).toBe('original');
    expect(stored?.refreshedAt).toBeInstanceOf(Date);
  });

  it('accepts a replacement when a platform does rotate the refresh token', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();
    await store.save(binding, 'original');

    await store.withRefreshLock(binding, () =>
      Promise.resolve({ refreshToken: 'rotated', result: null }),
    );

    expect((await store.load(binding))?.refreshToken).toBe('rotated');
  });

  it('rolls back the refresh when the callback throws', async () => {
    const store = new TokenStore(pool, testKeyRing());
    const binding = uniqueBinding();
    await store.save(binding, 'original');

    await expect(
      store.withRefreshLock(binding, () => Promise.reject(new Error('canvas said no'))),
    ).rejects.toThrow('canvas said no');

    const stored = await store.load(binding);
    expect(stored?.refreshToken).toBe('original');
    expect(stored?.refreshedAt).toBeUndefined();
  });

  it('reports a missing token rather than creating one', async () => {
    const store = new TokenStore(pool, testKeyRing());
    await expect(
      store.withRefreshLock(uniqueBinding(), () => Promise.resolve({ result: null })),
    ).rejects.toThrow(MissingTokenError);
  });
});

suite('TokenStore — key rotation', () => {
  it('still reads a row sealed under an older key', async () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const binding = uniqueBinding();

    await new TokenStore(pool, new KeyRing([oldKey])).save(binding, 'legacy-token');

    const rotated = new TokenStore(pool, new KeyRing([oldKey, newKey], '2'));
    expect((await rotated.load(binding))?.refreshToken).toBe('legacy-token');
  });

  it('lists the rows that are still on an older key', async () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const stale = uniqueBinding('stale');
    const current = uniqueBinding('current');

    await new TokenStore(pool, new KeyRing([oldKey])).save(stale, 'old');
    const rotated = new TokenStore(pool, new KeyRing([oldKey, newKey], '2'));
    await rotated.save(current, 'new');

    const pending = await rotated.listStale();
    expect(pending.map((p) => p.subject)).toEqual([stale.subject]);
  });

  it('re-wraps a stale row under the active key without changing the secret', async () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const binding = uniqueBinding();

    await new TokenStore(pool, new KeyRing([oldKey])).save(binding, 'legacy-token');
    const rotated = new TokenStore(pool, new KeyRing([oldKey, newKey], '2'));

    expect(await rotated.rewrapOne(binding)).toBe(true);

    const { rows } = await pool.query<{ sealed_token: string; key_version: string }>(
      'SELECT sealed_token, key_version FROM canvas_tokens WHERE subject = $1',
      [binding.subject],
    );
    expect(sealedKeyVersion(rows[0]!.sealed_token)).toBe('2');
    expect(rows[0]?.key_version).toBe('2');
    expect(open(rows[0]!.sealed_token, binding, new KeyRing([newKey]))).toBe('legacy-token');
  });

  it('does not re-wrap a row that is already current', async () => {
    const store = new TokenStore(pool, testKeyRing('1'));
    const binding = uniqueBinding();
    await store.save(binding, 'token');

    expect(await store.rewrapOne(binding)).toBe(false);
  });

  it('cannot read a row once the old key leaves the ring', async () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const binding = uniqueBinding();

    await new TokenStore(pool, new KeyRing([oldKey])).save(binding, 'legacy-token');

    await expect(new TokenStore(pool, new KeyRing([newKey])).load(binding)).rejects.toThrow(
      /unknown_key_version/,
    );
  });
});

suite('tool keys', () => {
  it('generates a key pair on first use and publishes only the public half', async () => {
    const { ensureToolKey, publishedKeys } = await import('../../src/lti/tool-keys.ts');
    const keyRing = testKeyRing();

    const key = await ensureToolKey(pool, keyRing);

    expect(key.kid).toBeTruthy();
    expectPublicJwk(key.publicJwk);
    expect((await publishedKeys(pool)).map((k) => k.kid)).toContain(key.kid);
  });

  it('publishes none of the private parameters RFC 7518 defines', async () => {
    const { ensureToolKey, publishedKeys } = await import('../../src/lti/tool-keys.ts');
    await ensureToolKey(pool, testKeyRing());

    for (const jwk of await publishedKeys(pool)) {
      expect(privateParametersIn(jwk)).toEqual([]);
    }
  });

  it('reuses the key it already has', async () => {
    const { ensureToolKey } = await import('../../src/lti/tool-keys.ts');
    const keyRing = testKeyRing();

    const first = await ensureToolKey(pool, keyRing);
    const second = await ensureToolKey(pool, keyRing);

    expect(second.kid).toBe(first.kid);
  });

  it('never stores the private key in the clear', async () => {
    const { ensureToolKey } = await import('../../src/lti/tool-keys.ts');
    await ensureToolKey(pool, testKeyRing());

    const { rows } = await pool.query<{ sealed_private: string }>(
      'SELECT sealed_private FROM tool_keys',
    );
    expect(rows[0]?.sealed_private).not.toContain('BEGIN PRIVATE KEY');
    expect(rows[0]?.sealed_private.startsWith('v1.')).toBe(true);
  });

  it('stores a real, usable pair rather than a placeholder', async () => {
    const { ensureToolKey, loadPrivateKey } = await import('../../src/lti/tool-keys.ts');
    const { SignJWT, jwtVerify, importJWK } = await import('jose');
    const keyRing = testKeyRing();

    const key = await ensureToolKey(pool, keyRing);
    const privateKey = await loadPrivateKey(pool, keyRing, key.kid);
    expect(privateKey).toBeDefined();

    const token = await new SignJWT({ probe: true })
      .setProtectedHeader({ alg: 'RS256', kid: key.kid })
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(privateKey!);

    const verified = await jwtVerify(token, await importJWK(key.publicJwk, 'RS256'));
    expect(verified.payload['probe']).toBe(true);
  });
});
