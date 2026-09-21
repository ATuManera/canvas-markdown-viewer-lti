import { describe, expect, it } from 'vitest';
import { InMemoryLaunchStateStore, type LaunchStateRecord } from '../../src/lti/state-store.ts';

function record(overrides: Partial<LaunchStateRecord> = {}): LaunchStateRecord {
  return {
    state: 'state-1',
    nonce: 'nonce-1',
    issuer: 'https://canvas.test.edu',
    clientId: 'client-1',
    targetLinkUri: 'https://md.test.edu/lti/launch',
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  };
}

describe('InMemoryLaunchStateStore', () => {
  it('returns a stored record exactly once', async () => {
    const store = new InMemoryLaunchStateStore();
    await store.create(record());

    expect(await store.consume('state-1')).toMatchObject({ nonce: 'nonce-1' });
    expect(await store.consume('state-1')).toBeUndefined();
  });

  it('returns undefined for a state it never issued', async () => {
    const store = new InMemoryLaunchStateStore();
    expect(await store.consume('never-issued')).toBeUndefined();
  });

  it('refuses an expired record and does not leave it behind', async () => {
    const store = new InMemoryLaunchStateStore();
    await store.create(record({ expiresAt: new Date(Date.now() - 1) }));

    expect(await store.consume('state-1')).toBeUndefined();
    expect(store.size).toBe(0);
  });

  it('serves only one caller when the same state is consumed concurrently', async () => {
    const store = new InMemoryLaunchStateStore();
    await store.create(record());

    const results = await Promise.all([
      store.consume('state-1'),
      store.consume('state-1'),
      store.consume('state-1'),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('accepts a nonce once and refuses it afterwards', async () => {
    const store = new InMemoryLaunchStateStore();
    const expiry = new Date(Date.now() + 60_000);

    expect(await store.markNonceUsed('https://canvas.test.edu', 'n1', expiry)).toBe(true);
    expect(await store.markNonceUsed('https://canvas.test.edu', 'n1', expiry)).toBe(false);
  });

  it('scopes the nonce memory to the issuer', async () => {
    const store = new InMemoryLaunchStateStore();
    const expiry = new Date(Date.now() + 60_000);

    expect(await store.markNonceUsed('https://a.test.edu', 'n1', expiry)).toBe(true);
    expect(await store.markNonceUsed('https://b.test.edu', 'n1', expiry)).toBe(true);
  });

  it('lets a nonce be used again once its memory window has passed', async () => {
    const store = new InMemoryLaunchStateStore();
    expect(await store.markNonceUsed('https://a.test.edu', 'n1', new Date(Date.now() - 1))).toBe(
      true,
    );
    expect(
      await store.markNonceUsed('https://a.test.edu', 'n1', new Date(Date.now() + 60_000)),
    ).toBe(true);
  });

  it('prunes expired states and nonces', async () => {
    const store = new InMemoryLaunchStateStore();
    await store.create(record({ state: 'fresh' }));
    await store.create(record({ state: 'stale', expiresAt: new Date(Date.now() - 1) }));

    await store.prune();

    expect(store.size).toBe(1);
    expect(await store.consume('fresh')).toBeDefined();
  });
});
