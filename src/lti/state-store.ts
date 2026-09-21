/**
 * Anti-replay store for the OIDC `state`/`nonce` pair.
 *
 * The tool mints a `state` when it starts the OIDC flow and remembers the `nonce` it sent
 * with it. On the callback the record is consumed **atomically**: a second attempt with the
 * same `state` finds nothing, which is what makes a captured launch unreplayable.
 *
 * Consumed nonces are remembered separately for a short window, so a captured `id_token`
 * cannot be paired with a freshly minted `state` either.
 */

export interface LaunchStateRecord {
  readonly state: string;
  readonly nonce: string;
  readonly issuer: string;
  readonly clientId: string;
  /** Where Canvas said the launch was headed, checked against the token's claim. */
  readonly targetLinkUri: string | undefined;
  readonly expiresAt: Date;
}

export interface LaunchStateStore {
  create(record: LaunchStateRecord): Promise<void>;

  /**
   * Removes and returns the record for `state`. Returns `undefined` if it never existed,
   * was already consumed, or has expired. Implementations must make this atomic.
   */
  consume(state: string): Promise<LaunchStateRecord | undefined>;

  /**
   * Records a nonce as used. Returns `false` if it was already used for this issuer,
   * which means the caller is looking at a replay.
   */
  markNonceUsed(issuer: string, nonce: string, expiresAt: Date): Promise<boolean>;

  /** Drops expired rows. Called periodically; safe to call concurrently. */
  prune(now?: Date): Promise<void>;
}

/**
 * In-memory implementation. Correct for a single process, and the reference against which
 * the PostgreSQL implementation is tested. Not suitable for multiple instances, where a
 * launch may return to a different process than the one that started it.
 */
export class InMemoryLaunchStateStore implements LaunchStateStore {
  readonly #states = new Map<string, LaunchStateRecord>();
  readonly #nonces = new Map<string, Date>();

  create(record: LaunchStateRecord): Promise<void> {
    this.#states.set(record.state, record);
    return Promise.resolve();
  }

  consume(state: string): Promise<LaunchStateRecord | undefined> {
    const record = this.#states.get(state);
    if (!record) return Promise.resolve(undefined);
    // Delete before any expiry check: a stale record is spent either way.
    this.#states.delete(state);
    if (record.expiresAt.getTime() <= Date.now()) return Promise.resolve(undefined);
    return Promise.resolve(record);
  }

  markNonceUsed(issuer: string, nonce: string, expiresAt: Date): Promise<boolean> {
    const key = nonceKey(issuer, nonce);
    const existing = this.#nonces.get(key);
    if (existing && existing.getTime() > Date.now()) return Promise.resolve(false);
    this.#nonces.set(key, expiresAt);
    return Promise.resolve(true);
  }

  prune(now: Date = new Date()): Promise<void> {
    for (const [key, record] of this.#states) {
      if (record.expiresAt.getTime() <= now.getTime()) this.#states.delete(key);
    }
    for (const [key, expiresAt] of this.#nonces) {
      if (expiresAt.getTime() <= now.getTime()) this.#nonces.delete(key);
    }
    return Promise.resolve();
  }

  /** Test helper: how many live records are held. */
  get size(): number {
    return this.#states.size;
  }
}

function nonceKey(issuer: string, nonce: string): string {
  return `${issuer}\u0000${nonce}`;
}
