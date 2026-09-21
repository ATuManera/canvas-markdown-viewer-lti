import { expect } from 'vitest';

/**
 * Structural check that a published JWK carries no private key material.
 *
 * Searching the serialised response for a substring is not enough: `"d"` appears inside
 * base64url modulus values, inside `kid` UUIDs and inside any field that happens to contain
 * the letter, so a substring search both misses real leaks and raises false ones. The key
 * is parsed and its parameter names are inspected instead.
 *
 * The forbidden names are the private parameters defined by RFC 7518 §6:
 *
 *   - RSA (§6.3.2): `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`
 *   - Elliptic curve (§6.2.2): `d`
 *   - Octet, i.e. symmetric (§6.4.1): `k`
 *
 * `oth` and `k` are included because a change of key type must not quietly slip past a
 * check written only for RSA.
 */
export const PRIVATE_JWK_PARAMETERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/** Parameters a published signing key is expected to carry. */
const EXPECTED_PUBLIC_RSA_PARAMETERS = ['kty', 'n', 'e'] as const;

export function privateParametersIn(value: unknown): string[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('not a JWK object');
  }
  const jwk = value as Record<string, unknown>;
  return PRIVATE_JWK_PARAMETERS.filter((name) => Object.hasOwn(jwk, name));
}

/** Asserts one JWK is a public key and nothing more. */
export function expectPublicJwk(value: unknown): void {
  expect(privateParametersIn(value)).toEqual([]);

  const jwk = value as Record<string, unknown>;
  expect(jwk['kty']).toBe('RSA');
  for (const name of EXPECTED_PUBLIC_RSA_PARAMETERS) {
    expect(typeof jwk[name]).toBe('string');
  }
  expect(jwk['alg']).toBe('RS256');
  expect(jwk['use']).toBe('sig');
  expect(typeof jwk['kid']).toBe('string');
}

/** Asserts a whole JWK Set is well formed and free of private material. */
export function expectPublicJwkSet(value: unknown): Record<string, unknown>[] {
  expect(typeof value).toBe('object');
  const set = value as Record<string, unknown>;

  expect(Array.isArray(set['keys'])).toBe(true);
  const keys = set['keys'] as unknown[];
  expect(keys.length).toBeGreaterThan(0);

  for (const key of keys) expectPublicJwk(key);

  // A key set must not carry anything beyond its keys: a stray field is a leak waiting to
  // happen, and nothing in this tool has a reason to add one.
  expect(Object.keys(set)).toEqual(['keys']);

  return keys as Record<string, unknown>[];
}
