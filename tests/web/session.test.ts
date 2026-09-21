import { describe, expect, it } from 'vitest';
import {
  SESSION_COOKIE,
  SessionCodec,
  SessionError,
  sessionCookieAttributes,
  type SessionClaims,
} from '../../src/web/session.ts';

const SECRET = 'a-secret-long-enough-to-be-a-real-hmac-key-0123456789';

const CLAIMS: SessionClaims = {
  issuer: 'https://canvas.test.edu',
  deploymentId: '1:deployment-abc',
  subject: 'lti-user-1',
  canvasCourseId: '4321',
  locale: 'es',
};

function codec(overrides: Partial<ConstructorParameters<typeof SessionCodec>[0]> = {}) {
  return new SessionCodec({ secret: SECRET, ...overrides });
}

describe('SessionCodec', () => {
  it('round-trips the launch context', () => {
    const c = codec();
    const { token } = c.issue(CLAIMS);
    const session = c.verify(token);

    expect(session.issuer).toBe(CLAIMS.issuer);
    expect(session.deploymentId).toBe(CLAIMS.deploymentId);
    expect(session.subject).toBe(CLAIMS.subject);
    expect(session.canvasCourseId).toBe('4321');
    expect(session.locale).toBe('es');
  });

  it('round-trips a launch outside a course', () => {
    const c = codec();
    const { token } = c.issue({ ...CLAIMS, canvasCourseId: undefined });
    expect(c.verify(token).canvasCourseId).toBeUndefined();
  });

  it('gives every session its own id', () => {
    const c = codec();
    const ids = new Set(Array.from({ length: 50 }, () => c.issue(CLAIMS).session.id));
    expect(ids.size).toBe(50);
  });

  it('refuses a token signed with a different secret', () => {
    const { token } = codec().issue(CLAIMS);
    expect(() => codec({ secret: 'a-completely-different-secret-value-here' }).verify(token)).toThrow(
      SessionError,
    );
  });

  it('refuses a payload edited after signing', () => {
    const c = codec();
    const { token } = c.issue(CLAIMS);
    const [encoded, signature] = token.split('.') as [string, string];

    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    payload['sub'] = 'somebody-else';
    const forged = `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${signature}`;

    expect(() => c.verify(forged)).toThrow(/bad_signature/);
  });

  it('refuses a token whose course was swapped', () => {
    const c = codec();
    const { token } = c.issue(CLAIMS);
    const [encoded, signature] = token.split('.') as [string, string];
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    payload['cid'] = '9999';
    const forged = `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${signature}`;

    expect(() => c.verify(forged)).toThrow(/bad_signature/);
  });

  it('refuses a truncated or shapeless token', () => {
    const c = codec();
    for (const bad of ['', 'nope', 'a.b.c.d', '.signature']) {
      expect(() => c.verify(bad)).toThrow(SessionError);
    }
  });

  it('refuses a missing token', () => {
    expect(() => codec().verify(undefined)).toThrow(/malformed/);
  });

  it('refuses an expired token', () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const c = codec({ ttlMs: 1_000, now: () => now });
    const { token } = c.issue(CLAIMS);

    now = new Date('2026-01-01T00:00:02Z');
    expect(() => c.verify(token)).toThrow(/expired/);
  });

  it('accepts a token that is still within its lifetime', () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const c = codec({ ttlMs: 60_000, now: () => now });
    const { token } = c.issue(CLAIMS);

    now = new Date('2026-01-01T00:00:30Z');
    expect(c.verify(token).subject).toBe(CLAIMS.subject);
  });

  it('checks the signature before it parses anything', () => {
    // A payload that would throw during JSON parsing still reports a signature failure,
    // which is the point: nothing inside an unverified token is looked at.
    const c = codec();
    const forged = `${Buffer.from('not json at all').toString('base64url')}.deadbeef`;
    expect(() => c.verify(forged)).toThrow(/bad_signature/);
  });

  it('produces a token with no obvious personal data in the clear', () => {
    const { token } = codec().issue(CLAIMS);
    // The payload is signed, not encrypted, so it is readable by design — but it carries
    // only opaque identifiers, never a name or an email address.
    const decoded = Buffer.from(token.split('.')[0]!, 'base64url').toString();
    expect(decoded).not.toMatch(/@/);
    expect(JSON.parse(decoded)).toMatchObject({ sub: 'lti-user-1' });
  });
});

describe('session cookie', () => {
  it('is set with the attributes a cross-site iframe requires', () => {
    const attributes = sessionCookieAttributes(true);
    expect(attributes['httpOnly']).toBe(true);
    expect(attributes['secure']).toBe(true);
    expect(attributes['sameSite']).toBe('none');
    expect(attributes['path']).toBe('/');
  });

  it('has a name that does not collide with Canvas cookies', () => {
    expect(SESSION_COOKIE).toBe('cmv_session');
  });
});
