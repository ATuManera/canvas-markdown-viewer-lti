import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * The viewer's session, carried without relying on a third-party cookie.
 *
 * The tool runs in an iframe whose top document is Canvas, so any cookie it sets is a
 * third-party cookie: blocked in Safari, restricted in Chrome, partitioned in Firefox. The
 * session is therefore a signed token embedded in the page itself — hidden form fields for
 * navigation, a request header for fetch — and a cookie is set only as a convenience where
 * the browser accepts one. See ADR-003.
 *
 * The token never travels in a query string. A URL ends up in browser history, in `Referer`
 * headers and in proxy logs, and a session token has no business in any of them.
 */

const TOKEN_VERSION = 'v1';

export interface SessionClaims {
  readonly issuer: string;
  readonly deploymentId: string;
  readonly subject: string;
  readonly canvasCourseId: string | undefined;
  readonly locale: 'es' | 'en';
}

export interface Session extends SessionClaims {
  /** Unique per launch, so one session can be told from another in logs. */
  readonly id: string;
  readonly expiresAt: Date;
}

export type SessionErrorCode = 'malformed' | 'bad_signature' | 'expired';

export class SessionError extends Error {
  override readonly name = 'SessionError';
  constructor(readonly code: SessionErrorCode) {
    super(code);
  }
}

interface Payload {
  v: string;
  jti: string;
  iss: string;
  dep: string;
  sub: string;
  cid: string | null;
  loc: 'es' | 'en';
  exp: number;
}

export interface SessionCodecOptions {
  readonly secret: string;
  readonly ttlMs?: number;
  readonly now?: () => Date;
}

const DEFAULT_TTL_MS = 8 * 60 * 60_000;

export class SessionCodec {
  readonly #secret: Buffer;
  readonly #ttlMs: number;
  readonly #now: () => Date;

  constructor(options: SessionCodecOptions) {
    this.#secret = Buffer.from(options.secret, 'utf8');
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#now = options.now ?? (() => new Date());
  }

  issue(claims: SessionClaims): { token: string; session: Session } {
    const id = randomBytes(12).toString('base64url');
    const expiresAt = new Date(this.#now().getTime() + this.#ttlMs);

    const payload: Payload = {
      v: TOKEN_VERSION,
      jti: id,
      iss: claims.issuer,
      dep: claims.deploymentId,
      sub: claims.subject,
      cid: claims.canvasCourseId ?? null,
      loc: claims.locale,
      exp: Math.floor(expiresAt.getTime() / 1000),
    };

    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    return {
      token: `${encoded}.${this.sign(encoded)}`,
      session: { ...claims, id, expiresAt },
    };
  }

  /** Verifies and decodes a token, or throws {@link SessionError}. */
  verify(token: string | undefined): Session {
    if (!token) throw new SessionError('malformed');

    const separator = token.lastIndexOf('.');
    if (separator <= 0) throw new SessionError('malformed');

    const encoded = token.slice(0, separator);
    const signature = token.slice(separator + 1);

    // Signature first: nothing inside the payload is trusted until it has been checked.
    if (!this.signatureMatches(encoded, signature)) throw new SessionError('bad_signature');

    let payload: Payload;
    try {
      payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as Payload;
    } catch {
      throw new SessionError('malformed');
    }

    if (payload.v !== TOKEN_VERSION) throw new SessionError('malformed');
    if (typeof payload.exp !== 'number') throw new SessionError('malformed');
    if (typeof payload.iss !== 'string' || typeof payload.sub !== 'string') {
      throw new SessionError('malformed');
    }

    const expiresAt = new Date(payload.exp * 1000);
    if (expiresAt.getTime() <= this.#now().getTime()) throw new SessionError('expired');

    return {
      id: payload.jti,
      issuer: payload.iss,
      deploymentId: payload.dep,
      subject: payload.sub,
      canvasCourseId: payload.cid ?? undefined,
      locale: payload.loc === 'en' ? 'en' : 'es',
      expiresAt,
    };
  }

  private sign(encoded: string): string {
    return createHmac('sha256', this.#secret).update(encoded).digest('base64url');
  }

  private signatureMatches(encoded: string, signature: string): boolean {
    const expected = Buffer.from(this.sign(encoded), 'utf8');
    const actual = Buffer.from(signature, 'utf8');
    if (expected.length !== actual.length) return false;
    return timingSafeEqual(expected, actual);
  }
}

/**
 * Cookie attributes for the optional convenience cookie.
 *
 * `SameSite=None` is required for the cookie to be sent at all from inside a cross-site
 * iframe, and `Secure` is required for `SameSite=None` to be accepted. Browsers that block
 * third-party cookies ignore it entirely, which is why nothing depends on it.
 */
export const SESSION_COOKIE = 'cmv_session';

export function sessionCookieAttributes(secure: boolean): Record<string, unknown> {
  return {
    httpOnly: true,
    secure,
    sameSite: 'none' as const,
    path: '/',
  };
}
