import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CanvasOAuth,
  codeChallengeFor,
  createCodeVerifier,
  OAuthError,
  type FlowContext,
} from '../../src/canvas/oauth.ts';
import { TokenStore } from '../../src/canvas/token-store.ts';
import { CANVAS_API_SCOPES, scopeParameter } from '../../src/canvas/scopes.ts';
import type { Platform } from '../../src/config/platforms.ts';
import type { DbPool } from '../../src/db/pool.ts';
import { hasDatabase, setupDatabase, testKeyRing, truncateAll } from '../helpers/db.ts';

const suite = hasDatabase ? describe : describe.skip;

const REDIRECT_URI = 'https://md.test.edu/canvas/callback';

interface TokenCall {
  readonly form: URLSearchParams;
  readonly contentType: string | undefined;
  readonly authorization: string | undefined;
}

let pool: DbPool;
let server: Server;
let origin: string;
let calls: TokenCall[] = [];
let nextResponse: { status: number; body: unknown } = { status: 200, body: {} };

function platformFor(base: string): Platform {
  // Built as a literal rather than through the schema: these tests need a plain-http
  // Canvas double, and the schema rightly refuses http for a real platform.
  return {
    issuer: 'https://canvas.test.edu',
    clientId: 'lti-client-1',
    deploymentIds: ['1:deployment-abc'],
    authorizationEndpoint: 'https://canvas.test.edu/api/lti/authorize_redirect',
    jwksUri: 'https://canvas.test.edu/api/lti/security/jwks',
    apiBaseUrl: base,
    apiClientId: 'api-client-1',
    apiClientSecret: 'api-client-secret',
    downloadHostAllowlist: [],
  };
}

function contextFor(overrides: Partial<FlowContext> = {}): FlowContext {
  return {
    issuer: 'https://canvas.test.edu',
    clientId: 'lti-client-1',
    deploymentId: '1:deployment-abc',
    subject: 'lti-user-1',
    canvasCourseId: '4321',
    ...overrides,
  };
}

function oauthFor(pool_: DbPool, keyRing = testKeyRing()): CanvasOAuth {
  return new CanvasOAuth({
    pool: pool_,
    keyRing,
    tokens: new TokenStore(pool_, keyRing),
    redirectUri: REDIRECT_URI,
    fetchOptions: {
      maxRedirects: 0,
      timeoutMs: 2_000,
      maxBytes: 64_000,
      allowInsecureScheme: true,
      allowPrivateAddresses: true,
    },
  });
}

beforeAll(async () => {
  if (!hasDatabase) return;
  pool = await setupDatabase('test_oauth');

  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      calls.push({
        form: new URLSearchParams(Buffer.concat(chunks).toString('utf8')),
        contentType: req.headers['content-type'],
        authorization: req.headers.authorization,
      });
      res.writeHead(nextResponse.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(nextResponse.body));
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');
  origin = `http://localhost:${address.port}`;
});

afterAll(async () => {
  if (!hasDatabase) return;
  await pool.end();
  await new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => {
      resolve();
    });
  });
});

beforeEach(async () => {
  if (!hasDatabase) return;
  await truncateAll(pool);
  calls = [];
  nextResponse = {
    status: 200,
    body: { access_token: 'access-1', refresh_token: 'refresh-1', expires_in: 3600 },
  };
});

afterEach(() => {
  nextResponse = { status: 200, body: {} };
});

describe('PKCE', () => {
  it('produces a verifier within the length the RFC allows', () => {
    const verifier = createCodeVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  it('produces a verifier from unreserved characters only', () => {
    expect(createCodeVerifier()).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('never repeats a verifier', () => {
    const seen = new Set(Array.from({ length: 200 }, () => createCodeVerifier()));
    expect(seen.size).toBe(200);
  });

  it('derives the challenge as base64url(sha256(verifier))', () => {
    const verifier = createCodeVerifier();
    const expected = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    expect(codeChallengeFor(verifier)).toBe(expected);
  });

  it('produces a challenge that does not reveal the verifier', () => {
    const verifier = createCodeVerifier();
    expect(codeChallengeFor(verifier)).not.toBe(verifier);
  });
});

describe('scopes', () => {
  it('asks for exactly the two scopes Canvas publishes', () => {
    // Canvas offers a scope only for /api/v1 and /api/sis routes, so the web download
    // route cannot be granted. Asking for a third, non-existent scope made Canvas refuse
    // the authorisation outright during the physical test. See ADR-002.
    expect([...CANVAS_API_SCOPES]).toEqual([
      'url:GET|/api/v1/courses/:course_id/files',
      'url:GET|/api/v1/courses/:course_id/files/:id',
    ]);
  });

  it('asks for no scope outside /api/v1', () => {
    for (const scope of CANVAS_API_SCOPES) {
      expect(scope).toMatch(/^url:GET\|\/api\/v1\//);
    }
  });

  it('asks only for read access', () => {
    for (const scope of CANVAS_API_SCOPES) {
      expect(scope.startsWith('url:GET|')).toBe(true);
    }
  });

  it('joins scopes with spaces, as Canvas requires a single parameter', () => {
    expect(scopeParameter(['a', 'b'])).toBe('a b');
  });
});

suite('beginAuthorization', () => {
  it('builds an authorization URL with PKCE S256 and a single scope parameter', async () => {
    const oauth = oauthFor(pool);
    const { url, state } = await oauth.beginAuthorization(platformFor(origin), contextFor());
    const parsed = new URL(url);

    expect(parsed.pathname).toBe('/login/oauth2/auth');
    expect(parsed.searchParams.get('client_id')).toBe('api-client-1');
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(parsed.searchParams.get('state')).toBe(state);
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('code_challenge')).toBeTruthy();
    expect(parsed.searchParams.getAll('scope')).toHaveLength(1);
    expect(parsed.searchParams.get('scope')).toBe(scopeParameter());
  });

  it('sends exactly two scope values in the authorization request', async () => {
    const oauth = oauthFor(pool);
    const { url } = await oauth.beginAuthorization(platformFor(origin), contextFor());
    const scopes = (new URL(url).searchParams.get('scope') ?? '').split(' ').filter(Boolean);

    expect(scopes).toHaveLength(2);
    expect(scopes).not.toContain('url:GET|/courses/:course_id/files/:id/download');
  });

  it('never offers the plain challenge method', async () => {
    const oauth = oauthFor(pool);
    const { url } = await oauth.beginAuthorization(platformFor(origin), contextFor());
    expect(url).not.toContain('plain');
  });

  it('mints an unpredictable state on every call', async () => {
    const oauth = oauthFor(pool);
    const states = new Set<string>();
    for (let i = 0; i < 25; i += 1) {
      const { state } = await oauth.beginAuthorization(platformFor(origin), contextFor());
      states.add(state);
      expect(state.length).toBeGreaterThanOrEqual(43);
    }
    expect(states.size).toBe(25);
  });

  it('never sends the client secret to the browser', async () => {
    const oauth = oauthFor(pool);
    const { url } = await oauth.beginAuthorization(platformFor(origin), contextFor());
    expect(url).not.toContain('api-client-secret');
  });

  it('seals the verifier before it reaches the database', async () => {
    const oauth = oauthFor(pool);
    await oauth.beginAuthorization(platformFor(origin), contextFor());

    const { rows } = await pool.query<{ sealed_verifier: string }>(
      'SELECT sealed_verifier FROM oauth_flows',
    );
    expect(rows[0]?.sealed_verifier.startsWith('v1.')).toBe(true);
  });

  it('gives the flow a short expiry', async () => {
    const oauth = oauthFor(pool);
    await oauth.beginAuthorization(platformFor(origin), contextFor());

    const { rows } = await pool.query<{ expires_at: Date }>('SELECT expires_at FROM oauth_flows');
    const ttlMs = rows[0]!.expires_at.getTime() - Date.now();
    expect(ttlMs).toBeGreaterThan(0);
    expect(ttlMs).toBeLessThanOrEqual(10 * 60_000 + 1_000);
  });
});

suite('completeAuthorization', () => {
  async function start(oauth: CanvasOAuth, context = contextFor()) {
    return oauth.beginAuthorization(platformFor(origin), context);
  }

  it('exchanges the code and stores the refresh token', async () => {
    const keyRing = testKeyRing();
    const oauth = oauthFor(pool, keyRing);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await oauth.completeAuthorization(platformFor(origin), { state, code: 'auth-code' }, context);

    const exchange = calls[0]!;
    expect(exchange.form.get('grant_type')).toBe('authorization_code');
    expect(exchange.form.get('client_id')).toBe('api-client-1');
    expect(exchange.form.get('client_secret')).toBe('api-client-secret');
    expect(exchange.form.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(exchange.form.get('code')).toBe('auth-code');
    expect(exchange.form.get('code_verifier')).toBeTruthy();
    expect(exchange.contentType).toBe('application/x-www-form-urlencoded');

    const stored = await new TokenStore(pool, keyRing).load(context);
    expect(stored?.refreshToken).toBe('refresh-1');
  });

  it('sends a verifier whose challenge matches the one it advertised', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { url, state } = await start(oauth, context);
    const advertised = new URL(url).searchParams.get('code_challenge');

    await oauth.completeAuthorization(platformFor(origin), { state, code: 'auth-code' }, context);

    const verifier = calls[0]!.form.get('code_verifier')!;
    expect(codeChallengeFor(verifier)).toBe(advertised);
  });

  it('refuses a state that was already used', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await oauth.completeAuthorization(platformFor(origin), { state, code: 'code-1' }, context);
    await expect(
      oauth.completeAuthorization(platformFor(origin), { state, code: 'code-2' }, context),
    ).rejects.toThrow(/unknown_flow/);
  });

  it('refuses a state it never issued', async () => {
    const oauth = oauthFor(pool);
    await expect(
      oauth.completeAuthorization(
        platformFor(origin),
        { state: 'fabricated', code: 'code' },
        contextFor(),
      ),
    ).rejects.toThrow(/unknown_flow/);
  });

  it('refuses a callback with no code', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await expect(
      oauth.completeAuthorization(platformFor(origin), { state }, context),
    ).rejects.toThrow(/unknown_flow/);
  });

  it('reports a denial from the authorization screen', async () => {
    const oauth = oauthFor(pool);
    await expect(
      oauth.completeAuthorization(platformFor(origin), { error: 'access_denied' }, contextFor()),
    ).rejects.toThrow(/authorization_denied/);
  });

  it('refuses a callback completed during another user’s launch', async () => {
    const oauth = oauthFor(pool);
    const alice = contextFor({ subject: 'alice' });
    const { state } = await start(oauth, alice);

    await expect(
      oauth.completeAuthorization(
        platformFor(origin),
        { state, code: 'code' },
        contextFor({ subject: 'mallory' }),
      ),
    ).rejects.toThrow(/context_mismatch/);
  });

  it('refuses a callback completed in another course', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor({ canvasCourseId: '1' });
    const { state } = await start(oauth, context);

    await expect(
      oauth.completeAuthorization(
        platformFor(origin),
        { state, code: 'code' },
        contextFor({ canvasCourseId: '2' }),
      ),
    ).rejects.toThrow(/context_mismatch/);
  });

  it('refuses a callback completed under another deployment', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await expect(
      oauth.completeAuthorization(
        platformFor(origin),
        { state, code: 'code' },
        contextFor({ deploymentId: '9:elsewhere' }),
      ),
    ).rejects.toThrow(/context_mismatch/);
  });

  it('leaves no flow row behind after a mismatch, so the code cannot be retried', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await expect(
      oauth.completeAuthorization(
        platformFor(origin),
        { state, code: 'code' },
        contextFor({ subject: 'mallory' }),
      ),
    ).rejects.toThrow();

    expect((await pool.query('SELECT 1 FROM oauth_flows')).rows).toHaveLength(0);
  });

  it('always posts the tool’s configured redirect_uri, never one from the request', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context);

    expect(calls[0]!.form.get('redirect_uri')).toBe(REDIRECT_URI);
  });

  it('rejects a token response that carries no refresh token', async () => {
    nextResponse = { status: 200, body: { access_token: 'a', expires_in: 3600 } };
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    await expect(
      oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context),
    ).rejects.toThrow(/malformed_token_response/);
  });

  it('surfaces an error code from the token endpoint without echoing its description', async () => {
    nextResponse = {
      status: 400,
      body: { error: 'invalid_grant', error_description: 'reflected <script>alert(1)</script>' },
    };
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await start(oauth, context);

    const error = await oauth
      .completeAuthorization(platformFor(origin), { state, code: 'c' }, context)
      .catch((e: unknown) => e as OAuthError);

    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).code).toBe('token_endpoint_error');
    expect((error as OAuthError).detail).toBe('invalid_grant');
    expect((error as OAuthError).message).not.toContain('script');
  });
});

suite('getAccessToken', () => {
  async function authorize(oauth: CanvasOAuth, context = contextFor()) {
    const { state } = await oauth.beginAuthorization(platformFor(origin), context);
    await oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context);
    calls = [];
  }

  it('reuses a cached access token instead of refreshing', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    await authorize(oauth, context);

    expect(await oauth.getAccessToken(platformFor(origin), context)).toBe('access-1');
    expect(calls).toHaveLength(0);
  });

  it('refreshes once the cached token is gone', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    await authorize(oauth, context);
    oauth.forget(context);

    nextResponse = { status: 200, body: { access_token: 'access-2', expires_in: 3600 } };
    expect(await oauth.getAccessToken(platformFor(origin), context)).toBe('access-2');

    expect(calls[0]!.form.get('grant_type')).toBe('refresh_token');
    expect(calls[0]!.form.get('refresh_token')).toBe('refresh-1');
  });

  it('keeps the stored refresh token when Canvas returns none, which is what Canvas does', async () => {
    const keyRing = testKeyRing();
    const oauth = oauthFor(pool, keyRing);
    const context = contextFor();
    await authorize(oauth, context);
    oauth.forget(context);

    nextResponse = { status: 200, body: { access_token: 'access-2', expires_in: 3600 } };
    await oauth.getAccessToken(platformFor(origin), context);

    expect((await new TokenStore(pool, keyRing).load(context))?.refreshToken).toBe('refresh-1');
  });

  it('accepts a rotated refresh token from a platform that supplies one', async () => {
    const keyRing = testKeyRing();
    const oauth = oauthFor(pool, keyRing);
    const context = contextFor();
    await authorize(oauth, context);
    oauth.forget(context);

    nextResponse = {
      status: 200,
      body: { access_token: 'access-2', refresh_token: 'refresh-2', expires_in: 3600 },
    };
    await oauth.getAccessToken(platformFor(origin), context);

    expect((await new TokenStore(pool, keyRing).load(context))?.refreshToken).toBe('refresh-2');
  });

  it('coalesces concurrent refreshes into a single exchange', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    await authorize(oauth, context);
    oauth.forget(context);

    nextResponse = { status: 200, body: { access_token: 'access-2', expires_in: 3600 } };
    const results = await Promise.all([
      oauth.getAccessToken(platformFor(origin), context),
      oauth.getAccessToken(platformFor(origin), context),
      oauth.getAccessToken(platformFor(origin), context),
    ]);

    expect(results).toEqual(['access-2', 'access-2', 'access-2']);
    expect(calls).toHaveLength(1);
  });

  it('reports a user who has never authorised rather than inventing a token', async () => {
    const oauth = oauthFor(pool);
    await expect(
      oauth.getAccessToken(platformFor(origin), contextFor({ subject: 'stranger' })),
    ).rejects.toThrow(/no Canvas authorisation stored/);
  });

  it('does not cache a token when the refresh fails', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    await authorize(oauth, context);
    oauth.forget(context);

    nextResponse = { status: 400, body: { error: 'invalid_grant' } };
    await expect(oauth.getAccessToken(platformFor(origin), context)).rejects.toThrow(
      /token_endpoint_error/,
    );

    nextResponse = { status: 200, body: { access_token: 'access-3', expires_in: 3600 } };
    expect(await oauth.getAccessToken(platformFor(origin), context)).toBe('access-3');
  });
});

suite('revoke', () => {
  it('removes the stored authorization', async () => {
    const keyRing = testKeyRing();
    const oauth = oauthFor(pool, keyRing);
    const context = contextFor();
    const { state } = await oauth.beginAuthorization(platformFor(origin), context);
    await oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context);

    await oauth.revoke(platformFor(origin), context);

    expect(await new TokenStore(pool, keyRing).load(context)).toBeUndefined();
  });

  it('tells Canvas, carrying the access token rather than the refresh token', async () => {
    const oauth = oauthFor(pool);
    const context = contextFor();
    const { state } = await oauth.beginAuthorization(platformFor(origin), context);
    await oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context);
    calls = [];

    await oauth.revoke(platformFor(origin), context);

    expect(calls[0]?.authorization).toBe('Bearer access-1');
    expect(JSON.stringify(calls[0]?.form.toString())).not.toContain('refresh-1');
  });

  it('removes the local authorization even when Canvas refuses', async () => {
    const keyRing = testKeyRing();
    const oauth = oauthFor(pool, keyRing);
    const context = contextFor();
    const { state } = await oauth.beginAuthorization(platformFor(origin), context);
    await oauth.completeAuthorization(platformFor(origin), { state, code: 'c' }, context);

    nextResponse = { status: 500, body: { error: 'server_error' } };
    await oauth.revoke(platformFor(origin), context);

    expect(await new TokenStore(pool, keyRing).load(context)).toBeUndefined();
  });

  it('is safe to call for a user who never authorised', async () => {
    const oauth = oauthFor(pool);
    await expect(
      oauth.revoke(platformFor(origin), contextFor({ subject: 'stranger' })),
    ).resolves.toBeUndefined();
  });
});
