import { createServer, type Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig, type Config } from '../../src/config/env.ts';
import type { DbPool } from '../../src/db/pool.ts';
import { silentLogger } from '../../src/logging/logger.ts';
import { buildServer } from '../../src/web/server.ts';
import { SessionCodec } from '../../src/web/session.ts';
import { frameAncestorsFor, contentSecurityPolicy } from '../../src/web/security-headers.ts';
import { hasDatabase, setupDatabase, truncateAll } from '../helpers/db.ts';
import {
  buildPlatform,
  CLIENT_ID,
  COURSE_ID,
  createSigningKey,
  DEPLOYMENT_ID,
  ISSUER,
  launchClaims,
} from '../helpers/lti-fixtures.ts';

const suite = hasDatabase ? describe : describe.skip;

const STATE_SECRET = 'x'.repeat(48);
const PUBLIC_URL = 'https://markdown.test.edu';

let pool: DbPool;
let app: FastifyInstance;
let config: Config;
let canvas: Server;
let canvasOrigin: string;

/** A Canvas double: the JWKS is not used (tests inject the key) but the API is. */
let canvasHandler: (url: string) => { status: number; body: string } = () => ({
  status: 200,
  body: '[]',
});

function buildConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    NODE_ENV: 'test',
    PUBLIC_URL,
    DATABASE_URL: process.env['TEST_DATABASE_URL'] ?? '',
    ENCRYPTION_KEYS: `1:${randomBytes(32).toString('base64')}`,
    STATE_SECRET,
    DEFAULT_LOCALE: 'es',
    CANVAS_PLATFORMS: JSON.stringify([
      {
        ...buildPlatform(),
        apiBaseUrl: canvasOrigin,
      },
    ]),
    ...overrides,
  });
}

beforeAll(async () => {
  if (!hasDatabase) return;

  canvas = createServer((request, response) => {
    const answer = canvasHandler(request.url ?? '');
    response.writeHead(answer.status, { 'content-type': 'application/json' });
    response.end(answer.body);
  });
  await new Promise<void>((resolve) => {
    canvas.listen(0, '127.0.0.1', resolve);
  });
  const address = canvas.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');
  canvasOrigin = `http://localhost:${address.port}`;

  pool = await setupDatabase('test_server');
  config = buildConfig();
  ({ app } = await buildServer({ config, pool, logger: silentLogger }));
  await app.ready();
});

afterAll(async () => {
  if (!hasDatabase) return;
  await app.close();
  await pool.end();
  await new Promise<void>((resolve) => {
    canvas.closeAllConnections();
    canvas.close(() => {
      resolve();
    });
  });
});

beforeEach(async () => {
  if (!hasDatabase) return;
  await truncateAll(pool);
  canvasHandler = () => ({ status: 200, body: '[]' });
});

describe('security headers', () => {
  const platform = buildPlatform();

  it('permits framing only by the configured Canvas instances', () => {
    const ancestors = frameAncestorsFor([platform]);
    expect(ancestors).toContain('https://canvas.test.edu');
    expect(ancestors).not.toContain('*');
  });

  it('falls back to none rather than to a wildcard', () => {
    expect(contentSecurityPolicy([])).toContain("frame-ancestors 'none'");
  });

  it('denies everything by default and allows scripts only from this origin', () => {
    const policy = contentSecurityPolicy([platform]);
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("script-src 'self'");
    expect(policy).toContain("style-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("base-uri 'none'");
    expect(policy).toContain("form-action 'self'");
  });

  it('never allows unsafe-inline for styles', () => {
    expect(contentSecurityPolicy([platform])).not.toContain('unsafe-inline');
  });

  it('adds a nonce only when the relay pages need one', () => {
    expect(contentSecurityPolicy([platform], { scriptNonce: 'abc' })).toContain("'nonce-abc'");
    expect(contentSecurityPolicy([platform])).not.toContain('nonce-');
  });

  it('keeps remote images out of the policy unless the operator allows them', () => {
    expect(contentSecurityPolicy([platform])).toContain("img-src 'self' data:");
    expect(contentSecurityPolicy([platform], { allowExternalImages: true })).toContain(
      "img-src 'self' data: https:",
    );
  });
});

suite('health', () => {
  it('reports ok while the database answers', async () => {
    const response = await app.inject({ method: 'GET', url: '/healthz' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });

  it('is never cached', async () => {
    const response = await app.inject({ method: 'GET', url: '/healthz' });
    expect(response.headers['cache-control']).toContain('no-store');
  });
});

suite('LTI login', () => {
  it('redirects to the platform when Platform Storage is unavailable', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: { iss: ISSUER, login_hint: 'user-1', client_id: CLIENT_ID },
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers['location']).toContain('/api/lti/authorize_redirect');
    expect(response.headers['location']).toContain('response_mode=form_post');
  });

  it('renders the storage relay when Canvas offers Platform Storage', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: {
        iss: ISSUER,
        login_hint: 'user-1',
        client_id: CLIENT_ID,
        lti_storage_target: 'post_message_forwarding',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('lti.put_data');
    expect(response.body).toContain('post_message_forwarding');
  });

  it('gives the relay page a nonce that matches its policy', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: {
        iss: ISSUER,
        login_hint: 'user-1',
        client_id: CLIENT_ID,
        lti_storage_target: '_parent',
      },
    });

    const policy = String(response.headers['content-security-policy']);
    const nonce = /'nonce-([^']+)'/.exec(policy)?.[1];
    expect(nonce).toBeTruthy();
    expect(response.body).toContain(`<script nonce="${nonce}">`);
  });

  it('refuses a login from an unregistered issuer', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: { iss: 'https://evil.example', login_hint: 'u' },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain('unknown_platform');
  });

  it('never caches a launch response', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: { iss: ISSUER, login_hint: 'u', client_id: CLIENT_ID },
    });
    expect(response.headers['cache-control']).toContain('no-store');
  });
});

suite('LTI launch', () => {
  async function login(storageTarget?: string) {
    const response = await app.inject({
      method: 'POST',
      url: '/lti/login',
      payload: {
        iss: ISSUER,
        login_hint: 'user-1',
        client_id: CLIENT_ID,
        ...(storageTarget ? { lti_storage_target: storageTarget } : {}),
      },
    });

    const location = response.headers['location'];
    if (typeof location === 'string') {
      const url = new URL(location);
      return { state: url.searchParams.get('state')!, nonce: url.searchParams.get('nonce')! };
    }
    const state = /state-([A-Za-z0-9_-]+)/.exec(response.body)?.[1];
    const nonceMatch = /"value":"([A-Za-z0-9_-]+)"/.exec(response.body);
    return { state: state ?? '', nonce: nonceMatch?.[1] ?? '' };
  }

  it('rejects a launch with no id_token', async () => {
    const response = await app.inject({ method: 'POST', url: '/lti/launch', payload: {} });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a forged id_token', async () => {
    const { state } = await login();
    const attacker = await createSigningKey('attacker');
    const idToken = await attacker.sign(launchClaims({ nonce: 'whatever' }));

    const response = await app.inject({
      method: 'POST',
      url: '/lti/launch',
      payload: { id_token: idToken, state },
    });

    expect(response.statusCode).toBe(400);
    // The page must not disclose which check failed.
    expect(response.body).not.toMatch(/signature|nonce|deployment/i);
  });

  it('shows a generic message and a support reference on rejection', async () => {
    const response = await app.inject({ method: 'POST', url: '/lti/launch', payload: {} });
    expect(response.body).toContain('Referencia para soporte');
  });
});

suite('session handling', () => {
  const sessions = new SessionCodec({ secret: STATE_SECRET });

  function sessionToken(overrides: Partial<Parameters<typeof sessions.issue>[0]> = {}): string {
    return sessions.issue({
      issuer: ISSUER,
      deploymentId: DEPLOYMENT_ID,
      subject: 'lti-user-1',
      canvasCourseId: COURSE_ID,
      locale: 'es',
      ...overrides,
    }).token;
  }

  it('refuses a request with no session', async () => {
    const response = await app.inject({ method: 'POST', url: '/app/files', payload: {} });
    expect(response.statusCode).toBe(401);
  });

  it('refuses a session signed with another secret', async () => {
    const other = new SessionCodec({ secret: 'y'.repeat(48) });
    const token = other.issue({
      issuer: ISSUER,
      deploymentId: DEPLOYMENT_ID,
      subject: 'mallory',
      canvasCourseId: COURSE_ID,
      locale: 'es',
    }).token;

    const response = await app.inject({
      method: 'POST',
      url: '/app/files',
      payload: { session: token },
    });

    expect(response.statusCode).toBe(401);
  });

  it('offers the authorisation page to a user who has not authorised', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/app/start',
      payload: { launch: sessionToken() },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('Autorizar');
    expect(response.body).toContain('Abrir en ventana completa');
  });

  it('explains when the launch carried no course', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/app/start',
      payload: { launch: sessionToken({ canvasCourseId: undefined }) },
    });

    expect(response.body).toContain('archivos de un curso');
  });

  it('never puts the session token in a URL', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/app/start',
      payload: { launch: sessionToken() },
    });

    const hrefs = [...response.body.matchAll(/href="([^"]*)"/g)].map((m) => m[1] ?? '');
    for (const href of hrefs) {
      expect(href).not.toContain('session=');
      expect(href).not.toContain('launch=');
    }
  });

  it('carries the session in a hidden form field instead', async () => {
    const token = sessionToken();
    const response = await app.inject({
      method: 'POST',
      url: '/app/start',
      payload: { launch: token },
    });

    expect(response.body).toContain(`name="session" value="${token}"`);
  });

  it('sets the session cookie with the attributes a cross-site iframe needs', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/app/authorize',
      payload: { session: sessionToken() },
    });

    const cookie = response.headers['set-cookie'];
    const value = Array.isArray(cookie) ? cookie.join(';') : (cookie ?? '');
    expect(value).toContain('HttpOnly');
    expect(value).toContain('SameSite=None');
  });
});

suite('the viewer', () => {
  const sessions = new SessionCodec({ secret: STATE_SECRET });
  const token = () =>
    sessions.issue({
      issuer: ISSUER,
      deploymentId: DEPLOYMENT_ID,
      subject: 'lti-user-1',
      canvasCourseId: COURSE_ID,
      locale: 'es',
    }).token;

  async function authorise(subject = 'lti-user-1'): Promise<void> {
    const { TokenStore } = await import('../../src/canvas/token-store.ts');
    await new TokenStore(pool, config.keyRing).save(
      { issuer: ISSUER, deploymentId: DEPLOYMENT_ID, subject },
      'refresh-1',
    );
  }

  it('lists the course files once the user has authorised', async () => {
    await authorise();
    canvasHandler = (url) => {
      if (url.startsWith('/login/oauth2/token')) {
        return {
          status: 200,
          body: JSON.stringify({ access_token: 'access-1', expires_in: 3600 }),
        };
      }
      return {
        status: 200,
        body: JSON.stringify([
          { id: 1, display_name: 'apuntes.md', 'content-type': 'text/markdown', size: 42 },
          { id: 2, display_name: 'guia.pdf', 'content-type': 'application/pdf', size: 99 },
        ]),
      };
    };

    const response = await app.inject({
      method: 'POST',
      url: '/app/files',
      payload: { session: token() },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('apuntes.md');
    expect(response.body).toContain('Elige un archivo Markdown');
    expect(response.body).toContain('Canvas no comunica');
  });

  it('renders a document, sanitised, with the download control', async () => {
    await authorise();
    canvasHandler = (url) => {
      if (url.startsWith('/login/oauth2/token')) {
        return { status: 200, body: JSON.stringify({ access_token: 'a', expires_in: 3600 }) };
      }
      if (url.startsWith('/api/v1/courses/')) {
        return {
          status: 200,
          body: JSON.stringify({
            id: 1,
            display_name: 'apuntes.md',
            'content-type': 'text/markdown',
            size: 60,
          }),
        };
      }
      return { status: 200, body: '# Título\n\n<script>alert(1)</script>\n\nTexto.' };
    };

    const response = await app.inject({
      method: 'POST',
      url: '/app/view',
      payload: { session: token(), file: '1' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('<h1>Título</h1>');
    expect(response.body).toContain('Texto.');
    expect(response.body).not.toContain('<script>alert(1)</script>');
    expect(response.body).toContain('Descargar el original');
  });

  it('serves the original from this origin rather than redirecting to Canvas', async () => {
    await authorise();
    canvasHandler = (url) => {
      if (url.startsWith('/login/oauth2/token')) {
        return { status: 200, body: JSON.stringify({ access_token: 'a', expires_in: 3600 }) };
      }
      if (url.startsWith('/api/v1/courses/')) {
        return {
          status: 200,
          body: JSON.stringify({
            id: 1,
            display_name: 'apuntes.md',
            'content-type': 'text/markdown',
            size: 10,
          }),
        };
      }
      return { status: 200, body: '# Original' };
    };

    const response = await app.inject({
      method: 'POST',
      url: '/app/download',
      payload: { session: token(), file: '1' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/markdown');
    expect(response.headers['content-disposition']).toContain('apuntes.md');
    expect(response.body).toBe('# Original');
  });

  it('reports a file the user may not read without leaking Canvas detail', async () => {
    await authorise();
    canvasHandler = (url) =>
      url.startsWith('/login/oauth2/token')
        ? { status: 200, body: JSON.stringify({ access_token: 'a', expires_in: 3600 }) }
        : { status: 403, body: '{"status":"unauthorized","detail":"internal note"}' };

    const response = await app.inject({
      method: 'POST',
      url: '/app/view',
      payload: { session: token(), file: '1' },
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).toContain('No tienes permiso');
    expect(response.body).not.toContain('internal note');
  });

  it('applies the restrictive policy to every page it renders', async () => {
    await authorise();
    canvasHandler = (url) =>
      url.startsWith('/login/oauth2/token')
        ? { status: 200, body: JSON.stringify({ access_token: 'a', expires_in: 3600 }) }
        : { status: 200, body: '[]' };

    const response = await app.inject({
      method: 'POST',
      url: '/app/files',
      payload: { session: token() },
    });

    const policy = response.headers['content-security-policy'] as string;
    expect(policy).toContain("default-src 'none'");
    const ancestors = /frame-ancestors ([^;]+)/.exec(policy)?.[1] ?? '';
    expect(ancestors.split(' ')).toContain('https://canvas.test.edu');
    expect(ancestors).not.toContain('*');
    expect(response.headers['cache-control']).toContain('no-store');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });
});

suite('static assets', () => {
  it('serves the stylesheet and allows it to be cached', async () => {
    const response = await app.inject({ method: 'GET', url: '/assets/viewer.css' });
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toContain('max-age');
  });

  it('serves the one script the policy permits', async () => {
    const response = await app.inject({ method: 'GET', url: '/assets/viewer.js' });
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('requestFullWindowLaunch');
  });
});

suite('language', () => {
  it('renders in English when the launch says so', async () => {
    const sessions = new SessionCodec({ secret: STATE_SECRET });
    const token = sessions.issue({
      issuer: ISSUER,
      deploymentId: DEPLOYMENT_ID,
      subject: 'lti-user-en',
      canvasCourseId: COURSE_ID,
      locale: 'en',
    }).token;

    const response = await app.inject({
      method: 'POST',
      url: '/app/start',
      payload: { launch: token },
    });

    expect(response.body).toContain('Authorise access to your files');
    expect(response.body).toContain('lang="en"');
  });
});
