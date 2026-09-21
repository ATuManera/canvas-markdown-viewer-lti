import { createServer, type Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { FetchDenied, SafeFetcher, type SafeFetchOptions } from '../../src/canvas/safe-fetch.ts';

/**
 * These tests run a real HTTP server on loopback. `allowPrivateAddresses` is therefore on
 * where a request is expected to succeed, and deliberately off in the SSRF tests — the two
 * flags are separate precisely so that plain http does not imply "private is fine".
 */

type Handler = Parameters<typeof createServer>[1];

const servers: Server[] = [];

async function startServer(handler: Handler): Promise<{ port: number; origin: string }> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');
  return { port: address.port, origin: `http://localhost:${address.port}` };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => {
            resolve();
          });
        }),
    ),
  );
});

function fetcher(overrides: Partial<SafeFetchOptions> = {}): SafeFetcher {
  return new SafeFetcher({
    allowedHosts: ['localhost'],
    maxRedirects: 3,
    timeoutMs: 2_000,
    maxBytes: 1_000,
    allowInsecureScheme: true,
    allowPrivateAddresses: true,
    ...overrides,
  });
}

async function expectDenied(promise: Promise<unknown>, reason: string): Promise<FetchDenied> {
  try {
    await promise;
    expect.unreachable(`expected denial: ${reason}`);
  } catch (error) {
    expect(error).toBeInstanceOf(FetchDenied);
    expect((error as FetchDenied).reason).toBe(reason);
    return error as FetchDenied;
  }
}

describe('SafeFetcher — the happy path', () => {
  it('reads a 200 response body', async () => {
    const { origin } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/markdown' });
      res.end('# Hola');
    });

    const response = await fetcher().fetch(`${origin}/file.md`);

    expect(response.status).toBe(200);
    expect(response.body.toString()).toBe('# Hola');
    expect(response.redirects).toEqual([]);
  });

  it('forwards the Authorization header the caller supplies', async () => {
    let seen: string | undefined;
    const { origin } = await startServer((req, res) => {
      seen = req.headers.authorization;
      res.end('ok');
    });

    await fetcher().fetch(`${origin}/x`, { headers: { authorization: 'Bearer test-token' } });

    expect(seen).toBe('Bearer test-token');
  });

  it('follows a redirect within the allowlist and reports the hops', async () => {
    const { origin } = await startServer((req, res) => {
      if (req.url === '/start') {
        res.writeHead(302, { location: '/final' });
        res.end();
        return;
      }
      res.end('arrived');
    });

    const response = await fetcher().fetch(`${origin}/start`);

    expect(response.body.toString()).toBe('arrived');
    expect(response.redirects).toHaveLength(1);
    expect(response.finalUrl).toBe(`${origin}/final`);
  });
});

describe('SafeFetcher — SSRF defences', () => {
  it('refuses plain http when the insecure scheme is not permitted', async () => {
    const { origin } = await startServer((_req, res) => res.end('ok'));
    await expectDenied(
      fetcher({ allowInsecureScheme: false }).fetch(`${origin}/x`),
      'insecure_scheme',
    );
  });

  it('refuses a non-http scheme outright', async () => {
    await expectDenied(fetcher().fetch('file:///etc/passwd'), 'insecure_scheme');
  });

  it('refuses a host that is not on the allowlist', async () => {
    const { port } = await startServer((_req, res) => res.end('ok'));
    await expectDenied(fetcher().fetch(`http://127.0.0.1:${port}/x`), 'host_not_allowed');
  });

  it('refuses a host resolving to loopback when private addresses are not permitted', async () => {
    const { origin } = await startServer((_req, res) => res.end('ok'));
    await expectDenied(
      fetcher({ allowPrivateAddresses: false }).fetch(`${origin}/x`),
      'private_address',
    );
  });

  it('refuses the cloud metadata endpoint', async () => {
    const strict = new SafeFetcher({
      allowedHosts: ['169.254.169.254'],
      maxRedirects: 0,
      timeoutMs: 500,
      maxBytes: 1_000,
      allowInsecureScheme: true,
    });
    await expectDenied(strict.fetch('http://169.254.169.254/latest/meta-data/'), 'private_address');
  });

  it('refuses an RFC1918 destination', async () => {
    const strict = new SafeFetcher({
      allowedHosts: ['10.1.2.3'],
      maxRedirects: 0,
      timeoutMs: 500,
      maxBytes: 1_000,
      allowInsecureScheme: true,
    });
    await expectDenied(strict.fetch('http://10.1.2.3/internal'), 'private_address');
  });

  it('validates the destination of a redirect, not only the first request', async () => {
    const { origin } = await startServer((_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });

    await expectDenied(fetcher().fetch(`${origin}/start`), 'host_not_allowed');
  });

  it('refuses a redirect that leaves the allowlist even for a public host', async () => {
    const { origin } = await startServer((_req, res) => {
      res.writeHead(302, { location: 'https://evil.example/payload' });
      res.end();
    });

    await expectDenied(fetcher().fetch(`${origin}/start`), 'host_not_allowed');
  });

  it('refuses a redirect to a private address even when its host is allowed', async () => {
    const { origin, port } = await startServer((req, res) => {
      if (req.url === '/start') {
        res.writeHead(302, { location: `http://localhost:${port}/final` });
        res.end();
        return;
      }
      res.end('should never be read');
    });

    // The first hop resolves through a permissive fetcher; the redirect target is then
    // rejected by a fetcher that does not allow private addresses.
    const strict = new SafeFetcher({
      allowedHosts: ['localhost'],
      maxRedirects: 2,
      timeoutMs: 2_000,
      maxBytes: 1_000,
      allowInsecureScheme: true,
      allowPrivateAddresses: false,
    });

    await expectDenied(strict.fetch(`${origin}/start`), 'private_address');
  });

  it('stops after the configured number of redirects', async () => {
    let hops = 0;
    const { origin } = await startServer((_req, res) => {
      hops += 1;
      res.writeHead(302, { location: `/hop-${hops}` });
      res.end();
    });

    await expectDenied(fetcher({ maxRedirects: 2 }).fetch(`${origin}/start`), 'too_many_redirects');
    expect(hops).toBe(3);
  });

  it('refuses a redirect with no Location header', async () => {
    const { origin } = await startServer((_req, res) => {
      res.writeHead(302);
      res.end();
    });

    await expectDenied(fetcher().fetch(`${origin}/start`), 'redirect_without_location');
  });

  it('refuses a URL carrying embedded credentials', async () => {
    const { port } = await startServer((_req, res) => res.end('ok'));
    await expectDenied(
      fetcher().fetch(`http://user:pass@localhost:${port}/x`),
      'credentials_in_url',
    );
  });
});

describe('SafeFetcher — resource limits', () => {
  it('refuses a body that declares more than the limit', async () => {
    const { origin } = await startServer((_req, res) => {
      const payload = 'x'.repeat(5_000);
      res.writeHead(200, { 'content-length': String(payload.length) });
      res.end(payload);
    });

    await expectDenied(fetcher({ maxBytes: 1_000 }).fetch(`${origin}/big`), 'response_too_large');
  });

  it('refuses a body that exceeds the limit while streaming, despite an honest-looking header', async () => {
    const { origin } = await startServer((_req, res) => {
      // Chunked: no content-length to inspect up front.
      res.writeHead(200, { 'transfer-encoding': 'chunked' });
      for (let i = 0; i < 50; i += 1) res.write('x'.repeat(200));
      res.end();
    });

    await expectDenied(fetcher({ maxBytes: 1_000 }).fetch(`${origin}/big`), 'response_too_large');
  });

  it('accepts a body exactly at the limit', async () => {
    const { origin } = await startServer((_req, res) => {
      res.end('x'.repeat(1_000));
    });

    const response = await fetcher({ maxBytes: 1_000 }).fetch(`${origin}/edge`);
    expect(response.body.length).toBe(1_000);
  });

  it('gives up on a server that never answers', async () => {
    const { origin } = await startServer(() => {
      // Deliberately no response.
    });

    await expectDenied(fetcher({ timeoutMs: 150 }).fetch(`${origin}/slow`), 'timeout');
  });

  it('reports an upstream error status without exposing the body', async () => {
    const { origin } = await startServer((_req, res) => {
      res.writeHead(403);
      res.end('detailed internal explanation');
    });

    const error = await expectDenied(fetcher().fetch(`${origin}/denied`), 'http_error');
    expect(error.status).toBe(403);
    expect(error.message).not.toContain('detailed internal explanation');
  });
});
