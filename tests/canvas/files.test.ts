import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CanvasFilesClient, FileError, nextPageUrl } from '../../src/canvas/files.ts';
import {
  ACCEPT_MEDIA_TYPES,
  decodeMarkdown,
  fileExtension,
  hasMarkdownExtension,
  isAcceptableMime,
  looksLikeMarkdown,
  normaliseMime,
} from '../../src/canvas/markdown-detection.ts';
import type { Platform } from '../../src/config/platforms.ts';

const TOKEN = 'user-access-token';

interface Route {
  (path: string): { status: number; body: string; headers?: Record<string, string> } | undefined;
}

let server: Server;
let origin: string;
let route: Route = () => undefined;
let seenAuthorization: (string | undefined)[] = [];

function platformFor(base: string, redirectHosts: string[] = []): Platform {
  return {
    issuer: 'https://canvas.test.edu',
    clientId: 'lti-client',
    deploymentIds: ['1:d'],
    authorizationEndpoint: 'https://canvas.test.edu/api/lti/authorize_redirect',
    jwksUri: 'https://canvas.test.edu/api/lti/security/jwks',
    apiBaseUrl: base,
    apiClientId: 'api-client',
    apiClientSecret: 'api-secret',
    downloadHostAllowlist: redirectHosts,
  };
}

function client(maxFileBytes = 1_000_000): CanvasFilesClient {
  return new CanvasFilesClient({
    maxFileBytes,
    fetchOptions: {
      maxRedirects: 2,
      timeoutMs: 2_000,
      maxBytes: maxFileBytes,
      allowInsecureScheme: true,
      allowPrivateAddresses: true,
    },
  });
}

function fileJson(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 77,
    display_name: 'apuntes.md',
    'content-type': 'text/markdown',
    size: 120,
    updated_at: '2026-09-01T10:00:00Z',
    folder_id: 3,
    ...overrides,
  };
}

beforeAll(async () => {
  server = createServer((req, res) => {
    seenAuthorization.push(req.headers.authorization);
    const answer = route(req.url ?? '');
    if (!answer) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"errors":[{"message":"not found"}]}');
      return;
    }
    res.writeHead(answer.status, { 'content-type': 'application/json', ...answer.headers });
    res.end(answer.body);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');
  origin = `http://localhost:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => {
      resolve();
    });
  });
});

beforeEach(() => {
  seenAuthorization = [];
  route = () => undefined;
});

describe('markdown detection — extension', () => {
  it('recognises the usual Markdown extensions', () => {
    for (const name of ['a.md', 'a.markdown', 'a.mdown', 'a.mkd', 'A.MD']) {
      expect(hasMarkdownExtension(name)).toBe(true);
    }
  });

  it('does not treat .mdx as Markdown, because it is Javascript', () => {
    expect(hasMarkdownExtension('component.mdx')).toBe(false);
  });

  it('rejects other extensions', () => {
    for (const name of ['a.pdf', 'a.txt.exe', 'a.html', 'archivo']) {
      expect(hasMarkdownExtension(name)).toBe(false);
    }
  });

  it('is not fooled by a dot in a directory name', () => {
    expect(fileExtension('notes.d/readme')).toBe('');
  });

  it('treats a leading dot as no extension', () => {
    expect(fileExtension('.md')).toBe('');
  });
});

describe('markdown detection — MIME', () => {
  it('strips the charset Canvas may append', () => {
    expect(normaliseMime('text/markdown; charset=utf-8')).toBe('text/markdown');
  });

  it('accepts the types Canvas actually stores .md files under', () => {
    for (const type of ACCEPT_MEDIA_TYPES) {
      expect(isAcceptableMime(type)).toBe(true);
    }
  });

  it('accepts a missing type, which Canvas produces for some uploads', () => {
    expect(isAcceptableMime(undefined)).toBe(true);
    expect(isAcceptableMime('')).toBe(true);
  });

  it('refuses types that are definitely not Markdown', () => {
    for (const type of ['application/pdf', 'text/html', 'image/png', 'application/zip']) {
      expect(isAcceptableMime(type)).toBe(false);
    }
  });

  it('requires the name and the type to agree', () => {
    expect(looksLikeMarkdown('apuntes.md', 'text/plain')).toBe(true);
    expect(looksLikeMarkdown('apuntes.md', 'application/pdf')).toBe(false);
    expect(looksLikeMarkdown('informe.pdf', 'text/markdown')).toBe(false);
  });
});

describe('markdown detection — content', () => {
  it('decodes UTF-8, including Spanish text', () => {
    const verdict = decodeMarkdown(Buffer.from('# Año académico — ñ', 'utf8'));
    expect(verdict).toEqual({ ok: true, text: '# Año académico — ñ' });
  });

  it('strips a UTF-8 byte order mark', () => {
    const body = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('# Hola', 'utf8')]);
    expect(decodeMarkdown(body)).toEqual({ ok: true, text: '# Hola' });
  });

  it('refuses a file containing a NUL byte, whatever it is called', () => {
    const body = Buffer.concat([Buffer.from('# Hola'), Buffer.from([0x00]), Buffer.from('x')]);
    expect(decodeMarkdown(body)).toEqual({ ok: false, reason: 'binary' });
  });

  it('refuses malformed UTF-8 rather than substituting replacement characters', () => {
    expect(decodeMarkdown(Buffer.from([0xc3, 0x28]))).toEqual({
      ok: false,
      reason: 'invalid_encoding',
    });
  });

  it('refuses an empty file', () => {
    expect(decodeMarkdown(Buffer.alloc(0))).toEqual({ ok: false, reason: 'empty' });
  });
});

describe('listFiles', () => {
  it('lists the course files and marks which are Markdown', async () => {
    route = (path) =>
      path.startsWith('/api/v1/courses/42/files')
        ? {
            status: 200,
            body: JSON.stringify([
              fileJson(),
              fileJson({ id: 78, display_name: 'guia.pdf', 'content-type': 'application/pdf' }),
              fileJson({ id: 79, display_name: 'plan.md', 'content-type': 'text/plain' }),
            ]),
          }
        : undefined;

    const files = await client().listFiles(platformFor(origin), '42', TOKEN);

    expect(files).toHaveLength(3);
    expect(files.filter((f) => f.isMarkdown).map((f) => f.displayName)).toEqual([
      'apuntes.md',
      'plan.md',
    ]);
  });

  it('sends the user’s token', async () => {
    route = () => ({ status: 200, body: '[]' });
    await client().listFiles(platformFor(origin), '42', TOKEN);
    expect(seenAuthorization[0]).toBe(`Bearer ${TOKEN}`);
  });

  it('passes a search term through to Canvas', async () => {
    let seenPath = '';
    route = (path) => {
      seenPath = path;
      return { status: 200, body: '[]' };
    };

    await client().listFiles(platformFor(origin), '42', TOKEN, { search: 'apuntes' });

    expect(seenPath).toContain('search_term=apuntes');
  });

  it('refuses a course id that is not a Canvas id', async () => {
    await expect(
      client().listFiles(platformFor(origin), '../../accounts/1', TOKEN),
    ).rejects.toThrow(/not_found/);
  });

  it('follows Link pagination within the Canvas host', async () => {
    route = (path) => {
      if (path.includes('page=2')) {
        return { status: 200, body: JSON.stringify([fileJson({ id: 80, display_name: 'b.md' })]) };
      }
      return {
        status: 200,
        body: JSON.stringify([fileJson({ id: 79, display_name: 'a.md' })]),
        headers: { link: `<${origin}/api/v1/courses/42/files?page=2>; rel="next"` },
      };
    };

    const files = await client().listFiles(platformFor(origin), '42', TOKEN);
    expect(files.map((f) => f.displayName)).toEqual(['a.md', 'b.md']);
  });

  it('stops after the configured number of pages', async () => {
    let requests = 0;
    route = () => {
      requests += 1;
      return {
        status: 200,
        body: JSON.stringify([fileJson()]),
        headers: { link: `<${origin}/api/v1/courses/42/files?page=${requests + 1}>; rel="next"` },
      };
    };

    const limited = new CanvasFilesClient({
      maxFileBytes: 1_000,
      maxPages: 3,
      fetchOptions: {
        maxRedirects: 0,
        timeoutMs: 2_000,
        maxBytes: 1_000,
        allowInsecureScheme: true,
        allowPrivateAddresses: true,
      },
    });
    await limited.listFiles(platformFor(origin), '42', TOKEN);

    expect(requests).toBe(3);
  });

  it('skips rows that do not look like files rather than failing the whole listing', async () => {
    route = () => ({
      status: 200,
      body: JSON.stringify([fileJson(), null, 'nonsense', { id: 1 }]),
    });

    const files = await client().listFiles(platformFor(origin), '42', TOKEN);
    expect(files).toHaveLength(1);
  });

  it('reports a permission failure as forbidden', async () => {
    route = () => ({ status: 403, body: '{"status":"unauthorized"}' });
    await expect(client().listFiles(platformFor(origin), '42', TOKEN)).rejects.toThrow(/forbidden/);
  });
});

describe('nextPageUrl', () => {
  const platform = platformFor('https://canvas.test.edu');

  it('finds the next link among several relations', () => {
    const header =
      '<https://canvas.test.edu/a?page=1>; rel="current",<https://canvas.test.edu/a?page=2>; rel="next"';
    expect(nextPageUrl(header, platform)).toBe('https://canvas.test.edu/a?page=2');
  });

  it('ignores a next link pointing at another host', () => {
    expect(nextPageUrl('<https://evil.example/a>; rel="next"', platform)).toBeUndefined();
  });

  it('returns undefined when there is no next link', () => {
    expect(nextPageUrl('<https://canvas.test.edu/a>; rel="last"', platform)).toBeUndefined();
    expect(nextPageUrl(undefined, platform)).toBeUndefined();
  });

  it('survives a malformed header', () => {
    expect(nextPageUrl('<not a url>; rel="next"', platform)).toBeUndefined();
  });
});

describe('fetchMarkdown', () => {
  function serveFile(body: string, meta: Record<string, unknown> = {}) {
    route = (path) => {
      if (path.startsWith('/api/v1/courses/42/files/77')) {
        return { status: 200, body: JSON.stringify(fileJson({ size: body.length, ...meta })) };
      }
      if (path.startsWith('/courses/42/files/77/download')) {
        return { status: 200, body };
      }
      return undefined;
    };
  }

  it('returns the document text', async () => {
    serveFile('# Apuntes\n\nContenido en español.');
    const doc = await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(doc.text).toBe('# Apuntes\n\nContenido en español.');
    expect(doc.file.displayName).toBe('apuntes.md');
  });

  it('asks Canvas for the metadata through the course-scoped route', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      if (path.includes('/api/v1/')) return { status: 200, body: JSON.stringify(fileJson()) };
      return { status: 200, body: '# ok' };
    };

    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(paths[0]).toBe('/api/v1/courses/42/files/77');
  });

  it('sends the user’s token on both calls', async () => {
    serveFile('# ok');
    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);
    expect(seenAuthorization).toEqual([`Bearer ${TOKEN}`, `Bearer ${TOKEN}`]);
  });

  it('never requests the download URL Canvas puts in the File object', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      if (path.includes('/api/v1/')) {
        return {
          status: 200,
          body: JSON.stringify(
            fileJson({ url: `${origin}/files/77/download?verifier=secret-uuid&download=1` }),
          ),
        };
      }
      return { status: 200, body: '# ok' };
    };

    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(paths.some((p) => p.includes('verifier='))).toBe(false);
    expect(paths[1]).toContain('/courses/42/files/77/download');
  });

  it('refuses a file that is not Markdown before downloading anything', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      return {
        status: 200,
        body: JSON.stringify(
          fileJson({ display_name: 'informe.pdf', 'content-type': 'application/pdf' }),
        ),
      };
    };

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /not_markdown/,
    );
    expect(paths).toHaveLength(1);
  });

  it('refuses a file larger than the limit before downloading anything', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      return { status: 200, body: JSON.stringify(fileJson({ size: 9_000_000 })) };
    };

    await expect(
      client(1_000_000).fetchMarkdown(platformFor(origin), '42', '77', TOKEN),
    ).rejects.toThrow(/too_large/);
    expect(paths).toHaveLength(1);
  });

  it('refuses a file whose body turns out to be binary despite its name', async () => {
    route = (path) =>
      path.includes('/api/v1/')
        ? { status: 200, body: JSON.stringify(fileJson()) }
        : { status: 200, body: 'PK\u0000\u0003binary' };

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /unreadable/,
    );
  });

  it('reports a file the user may not read as forbidden', async () => {
    route = () => ({ status: 401, body: '{"status":"unauthenticated"}' });
    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /forbidden/,
    );
  });

  it('reports a file from another course as not found, because Canvas says so', async () => {
    // The course-scoped route is what enforces membership: Canvas answers 404 for a file
    // that belongs elsewhere, so this tool does not have to infer the relationship.
    route = () => ({ status: 404, body: '{"errors":[{"message":"not found"}]}' });
    await expect(client().fetchMarkdown(platformFor(origin), '42', '99', TOKEN)).rejects.toThrow(
      /not_found/,
    );
  });

  it('refuses a file id that is not a Canvas id', async () => {
    await expect(
      client().fetchMarkdown(platformFor(origin), '42', '77/../../secrets', TOKEN),
    ).rejects.toThrow(FileError);
  });

  it('stops a download that exceeds the limit while streaming, despite honest metadata', async () => {
    route = (path) =>
      path.includes('/api/v1/')
        ? { status: 200, body: JSON.stringify(fileJson({ size: 10 })) }
        : { status: 200, body: 'x'.repeat(50_000) };

    await expect(
      client(1_000).fetchMarkdown(platformFor(origin), '42', '77', TOKEN),
    ).rejects.toThrow(/response_too_large/);
  });
});
