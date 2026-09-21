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
const storageServers: Server[] = [];

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
  await Promise.all(
    [server, ...storageServers].map(
      (instance) =>
        new Promise<void>((resolve) => {
          instance.closeAllConnections();
          instance.close(() => {
            resolve();
          });
        }),
    ),
  );
});

beforeEach(() => {
  seenAuthorization = [];
  route = () => undefined;
});

/**
 * A second server standing in for a Canvas files domain or object storage. It records
 * whether it was sent an Authorization header, which is the point of several tests: the
 * user's Canvas token must never reach it.
 */
async function startStorageServer(body: string) {
  let sawAuthorization: string | undefined;
  const storage = createServer((req, res) => {
    sawAuthorization = req.headers.authorization;
    res.writeHead(200, { 'content-type': 'text/markdown' });
    res.end(body);
  });
  storageServers.push(storage);

  await new Promise<void>((resolve) => {
    storage.listen(0, '127.0.0.1', resolve);
  });
  const address = storage.address();
  if (typeof address === 'string' || address === null) throw new Error('no port');

  return { port: address.port, sawAuthorization: () => sawAuthorization };
}

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
  /**
   * The download now goes through the `url` the File object carries, because Canvas
   * publishes scopes only for /api/v1 and /api/sis routes and the web download route
   * therefore cannot be granted. See ADR-002.
   */
  function serveFile(body: string, meta: Record<string, unknown> = {}) {
    route = (path) => {
      if (path.startsWith('/api/v1/courses/42/files/77')) {
        return {
          status: 200,
          body: JSON.stringify(
            fileJson({
              size: body.length,
              url: `${origin}/files/77/download?download_frd=1&verifier=secret-attachment-uuid`,
              ...meta,
            }),
          ),
        };
      }
      if (path.startsWith('/files/77/download')) {
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

  it('asks Canvas for the metadata through the course-scoped route, first', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      if (path.includes('/api/v1/')) {
        return {
          status: 200,
          body: JSON.stringify(fileJson({ url: `${origin}/files/77/download?verifier=v` })),
        };
      }
      return { status: 200, body: '# ok' };
    };

    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(paths[0]).toBe('/api/v1/courses/42/files/77');
    expect(paths[1]).toContain('/files/77/download');
  });

  it('sends the user’s token to the metadata call and to nothing else', async () => {
    serveFile('# ok');
    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    // The metadata request is authorised; the download is not, because the URL
    // authenticates itself and the storage host must never see the user's credential.
    expect(seenAuthorization[0]).toBe(`Bearer ${TOKEN}`);
    expect(seenAuthorization[1]).toBeUndefined();
  });

  it('uses the URL Canvas supplied rather than constructing one', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      if (path.includes('/api/v1/')) {
        return {
          status: 200,
          body: JSON.stringify(fileJson({ url: `${origin}/some/other/place?token=canvas-issued` })),
        };
      }
      return { status: 200, body: '# ok' };
    };

    await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(paths[1]).toContain('/some/other/place');
    expect(paths.some((p) => p.includes('/courses/42/files/77/download'))).toBe(false);
  });

  it('never exposes the ephemeral URL on the returned document', async () => {
    serveFile('# ok');
    const doc = await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    const serialised = JSON.stringify(doc);
    expect(serialised).not.toContain('secret-attachment-uuid');
    expect(serialised).not.toContain('verifier');
    expect(doc.file).not.toHaveProperty('url');
    expect(doc.file).not.toHaveProperty('downloadUrl');
  });

  it('redacts the query of every hop it reports', async () => {
    route = (path) => {
      if (path.includes('/api/v1/')) {
        return {
          status: 200,
          body: JSON.stringify(
            fileJson({ url: `${origin}/files/77/download?verifier=secret-attachment-uuid` }),
          ),
        };
      }
      if (path.startsWith('/files/77/download')) {
        return {
          status: 302,
          body: '',
          headers: { location: `${origin}/storage/blob?signature=secret-signature` },
        };
      }
      return { status: 200, body: '# ok' };
    };

    const doc = await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);

    expect(doc.text).toBe('# ok');
    for (const hop of doc.via) {
      expect(hop).not.toContain('secret-attachment-uuid');
      expect(hop).not.toContain('secret-signature');
      expect(hop).toContain('[redacted]');
    }
  });

  it('refuses a file that is not Markdown before requesting any content', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      return {
        status: 200,
        body: JSON.stringify(
          fileJson({
            display_name: 'informe.pdf',
            'content-type': 'application/pdf',
            url: `${origin}/files/77/download?verifier=v`,
          }),
        ),
      };
    };

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /not_markdown/,
    );
    expect(paths).toHaveLength(1);
  });

  it('refuses a file larger than the limit before requesting any content', async () => {
    const paths: string[] = [];
    route = (path) => {
      paths.push(path);
      return {
        status: 200,
        body: JSON.stringify(
          fileJson({ size: 9_000_000, url: `${origin}/files/77/download?verifier=v` }),
        ),
      };
    };

    await expect(
      client(1_000_000).fetchMarkdown(platformFor(origin), '42', '77', TOKEN),
    ).rejects.toThrow(/too_large/);
    expect(paths).toHaveLength(1);
  });

  it('fails safely when the File object carries no url', async () => {
    route = () => ({ status: 200, body: JSON.stringify(fileJson({ url: '' })) });

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /no_download_url/,
    );
  });

  it('fails safely when the url field is missing altogether', async () => {
    route = () => {
      const file = fileJson();
      delete file['url'];
      return { status: 200, body: JSON.stringify(file) };
    };

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /no_download_url/,
    );
  });

  it('fails safely when the url is not a string', async () => {
    route = () => ({ status: 200, body: JSON.stringify(fileJson({ url: { href: 'x' } })) });

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /no_download_url/,
    );
  });

  it('refuses a url pointing at a host that is not allowed', async () => {
    route = () => ({
      status: 200,
      body: JSON.stringify(fileJson({ url: 'https://evil.example/steal?verifier=v' })),
    });

    await expect(client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN)).rejects.toThrow(
      /host_not_allowed/,
    );
  });

  it('accepts a url on a host the operator listed for downloads', async () => {
    const storage = await startStorageServer('# from storage');
    route = (path) =>
      path.includes('/api/v1/')
        ? {
            status: 200,
            body: JSON.stringify(
              fileJson({ url: `http://127.0.0.1:${storage.port}/blob?signature=s` }),
            ),
          }
        : undefined;

    const doc = await client().fetchMarkdown(platformFor(origin, ['127.0.0.1']), '42', '77', TOKEN);

    expect(doc.text).toBe('# from storage');
    expect(storage.sawAuthorization()).toBeUndefined();
  });

  it('drops nothing to leak when the url redirects to storage', async () => {
    const storage = await startStorageServer('# redirected');
    route = (path) => {
      if (path.includes('/api/v1/')) {
        return {
          status: 200,
          body: JSON.stringify(
            fileJson({ url: `${origin}/files/77/download?verifier=secret-attachment-uuid` }),
          ),
        };
      }
      return {
        status: 302,
        body: '',
        headers: { location: `http://127.0.0.1:${storage.port}/blob?signature=s` },
      };
    };

    const doc = await client().fetchMarkdown(platformFor(origin, ['127.0.0.1']), '42', '77', TOKEN);

    expect(doc.text).toBe('# redirected');
    expect(storage.sawAuthorization()).toBeUndefined();
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
        ? {
            status: 200,
            body: JSON.stringify(
              fileJson({ size: 10, url: `${origin}/files/77/download?verifier=v` }),
            ),
          }
        : { status: 200, body: 'x'.repeat(50_000) };

    await expect(
      client(1_000).fetchMarkdown(platformFor(origin), '42', '77', TOKEN),
    ).rejects.toThrow(/response_too_large/);
  });

  it('keeps the ephemeral url out of the error it raises', async () => {
    route = () => ({
      status: 200,
      body: JSON.stringify(
        fileJson({ url: 'https://evil.example/steal?verifier=secret-attachment-uuid' }),
      ),
    });

    let error: Error | undefined;
    try {
      await client().fetchMarkdown(platformFor(origin), '42', '77', TOKEN);
    } catch (thrown) {
      error = thrown as Error;
    }

    expect(error).toBeDefined();
    expect(error!.message).not.toContain('secret-attachment-uuid');
    // Every own property, not just the message: a detail field leaks just as readily.
    expect(JSON.stringify(error, Object.getOwnPropertyNames(error!))).not.toContain(
      'secret-attachment-uuid',
    );
  });
});
