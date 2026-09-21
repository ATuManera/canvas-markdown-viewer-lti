import { describe, expect, it } from 'vitest';
import {
  createLogger,
  REDACTED,
  redact,
  type LogLevel,
  type LogRecord,
} from '../../src/logging/logger.ts';

function capture(level: LogLevel = 'trace') {
  const records: LogRecord[] = [];
  const logger = createLogger({ level, sink: (record) => void records.push(record) });
  return { logger, records, text: () => JSON.stringify(records) };
}

describe('redact', () => {
  it('removes values of forbidden keys regardless of spelling', () => {
    const out = redact({
      Authorization: 'Bearer abc123',
      access_token: 'secret-token',
      accessToken: 'secret-token',
      'set-cookie': 'session=1',
      clientSecret: 'shhh',
      verifier: 'attachment-uuid',
      content: '# my private notes',
    }) as Record<string, unknown>;

    for (const value of Object.values(out)) {
      expect(value).toBe(REDACTED);
    }
  });

  it('keeps harmless fields intact', () => {
    const out = redact({ courseId: 42, fileId: 7, issuer: 'https://canvas.example.edu' });
    expect(out).toEqual({ courseId: 42, fileId: 7, issuer: 'https://canvas.example.edu' });
  });

  it('strips bearer tokens found inside free text', () => {
    const out = redact('called API with Authorization: Bearer abc.def.ghi') as string;
    expect(out).not.toContain('abc.def.ghi');
    expect(out).toContain(REDACTED);
  });

  it('strips JWT-shaped values anywhere', () => {
    const jwt = `${'a'.repeat(20)}.${'b'.repeat(20)}.${'c'.repeat(20)}`;
    expect(redact(`launch id_token=${jwt} done`)).not.toContain(jwt);
  });

  it('strips the whole query string of a URL, keeping its origin and path', () => {
    // Deliberately wholesale rather than by parameter name: a list of names is always one
    // storage provider behind, and the failure mode is a credential in a log file.
    const out = redact(
      'https://canvas.example.edu/courses/1/files/2/download?verifier=abc123&download=1',
    ) as string;
    expect(out).not.toContain('abc123');
    expect(out).not.toContain('download=1');
    expect(out).toContain('https://canvas.example.edu/courses/1/files/2/download');
    expect(out).toContain('[redacted]');
  });

  it('leaves a URL without a query string untouched', () => {
    expect(redact('see https://canvas.example.edu/courses/1/files')).toBe(
      'see https://canvas.example.edu/courses/1/files',
    );
  });

  it('does not swallow the punctuation that follows a URL in a sentence', () => {
    const out = redact('fetched https://canvas.example.edu/a?b=c, then stopped.') as string;
    expect(out).toContain('[redacted],');
    expect(out).toContain('then stopped.');
  });

  it('redacts inside nested structures', () => {
    const out = redact({ request: { headers: { cookie: 'a=b' } } }) as {
      request: { headers: { cookie: unknown } };
    };
    expect(out.request.headers.cookie).toBe(REDACTED);
  });

  it('never renders a Buffer’s contents', () => {
    expect(redact(Buffer.from('super secret key material'))).toBe('[buffer 25B]');
  });

  it('truncates very long strings so a document cannot be logged wholesale', () => {
    const out = redact('x'.repeat(5000)) as string;
    expect(out.length).toBeLessThan(600);
    expect(out).toContain('[truncated]');
  });

  it('stops at a bounded depth', () => {
    let deep: Record<string, unknown> = { value: 'leaf' };
    for (let i = 0; i < 20; i += 1) deep = { nested: deep };
    expect(() => redact(deep)).not.toThrow();
    expect(JSON.stringify(redact(deep))).toContain('[truncated]');
  });

  it('reduces an Error to name and message', () => {
    const out = redact(new Error('boom')) as { name: string; message: string; stack?: unknown };
    expect(out).toEqual({ name: 'Error', message: 'boom' });
    expect(out.stack).toBeUndefined();
  });
});

describe('redact — Canvas download URLs', () => {
  /**
   * The content URL Canvas puts on a File object carries `verifier`, the attachment's
   * UUID, which grants access to the file on its own. These are the shapes it takes.
   */
  const urls = [
    'https://canvas.example.edu/files/77/download?download_frd=1&verifier=9f8e7d6c5b4a',
    'https://files.example.edu/files/77/download?verifier=9f8e7d6c5b4a&inline=1',
    'https://canvas.example.edu/courses/1/files/2/download?sf_verifier=eyJhbGciOiJIUzI1NiJ9',
    'https://storage.example.com/blob?X-Amz-Signature=9f8e7d6c5b4a',
    'https://canvas.example.edu/files/77/download?verifier=9f8e7d6c5b4a#fragment',
  ];

  for (const url of urls) {
    it(`strips the credential from ${new URL(url).host}`, () => {
      const out = redact(url) as string;
      expect(out).not.toContain('9f8e7d6c5b4a');
      expect(out).not.toContain('eyJhbGciOiJIUzI1NiJ9');
    });
  }

  it('keeps enough of the URL to be useful for diagnosis', () => {
    const out = redact(urls[0]) as string;
    expect(out).toContain('canvas.example.edu');
    expect(out).toContain('/files/77/download');
  });

  it('strips it from a nested field as well as from free text', () => {
    const out = redact({ downloadUrl: urls[0], note: `fetched ${urls[0]}` });
    expect(JSON.stringify(out)).not.toContain('9f8e7d6c5b4a');
  });
});

describe('logger', () => {
  it('honours the level threshold', () => {
    const records: LogRecord[] = [];
    const logger = createLogger({ level: 'warn', sink: (r) => void records.push(r) });
    logger.info('ignored');
    logger.warn('kept');
    expect(records.map((r) => r.msg)).toEqual(['kept']);
  });

  it('redacts fields passed at the call site', () => {
    const { logger, text } = capture();
    logger.info('fetched file', { fileId: 9, access_token: 'leak-me' });
    expect(text()).not.toContain('leak-me');
    expect(text()).toContain('"fileId":9');
  });

  it('redacts the message itself', () => {
    const { logger, text } = capture();
    logger.error('failed with Bearer sk-do-not-log-this');
    expect(text()).not.toContain('sk-do-not-log-this');
  });

  it('redacts fields inherited from a child logger', () => {
    const records: LogRecord[] = [];
    const logger = createLogger({ level: 'trace', sink: (r) => void records.push(r) }).child({
      refreshToken: 'inherited-secret',
      issuer: 'https://canvas.example.edu',
    });
    logger.info('hello');
    expect(JSON.stringify(records)).not.toContain('inherited-secret');
    expect(records[0]?.['issuer']).toBe('https://canvas.example.edu');
  });

  it('emits a level and an ISO timestamp on every record', () => {
    const { logger, records } = capture();
    logger.debug('tick');
    expect(records[0]?.level).toBe('debug');
    expect(() => new Date(records[0]!.time).toISOString()).not.toThrow();
  });

  it('cannot be tricked into logging document content through a "content" field', () => {
    const { logger, text } = capture();
    logger.info('rendered', { content: '# Secret heading\nconfidential body' });
    expect(text()).not.toContain('confidential body');
  });
});
