/**
 * Structured logging with mandatory redaction.
 *
 * The privacy policy commits to never logging document content, tokens, client secrets,
 * Canvas file `verifier` values, cookies, authorization headers, names or email addresses.
 * Rather than trusting every call site to remember that, this module removes them on the
 * way out, and `tests/logging/redaction.test.ts` asserts it.
 */

export const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const LEVEL_RANK: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};

export const REDACTED = '[redacted]';

/**
 * Field names whose values never appear in a log line, whatever they contain.
 * Matching is case-insensitive and ignores `-` and `_`, so `Authorization`,
 * `authorization`, `access_token` and `accessToken` all collapse to the same key.
 */
const FORBIDDEN_KEYS = new Set(
  [
    'authorization',
    'proxyauthorization',
    'cookie',
    'setcookie',
    'accesstoken',
    'refreshtoken',
    'idtoken',
    'token',
    'clientsecret',
    'secret',
    'password',
    'apikey',
    'verifier',
    'sfverifier',
    'codeverifier',
    'codechallenge',
    'statesecret',
    'encryptionkey',
    'privatekey',
    'content',
    'markdown',
    'body',
    'html',
    'email',
    'emailaddress',
    'name',
    'fullname',
    'givenname',
    'familyname',
    'displayname',
  ].map(normaliseKey),
);

/** Values that look like bearer tokens or JWTs, wherever they appear. */
const TOKEN_SHAPED = /\b(?:[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,})\b/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;

/**
 * Any absolute http(s) URL appearing in a logged value.
 *
 * Its **whole** query string and fragment are removed, not a list of named parameters.
 * A Canvas content URL carries `verifier`; a files-domain redirect carries `sf_verifier`;
 * object storage carries `X-Amz-Signature`, `X-Goog-Signature` or an Azure SAS. Enumerating
 * those names means the list is always one provider behind, and the failure mode is a
 * credential in a log file. Redacting the query wholesale has no such gap, and the origin
 * and path — which is what a diagnosis actually needs — are kept.
 */
const ABSOLUTE_URL = /\bhttps?:\/\/[^\s"'<>\\)\]}]+/gi;

function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[-_]/g, '');
}

const MAX_DEPTH = 6;
const MAX_STRING = 512;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return '[truncated]';

  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;

  if (value instanceof Error) {
    return { name: value.name, message: redactString(value.message) };
  }
  if (value instanceof URL) return redactString(value.toString());
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return `[buffer ${value.length}B]`;

  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => redact(item, depth + 1));
  }

  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    out[key] = FORBIDDEN_KEYS.has(normaliseKey(key)) ? REDACTED : redact(item, depth + 1);
  }
  return out;
}

function redactString(value: string): string {
  const cleaned = value
    .replace(BEARER, `Bearer ${REDACTED}`)
    .replace(ABSOLUTE_URL, stripQuery)
    .replace(TOKEN_SHAPED, REDACTED);
  return cleaned.length > MAX_STRING ? `${cleaned.slice(0, MAX_STRING)}…[truncated]` : cleaned;
}

/** Keeps a URL's origin and path; removes everything that could be a credential. */
function stripQuery(match: string): string {
  // Trailing punctuation is part of the sentence, not of the URL.
  const trailing = /[.,;:!?]+$/.exec(match)?.[0] ?? '';
  const candidate = trailing ? match.slice(0, -trailing.length) : match;

  try {
    const url = new URL(candidate);
    // Nothing to remove: return the value untouched. Normalising it would rewrite an
    // issuer — an exact identifier — by appending a path it did not have.
    if (url.search === '' && url.hash === '') return match;

    const query = url.search ? '?[redacted]' : '';
    const fragment = url.hash ? '#[redacted]' : '';
    return `${url.origin}${url.pathname}${query}${fragment}${trailing}`;
  } catch {
    return `${REDACTED}${trailing}`;
  }
}

export interface LogRecord {
  readonly level: LogLevel;
  readonly time: string;
  readonly msg: string;
  readonly [key: string]: unknown;
}

export type Sink = (record: LogRecord) => void;

export interface Logger {
  trace(msg: string, fields?: Record<string, unknown>): void;
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  fatal(msg: string, fields?: Record<string, unknown>): void;
  /** Returns a logger that adds `fields` to every record, redacted like any other. */
  child(fields: Record<string, unknown>): Logger;
}

export interface LoggerOptions {
  readonly level?: LogLevel;
  readonly sink?: Sink;
  readonly base?: Record<string, unknown>;
}

const defaultSink: Sink = (record) => {
  process.stdout.write(`${JSON.stringify(record)}\n`);
};

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? 'info';
  const sink = options.sink ?? defaultSink;
  const base = redact(options.base ?? {}) as Record<string, unknown>;
  const threshold = LEVEL_RANK[level];

  const emit = (recordLevel: LogLevel, msg: string, fields?: Record<string, unknown>): void => {
    if (LEVEL_RANK[recordLevel] < threshold) return;
    const safeFields = fields ? (redact(fields) as Record<string, unknown>) : {};
    sink({
      ...base,
      ...safeFields,
      level: recordLevel,
      time: new Date().toISOString(),
      msg: redactString(msg),
    });
  };

  return {
    trace: (msg, fields) => {
      emit('trace', msg, fields);
    },
    debug: (msg, fields) => {
      emit('debug', msg, fields);
    },
    info: (msg, fields) => {
      emit('info', msg, fields);
    },
    warn: (msg, fields) => {
      emit('warn', msg, fields);
    },
    error: (msg, fields) => {
      emit('error', msg, fields);
    },
    fatal: (msg, fields) => {
      emit('fatal', msg, fields);
    },
    child: (fields) =>
      createLogger({
        level,
        sink,
        base: { ...base, ...(redact(fields) as Record<string, unknown>) },
      }),
  };
}

/** A logger that discards everything. Useful in tests that do not assert on output. */
export const silentLogger: Logger = createLogger({ level: 'fatal', sink: () => undefined });
