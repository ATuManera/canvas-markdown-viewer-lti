import { z } from 'zod';
import { KeyRing, type KeyRingEntry } from '../crypto/envelope.ts';
import { PlatformRegistry, platformsSchema, type Platform } from './platforms.ts';

/**
 * All configuration arrives through the environment, and is validated once at startup.
 * A process that starts is a process whose configuration is known to be well formed.
 */

const booleanish = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((value) => value === true || value === 'true' || value === '1');

const bytes = z.coerce.number().int().positive();

/**
 * One or more AES-256-GCM keys, as `version:base64key`, comma-separated. Several keys may
 * be present at once so a rotation can introduce a new key while rows sealed under the old
 * one stay readable.
 *
 *   ENCRYPTION_KEYS="1:Base64Of32Bytes,2:Base64Of32Bytes"
 *   ENCRYPTION_ACTIVE_KEY="2"
 */
const encryptionKeys = z.string().transform((value, ctx) => {
  const entries: KeyRingEntry[] = [];

  for (const [index, raw] of value.split(',').entries()) {
    const chunk = raw.trim();
    if (chunk === '') continue;

    const separator = chunk.indexOf(':');
    if (separator <= 0) {
      ctx.addIssue({
        code: 'custom',
        message: `entry ${index + 1} must be "version:base64key"`,
      });
      return z.NEVER;
    }

    const version = chunk.slice(0, separator).trim();
    const key = Buffer.from(chunk.slice(separator + 1).trim(), 'base64');
    if (key.length !== 32) {
      ctx.addIssue({
        code: 'custom',
        message: `key "${version}" must decode to exactly 32 bytes, got ${key.length}`,
      });
      return z.NEVER;
    }
    entries.push({ version, key });
  }

  if (entries.length === 0) {
    ctx.addIssue({ code: 'custom', message: 'at least one key is required' });
    return z.NEVER;
  }
  return entries;
});

const baseEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  /**
   * Public HTTPS base URL of this tool, without a trailing slash. Every URL the tool hands
   * to Canvas is derived from it, so it is configured rather than inferred from request
   * headers, which a client controls.
   */
  PUBLIC_URL: z.url(),

  DATABASE_URL: z.string().min(1),

  /** Keys for AES-256-GCM encryption of stored refresh tokens. See {@link encryptionKeys}. */
  ENCRYPTION_KEYS: encryptionKeys,

  /** Which key seals new values. Defaults to the last entry of ENCRYPTION_KEYS. */
  ENCRYPTION_ACTIVE_KEY: z.string().min(1).optional(),

  /** Key used to sign the short-lived state that ties an OAuth2 callback to its launch. */
  STATE_SECRET: z.string().min(32),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  /** Hard ceiling on the Markdown a viewer will fetch and render. */
  MAX_FILE_BYTES: bytes.default(2_000_000),
  FETCH_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  MAX_REDIRECTS: z.coerce.number().int().min(0).max(10).default(3),

  /** Markdown complexity ceilings, guarding against pathological documents. */
  MAX_MARKDOWN_NODES: z.coerce.number().int().positive().default(50_000),
  MAX_RENDER_MS: z.coerce.number().int().positive().default(3_000),

  /**
   * External images stay off by default: loading one tells its host the reader's IP,
   * user agent and which document they are reading.
   */
  ALLOW_EXTERNAL_IMAGES: booleanish.default(false),

  DEFAULT_LOCALE: z.enum(['es', 'en']).default('es'),

  /**
   * `persistent` keeps the encrypted refresh token so the user authorises once.
   * `session` discards it when the browser session ends, at the cost of re-authorising.
   */
  TOKEN_PERSISTENCE: z.enum(['persistent', 'session']).default('persistent'),

  /** JSON array of Canvas instances. See `platforms.ts`. */
  CANVAS_PLATFORMS: z.string().min(1),

  /** Allows running behind a reverse proxy that sets X-Forwarded-*. */
  TRUST_PROXY: booleanish.default(false),
});

const envSchema = baseEnvSchema.strict().transform((raw, ctx) => {
  let parsedPlatforms: unknown;
  try {
    parsedPlatforms = JSON.parse(raw.CANVAS_PLATFORMS);
  } catch {
    ctx.addIssue({
      code: 'custom',
      path: ['CANVAS_PLATFORMS'],
      message: 'must be valid JSON',
    });
    return z.NEVER;
  }

  const platforms = platformsSchema.safeParse(parsedPlatforms);
  if (!platforms.success) {
    for (const issue of platforms.error.issues) {
      ctx.addIssue({
        code: 'custom',
        path: ['CANVAS_PLATFORMS', ...issue.path],
        message: issue.message,
      });
    }
    return z.NEVER;
  }

  let keyRing: KeyRing;
  try {
    keyRing = new KeyRing(raw.ENCRYPTION_KEYS, raw.ENCRYPTION_ACTIVE_KEY);
  } catch (error) {
    ctx.addIssue({
      code: 'custom',
      path: ['ENCRYPTION_ACTIVE_KEY'],
      message: error instanceof Error ? error.message : 'invalid key ring',
    });
    return z.NEVER;
  }

  if (raw.NODE_ENV === 'production' && new URL(raw.PUBLIC_URL).protocol !== 'https:') {
    ctx.addIssue({
      code: 'custom',
      path: ['PUBLIC_URL'],
      message: 'must use https in production',
    });
    return z.NEVER;
  }

  const rest: Omit<typeof raw, 'CANVAS_PLATFORMS'> & { CANVAS_PLATFORMS?: string } = { ...raw };
  delete rest.CANVAS_PLATFORMS;
  return { ...rest, platforms: platforms.data, keyRing };
});

export type Config = Omit<z.infer<typeof envSchema>, 'platforms'> & {
  readonly platforms: readonly Platform[];
  readonly platformRegistry: PlatformRegistry;
  readonly keyRing: KeyRing;
  readonly publicUrl: URL;
};

export class ConfigError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`Invalid configuration:\n${issues.map((i) => `  - ${i}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

/**
 * Validates the environment and produces the frozen configuration object.
 * Throws {@link ConfigError} listing every problem at once, so an operator fixing a
 * deployment sees the whole picture instead of one error per restart.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const candidate: Record<string, unknown> = {};
  for (const key of Object.keys(baseEnvSchema.shape)) {
    if (env[key] !== undefined) candidate[key] = env[key];
  }

  const result = envSchema.safeParse(candidate);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`),
    );
  }

  const { platforms, keyRing, ...rest } = result.data;
  return Object.freeze({
    ...rest,
    platforms: Object.freeze(platforms),
    platformRegistry: new PlatformRegistry(platforms),
    keyRing,
    publicUrl: new URL(rest.PUBLIC_URL),
  });
}
