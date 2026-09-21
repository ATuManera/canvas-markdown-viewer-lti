import { z } from 'zod';
import { PlatformRegistry, platformsSchema, type Platform } from './platforms.ts';

/**
 * All configuration arrives through the environment, and is validated once at startup.
 * A process that starts is a process whose configuration is known to be well formed.
 */

const booleanish = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((value) => value === true || value === 'true' || value === '1');

const bytes = z.coerce.number().int().positive();

/** 32 bytes, base64 or base64url, for AES-256-GCM. */
const encryptionKey = z.string().transform((value, ctx) => {
  let buffer: Buffer;
  try {
    buffer = Buffer.from(value, 'base64');
  } catch {
    ctx.addIssue({ code: 'custom', message: 'must be base64-encoded' });
    return z.NEVER;
  }
  if (buffer.length !== 32) {
    ctx.addIssue({
      code: 'custom',
      message: `must decode to exactly 32 bytes, got ${buffer.length}`,
    });
    return z.NEVER;
  }
  return buffer;
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

  /** Key for AES-256-GCM encryption of stored refresh tokens. */
  ENCRYPTION_KEY: encryptionKey,

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
  return { ...rest, platforms: platforms.data };
});

export type Config = Omit<z.infer<typeof envSchema>, 'platforms'> & {
  readonly platforms: readonly Platform[];
  readonly platformRegistry: PlatformRegistry;
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

  const { platforms, ...rest } = result.data;
  return Object.freeze({
    ...rest,
    platforms: Object.freeze(platforms),
    platformRegistry: new PlatformRegistry(platforms),
    publicUrl: new URL(rest.PUBLIC_URL),
  });
}
