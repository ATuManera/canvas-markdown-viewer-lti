import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../../src/config/env.ts';
import { PlatformRegistry, platformsSchema } from '../../src/config/platforms.ts';

const PLATFORM = {
  issuer: 'https://canvas.example.edu',
  clientId: '10000000000001',
  deploymentIds: ['1:abcdef'],
  authorizationEndpoint: 'https://canvas.example.edu/api/lti/authorize_redirect',
  jwksUri: 'https://canvas.example.edu/api/lti/security/jwks',
  apiBaseUrl: 'https://canvas.example.edu',
  apiClientId: '10000000000002',
  apiClientSecret: 'api-secret',
};

function env(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    PUBLIC_URL: 'https://md.example.edu',
    DATABASE_URL: 'postgres://user:pw@localhost:5432/md',
    ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
    STATE_SECRET: 'x'.repeat(48),
    CANVAS_PLATFORMS: JSON.stringify([PLATFORM]),
    ...overrides,
  };
}

describe('loadConfig', () => {
  it('accepts a minimal valid environment and applies defaults', () => {
    const config = loadConfig(env());

    expect(config.NODE_ENV).toBe('development');
    expect(config.PORT).toBe(3000);
    expect(config.MAX_FILE_BYTES).toBe(2_000_000);
    expect(config.ALLOW_EXTERNAL_IMAGES).toBe(false);
    expect(config.DEFAULT_LOCALE).toBe('es');
    expect(config.TOKEN_PERSISTENCE).toBe('persistent');
    expect(config.platforms).toHaveLength(1);
    expect(config.publicUrl.host).toBe('md.example.edu');
  });

  it('decodes the encryption key to exactly 32 bytes', () => {
    const config = loadConfig(env());
    expect(config.ENCRYPTION_KEY).toBeInstanceOf(Buffer);
    expect(config.ENCRYPTION_KEY.length).toBe(32);
  });

  it('rejects an encryption key of the wrong length', () => {
    expect(() => loadConfig(env({ ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') }))).toThrow(
      ConfigError,
    );
  });

  it('rejects a short state secret', () => {
    expect(() => loadConfig(env({ STATE_SECRET: 'too-short' }))).toThrow(ConfigError);
  });

  it('rejects plain http PUBLIC_URL in production', () => {
    expect(() =>
      loadConfig(env({ NODE_ENV: 'production', PUBLIC_URL: 'http://md.example.edu' })),
    ).toThrow(/must use https in production/);
  });

  it('allows plain http PUBLIC_URL outside production', () => {
    const config = loadConfig(env({ PUBLIC_URL: 'http://localhost:3000' }));
    expect(config.publicUrl.protocol).toBe('http:');
  });

  it('reports every problem at once', () => {
    try {
      loadConfig(env({ STATE_SECRET: 'short', ENCRYPTION_KEY: 'AAAA' }));
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as ConfigError).issues.length).toBeGreaterThanOrEqual(2);
    }
  });

  it('rejects malformed platform JSON', () => {
    expect(() => loadConfig(env({ CANVAS_PLATFORMS: 'not json' }))).toThrow(/must be valid JSON/);
  });

  it('requires at least one platform', () => {
    expect(() => loadConfig(env({ CANVAS_PLATFORMS: '[]' }))).toThrow(ConfigError);
  });

  it('ignores unrelated environment variables', () => {
    expect(() => loadConfig(env({ HOME: '/root', PATH: '/usr/bin' }))).not.toThrow();
  });

  it('coerces numeric limits from strings', () => {
    const config = loadConfig(env({ MAX_FILE_BYTES: '512000', MAX_REDIRECTS: '1' }));
    expect(config.MAX_FILE_BYTES).toBe(512_000);
    expect(config.MAX_REDIRECTS).toBe(1);
  });

  it('accepts booleanish flags in several spellings', () => {
    expect(loadConfig(env({ ALLOW_EXTERNAL_IMAGES: 'true' })).ALLOW_EXTERNAL_IMAGES).toBe(true);
    expect(loadConfig(env({ ALLOW_EXTERNAL_IMAGES: '1' })).ALLOW_EXTERNAL_IMAGES).toBe(true);
    expect(loadConfig(env({ ALLOW_EXTERNAL_IMAGES: 'false' })).ALLOW_EXTERNAL_IMAGES).toBe(false);
  });
});

describe('platform schema', () => {
  it('rejects a non-https authorization endpoint', () => {
    const result = platformsSchema.safeParse([
      {
        ...PLATFORM,
        authorizationEndpoint: 'http://canvas.example.edu/api/lti/authorize_redirect',
      },
    ]);
    expect(result.success).toBe(false);
  });

  it('rejects unknown keys so typos in configuration are loud', () => {
    const result = platformsSchema.safeParse([{ ...PLATFORM, clientID: 'typo' }]);
    expect(result.success).toBe(false);
  });

  it('requires at least one deployment id', () => {
    const result = platformsSchema.safeParse([{ ...PLATFORM, deploymentIds: [] }]);
    expect(result.success).toBe(false);
  });

  it('rejects duplicate issuer/clientId pairs', () => {
    const result = platformsSchema.safeParse([PLATFORM, { ...PLATFORM }]);
    expect(result.success).toBe(false);
  });

  it('accepts two client ids on the same issuer', () => {
    const result = platformsSchema.safeParse([PLATFORM, { ...PLATFORM, clientId: 'other' }]);
    expect(result.success).toBe(true);
  });
});

describe('PlatformRegistry', () => {
  const registry = new PlatformRegistry(platformsSchema.parse([PLATFORM]));

  it('resolves a platform by issuer and client id', () => {
    expect(registry.find(PLATFORM.issuer, PLATFORM.clientId)?.apiClientId).toBe('10000000000002');
  });

  it('does not resolve a known issuer with an unknown client id', () => {
    expect(registry.find(PLATFORM.issuer, 'someone-elses-tool')).toBeUndefined();
  });

  it('does not resolve an unknown issuer', () => {
    expect(registry.find('https://evil.example', PLATFORM.clientId)).toBeUndefined();
  });
});
