import { ConfigError, loadConfig } from './config/env.ts';
import { createLogger } from './logging/logger.ts';
import { buildServer } from './web/server.ts';

/**
 * Entry point.
 *
 * Configuration is validated before anything else starts, so a process that is listening is
 * a process whose configuration is known to be well formed. A configuration error exits
 * with every problem listed, rather than one per restart.
 */

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      process.stderr.write(`${error.message}\n`);
      process.exit(78); // EX_CONFIG
    }
    throw error;
  }

  const logger = createLogger({
    level: config.LOG_LEVEL,
    base: { app: 'canvas-markdown-viewer' },
  });

  const { app, pool } = await buildServer({ config, logger });

  const shutdown = (signal: string): void => {
    logger.info('shutting down', { signal });
    void (async () => {
      try {
        await app.close();
        await pool.end();
      } finally {
        process.exit(0);
      }
    })();
  };

  process.on('SIGTERM', () => {
    shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    shutdown('SIGINT');
  });

  await app.listen({ host: config.HOST, port: config.PORT });

  logger.info('listening', {
    host: config.HOST,
    port: config.PORT,
    publicUrl: config.publicUrl.origin,
    platforms: config.platforms.length,
    tokenPersistence: config.TOKEN_PERSISTENCE,
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exit(1);
});
