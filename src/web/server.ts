import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import formbody from '@fastify/formbody';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';

import type { Config } from '../config/env.ts';
import type { Platform } from '../config/platforms.ts';
import { CanvasFilesClient, FileError } from '../canvas/files.ts';
import { CanvasOAuth, OAuthError, type FlowContext } from '../canvas/oauth.ts';
import { TokenStore } from '../canvas/token-store.ts';
import { migrate } from '../db/migrations.ts';
import { createPool, type DbPool } from '../db/pool.ts';
import { messagesFor, negotiateLocale, type Locale } from '../i18n/catalog.ts';
import { LaunchError } from '../lti/errors.ts';
import { beginLogin, type LoginRequest } from '../lti/login.ts';
import { PostgresLaunchStateStore } from '../lti/pg-state-store.ts';
import { renderLaunchVerification, renderLoginRelay } from '../lti/platform-storage.ts';
import { validateLaunch } from '../lti/validate.ts';
import { createLogger, type Logger } from '../logging/logger.ts';
import { renderMarkdown, RenderRefused } from '../markdown/render.ts';
import {
  renderAuthorizePage,
  renderDocumentPage,
  renderErrorPage,
  renderPickerPage,
  renderStandaloneError,
  SESSION_FIELD,
  type PageContext,
} from '../viewer/pages.ts';
import {
  contentSecurityPolicy,
  dynamicResponseHeaders,
  staticResponseHeaders,
} from './security-headers.ts';
import { SESSION_COOKIE, SessionCodec, SessionError, type Session } from './session.ts';

/**
 * The HTTP surface.
 *
 * Every page is rendered on the server and every transition inside the tool is a form POST
 * carrying the signed session token, never a URL parameter. That is what lets the viewer
 * work where third-party cookies are blocked, and keeps the token out of history, referrer
 * headers and proxy logs. See ADR-003.
 */

const ROUTES = {
  health: '/healthz',
  login: '/lti/login',
  launch: '/lti/launch',
  start: '/app/start',
  files: '/app/files',
  view: '/app/view',
  download: '/app/download',
  authorize: '/app/authorize',
  callback: '/canvas/callback',
  revoke: '/app/revoke',
} as const;

export interface BuildOptions {
  readonly config: Config;
  readonly logger?: Logger;
  /** Supplied by tests; production creates its own from DATABASE_URL. */
  readonly pool?: DbPool;
}

export interface BuiltServer {
  readonly app: FastifyInstance;
  readonly pool: DbPool;
}

interface FormBody {
  readonly [key: string]: unknown;
}

export async function buildServer(options: BuildOptions): Promise<BuiltServer> {
  const { config } = options;
  const logger =
    options.logger ??
    createLogger({ level: config.LOG_LEVEL, base: { app: 'canvas-markdown-viewer' } });

  const pool = options.pool ?? createPool({ connectionString: config.DATABASE_URL });
  await migrate(pool);

  const states = new PostgresLaunchStateStore(pool);
  const tokens = new TokenStore(pool, config.keyRing);
  const sessions = new SessionCodec({ secret: config.STATE_SECRET });

  const publicUrl = config.publicUrl.toString().replace(/\/$/, '');
  const oauth = new CanvasOAuth({
    pool,
    keyRing: config.keyRing,
    tokens,
    redirectUri: `${publicUrl}${ROUTES.callback}`,
    fetchOptions: {
      maxRedirects: config.MAX_REDIRECTS,
      timeoutMs: config.FETCH_TIMEOUT_MS,
      maxBytes: config.MAX_FILE_BYTES,
      ...(config.NODE_ENV === 'production'
        ? {}
        : { allowInsecureScheme: true, allowPrivateAddresses: true }),
    },
  });

  const files = new CanvasFilesClient({
    maxFileBytes: config.MAX_FILE_BYTES,
    fetchOptions: {
      maxRedirects: config.MAX_REDIRECTS,
      timeoutMs: config.FETCH_TIMEOUT_MS,
      maxBytes: config.MAX_FILE_BYTES,
      ...(config.NODE_ENV === 'production'
        ? {}
        : { allowInsecureScheme: true, allowPrivateAddresses: true }),
    },
  });

  const app = Fastify({
    logger: false,
    trustProxy: config.TRUST_PROXY,
    bodyLimit: 128 * 1024,
    // Canvas is the only caller and sends well-formed requests; a generous header limit
    // only widens the surface.
    maxParamLength: 256,
  });

  await app.register(formbody);
  await app.register(rateLimit, {
    max: 240,
    timeWindow: '1 minute',
    keyGenerator: (request) => request.ip,
  });
  await app.register(fastifyStatic, {
    root: fileURLToPath(new URL('../../public/assets', import.meta.url)),
    prefix: '/assets/',
  });

  // The static assets are identical for every user and may be cached; everything else is
  // specific to one launch and carries `no-store`, set per response.
  app.addHook('onSend', (request, reply, _payload, done) => {
    if (request.url.startsWith('/assets/')) {
      for (const [name, value] of Object.entries(staticResponseHeaders())) {
        reply.header(name, value);
      }
    }
    done();
  });

  const csp = (nonce?: string): string =>
    contentSecurityPolicy(config.platforms, {
      ...(nonce === undefined ? {} : { scriptNonce: nonce }),
      allowExternalImages: config.ALLOW_EXTERNAL_IMAGES,
    });

  function html(reply: FastifyReply, body: string, nonce?: string): FastifyReply {
    return reply
      .headers(dynamicResponseHeaders(csp(nonce)))
      .type('text/html; charset=utf-8')
      .send(body);
  }

  function requestId(request: FastifyRequest): string {
    return typeof request.id === 'string' ? request.id : randomUUID();
  }

  function contextFor(session: Session, token: string, request: FastifyRequest): PageContext {
    return {
      locale: session.locale,
      messages: messagesFor(session.locale),
      sessionToken: token,
      basePath: '',
      requestId: requestId(request),
    };
  }

  /** Reads the session from the form field, falling back to the optional cookie. */
  function readSession(request: FastifyRequest): { session: Session; token: string } {
    const body = (request.body ?? {}) as FormBody;
    const fromForm = typeof body[SESSION_FIELD] === 'string' ? body[SESSION_FIELD] : undefined;
    const fromCookie = readCookie(request.headers.cookie, SESSION_COOKIE);
    const token = fromForm ?? fromCookie;
    return { session: sessions.verify(token), token: token ?? '' };
  }

  function platformFor(session: Session): Platform {
    const [platform] = config.platformRegistry.findByIssuer(session.issuer);
    if (!platform) throw new LaunchError('unknown_platform', session.issuer);
    return platform;
  }

  function flowContextFor(session: Session, platform: Platform): FlowContext {
    return {
      issuer: session.issuer,
      clientId: platform.clientId,
      deploymentId: session.deploymentId,
      subject: session.subject,
      canvasCourseId: session.canvasCourseId,
    };
  }

  // ---- health ------------------------------------------------------------

  app.get(ROUTES.health, async (_request, reply) => {
    try {
      await pool.query('SELECT 1');
      return await reply.headers({ 'cache-control': 'no-store' }).send({ status: 'ok' });
    } catch {
      return reply
        .status(503)
        .headers({ 'cache-control': 'no-store' })
        .send({ status: 'degraded' });
    }
  });

  // ---- LTI login ---------------------------------------------------------

  const handleLogin = async (request: FastifyRequest, reply: FastifyReply): Promise<unknown> => {
    const params = { ...(request.query as FormBody), ...((request.body ?? {}) as FormBody) };
    const loginRequest = params as unknown as LoginRequest;

    try {
      const result = await beginLogin(loginRequest, {
        registry: config.platformRegistry,
        store: states,
        redirectUri: `${publicUrl}${ROUTES.launch}`,
      });

      const locale = config.DEFAULT_LOCALE;
      const messages = messagesFor(locale);

      if (result.storageTarget === undefined) {
        // No Platform Storage: a plain redirect, with the cookie as the browser binding.
        return await reply
          .headers(dynamicResponseHeaders(csp()))
          .header('set-cookie', stateCookie(result.state, config.NODE_ENV === 'production'))
          .redirect(result.redirectUrl, 302);
      }

      const nonce = randomUUID();
      return await html(
        reply,
        withNonce(
          renderLoginRelay({
            state: result.state,
            storageTarget: result.storageTarget,
            authorizationOrigin: result.authorizationOrigin,
            redirectUrl: result.redirectUrl,
            texts: { title: messages.relayTitle, continueLabel: messages.relayContinue },
            locale,
          }),
          nonce,
        ),
        nonce,
      );
    } catch (error) {
      return failLaunch(reply, request, error, logger, config);
    }
  };

  app.get(ROUTES.login, handleLogin);
  app.post(ROUTES.login, handleLogin);

  // ---- LTI launch --------------------------------------------------------

  app.post(ROUTES.launch, async (request, reply) => {
    const body = (request.body ?? {}) as FormBody;

    try {
      const validated = await validateLaunch(
        {
          id_token: typeof body['id_token'] === 'string' ? body['id_token'] : undefined,
          state: typeof body['state'] === 'string' ? body['state'] : undefined,
        },
        { registry: config.platformRegistry, store: states },
      );

      const locale: Locale = negotiateLocale(validated.context.locale, config.DEFAULT_LOCALE);
      const { token } = sessions.issue({
        issuer: validated.context.identity.issuer,
        deploymentId: validated.context.identity.deploymentId,
        subject: validated.context.identity.subject,
        canvasCourseId: validated.context.canvasCourseId,
        locale,
      });

      logger.info('launch validated', {
        issuer: validated.context.identity.issuer,
        courseId: validated.context.canvasCourseId,
        requestId: requestId(request),
      });

      const storageTarget =
        typeof body['lti_storage_target'] === 'string' ? body['lti_storage_target'] : undefined;
      const messages = messagesFor(locale);

      reply.header('set-cookie', sessionCookie(token, config.NODE_ENV === 'production'));

      if (!storageTarget) {
        return await renderStart(request, reply, token, locale);
      }

      const nonce = randomUUID();
      return await html(
        reply,
        withNonce(
          renderLaunchVerification({
            state: typeof body['state'] === 'string' ? body['state'] : '',
            storageTarget,
            authorizationOrigin: new URL(validated.platform.authorizationEndpoint).origin,
            continueUrl: ROUTES.start,
            launchHandle: token,
            texts: {
              title: messages.verifyTitle,
              checking: messages.verifyChecking,
              mismatch: messages.verifyMismatch,
              continueLabel: messages.relayContinue,
            },
            locale,
          }),
          nonce,
        ),
        nonce,
      );
    } catch (error) {
      return failLaunch(reply, request, error, logger, config);
    }
  });

  /** The verification page posts here; so does a browser that never ran it. */
  app.post(ROUTES.start, async (request, reply) => {
    const body = (request.body ?? {}) as FormBody;
    const token = typeof body['launch'] === 'string' ? body['launch'] : undefined;
    try {
      const session = sessions.verify(token ?? readCookie(request.headers.cookie, SESSION_COOKIE));
      return await renderStart(request, reply, token ?? '', session.locale);
    } catch (error) {
      return failLaunch(reply, request, error, logger, config);
    }
  });

  async function renderStart(
    request: FastifyRequest,
    reply: FastifyReply,
    token: string,
    locale: Locale,
  ): Promise<unknown> {
    const session = sessions.verify(token || readCookie(request.headers.cookie, SESSION_COOKIE));
    const context = contextFor({ ...session, locale }, token, request);
    const platform = platformFor(session);

    if (!session.canvasCourseId) {
      return html(reply, renderErrorPage({ context, message: context.messages.errorNoCourse }));
    }

    const authorized = await tokens.has(session);
    if (!authorized) {
      return html(reply, authorizePage(context, publicUrl));
    }

    return showPicker(reply, context, session, platform);
  }

  // ---- OAuth2 ------------------------------------------------------------

  app.post(ROUTES.authorize, async (request, reply) => {
    try {
      const { session, token } = readSession(request);
      const platform = platformFor(session);
      const { url } = await oauth.beginAuthorization(platform, flowContextFor(session, platform));

      return await reply
        .headers(dynamicResponseHeaders(csp()))
        .header('set-cookie', sessionCookie(token, config.NODE_ENV === 'production'))
        .redirect(url, 303);
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  app.get(ROUTES.callback, async (request, reply) => {
    const query = (request.query ?? {}) as FormBody;
    const token = readCookie(request.headers.cookie, SESSION_COOKIE);

    try {
      // The session may not survive here: a browser that blocks third-party cookies drops
      // it during the round trip to Canvas. The flow row holds the launch context, so the
      // callback is completed against that and a fresh session is issued from it.
      const session = token ? tryVerify(sessions, token) : undefined;
      const state = typeof query['state'] === 'string' ? query['state'] : undefined;
      const flow = await readFlow(pool, state);

      if (!flow) throw new OAuthError('unknown_flow', 'state is unknown or already used');

      const platform =
        config.platformRegistry.find(flow.issuer, flow.client_id) ??
        (() => {
          throw new OAuthError('unknown_flow', 'platform is no longer configured');
        })();

      const expected: FlowContext = {
        issuer: flow.issuer,
        clientId: flow.client_id,
        deploymentId: flow.deployment_id,
        subject: flow.subject,
        canvasCourseId: flow.canvas_course_id ?? undefined,
      };

      await oauth.completeAuthorization(
        platform,
        {
          ...(state === undefined ? {} : { state }),
          ...(typeof query['code'] === 'string' ? { code: query['code'] } : {}),
          ...(typeof query['error'] === 'string' ? { error: query['error'] } : {}),
        },
        expected,
      );

      const locale = session?.locale ?? config.DEFAULT_LOCALE;
      const issued = sessions.issue({
        issuer: expected.issuer,
        deploymentId: expected.deploymentId,
        subject: expected.subject,
        canvasCourseId: expected.canvasCourseId,
        locale,
      });

      reply.header('set-cookie', sessionCookie(issued.token, config.NODE_ENV === 'production'));
      const context = contextFor(issued.session, issued.token, request);
      return await showPicker(reply, context, issued.session, platform);
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  app.post(ROUTES.revoke, async (request, reply) => {
    try {
      const { session, token } = readSession(request);
      const platform = platformFor(session);
      await oauth.revoke(platform, session);

      const context = contextFor(session, token, request);
      return await html(reply, authorizePage(context, publicUrl));
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  // ---- the viewer --------------------------------------------------------

  app.post(ROUTES.files, async (request, reply) => {
    try {
      const { session, token } = readSession(request);
      const body = (request.body ?? {}) as FormBody;
      const search = typeof body['search'] === 'string' ? body['search'] : undefined;
      const context = contextFor(session, token, request);

      return await showPicker(reply, context, session, platformFor(session), search);
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  app.post(ROUTES.view, async (request, reply) => {
    try {
      const { session, token } = readSession(request);
      const body = (request.body ?? {}) as FormBody;
      const fileId = typeof body['file'] === 'string' ? body['file'] : '';
      const context = contextFor(session, token, request);
      const platform = platformFor(session);

      if (!session.canvasCourseId) {
        return await html(reply, renderErrorPage({ context, message: context.messages.errorNoCourse }));
      }

      const accessToken = await oauth.getAccessToken(platform, session);
      const document = await files.fetchMarkdown(
        platform,
        session.canvasCourseId,
        fileId,
        accessToken,
      );

      const rendered = renderMarkdown(document.text, {
        allowExternalImages: config.ALLOW_EXTERNAL_IMAGES,
        maxTokens: config.MAX_MARKDOWN_NODES,
        maxRenderMs: config.MAX_RENDER_MS,
        texts: {
          externalImageBlocked: context.messages.viewerExternalImagesBlocked,
          externalLink: context.messages.viewerExternalLink,
        },
      });

      logger.info('document rendered', {
        courseId: session.canvasCourseId,
        fileId: document.file.id,
        tokens: rendered.stats.tokens,
        requestId: context.requestId,
      });

      return await html(
        reply,
        renderDocumentPage({
          context,
          file: document.file,
          contentHtml: rendered.html,
          backAction: ROUTES.files,
          downloadAction: ROUTES.download,
          externalImagesBlocked: rendered.warnings.includes('external_image_blocked'),
        }),
      );
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  app.post(ROUTES.download, async (request, reply) => {
    try {
      const { session } = readSession(request);
      const body = (request.body ?? {}) as FormBody;
      const fileId = typeof body['file'] === 'string' ? body['file'] : '';
      const platform = platformFor(session);

      if (!session.canvasCourseId) throw new FileError('not_found', 'no course in session');

      const accessToken = await oauth.getAccessToken(platform, session);
      const document = await files.fetchMarkdown(
        platform,
        session.canvasCourseId,
        fileId,
        accessToken,
      );

      // Served from this origin rather than redirecting the browser to Canvas: a redirect
      // would hand the browser a URL this tool has validated but cannot vouch for again.
      return await reply
        .headers(dynamicResponseHeaders(csp()))
        .type('text/markdown; charset=utf-8')
        .header(
          'content-disposition',
          `attachment; filename*=UTF-8''${encodeURIComponent(document.file.displayName)}`,
        )
        .send(document.text);
    } catch (error) {
      return failApp(reply, request, error, logger);
    }
  });

  async function showPicker(
    reply: FastifyReply,
    context: PageContext,
    session: Session,
    platform: Platform,
    search?: string,
  ): Promise<unknown> {
    if (!session.canvasCourseId) {
      return html(reply, renderErrorPage({ context, message: context.messages.errorNoCourse }));
    }

    const accessToken = await oauth.getAccessToken(platform, session);
    const listing = await files.listFiles(platform, session.canvasCourseId, accessToken, {
      ...(search === undefined ? {} : { search }),
    });

    logger.info('listed files', {
      courseId: session.canvasCourseId,
      count: listing.length,
      requestId: context.requestId,
    });

    return html(
      reply,
      renderPickerPage({
        context,
        files: listing,
        openAction: ROUTES.view,
        searchAction: ROUTES.files,
        revokeAction: ROUTES.revoke,
        ...(search === undefined ? {} : { search }),
      }),
    );
  }

  function authorizePage(context: PageContext, base: string): string {
    return renderAuthorizePage({
      context,
      authorizeAction: ROUTES.authorize,
      fullWindowAction: ROUTES.authorize,
    }).replace(
      'data-full-window',
      `data-full-window data-full-window-url="${base}${ROUTES.launch}" data-placement="file_menu"`,
    );
  }

  /** Failures before a session exists: the launch itself went wrong. */
  function failLaunch(
    reply: FastifyReply,
    request: FastifyRequest,
    error: unknown,
    log: Logger,
    cfg: Config,
  ): FastifyReply {
    const id = requestId(request);
    const locale = cfg.DEFAULT_LOCALE;
    const messages = messagesFor(locale);

    log.warn('launch rejected', {
      code: error instanceof LaunchError ? error.code : 'unexpected',
      detail: error instanceof LaunchError ? error.detail : undefined,
      requestId: id,
    });

    return reply
      .status(400)
      .headers(dynamicResponseHeaders(csp()))
      .type('text/html; charset=utf-8')
      .send(renderStandaloneError(locale, messages, '', messages.errorLaunch, id));
  }

  /** Failures once a session exists: the user sees a page they can act on. */
  function failApp(
    reply: FastifyReply,
    request: FastifyRequest,
    error: unknown,
    log: Logger,
  ): FastifyReply {
    const id = requestId(request);
    let session: Session | undefined;
    let token = '';

    try {
      const read = readSession(request);
      session = read.session;
      token = read.token;
    } catch {
      session = undefined;
    }

    const locale = session?.locale ?? config.DEFAULT_LOCALE;
    const messages = messagesFor(locale);
    const message = userFacingMessage(error, messages);
    const status = statusFor(error);

    log.warn('request failed', {
      kind: error instanceof Error ? error.name : 'unknown',
      code: errorCode(error),
      requestId: id,
    });

    if (!session) {
      return reply
        .status(status)
        .headers(dynamicResponseHeaders(csp()))
        .type('text/html; charset=utf-8')
        .send(renderStandaloneError(locale, messages, '', message, id));
    }

    const context: PageContext = {
      locale,
      messages,
      sessionToken: token,
      basePath: '',
      requestId: id,
    };

    return reply
      .status(status)
      .headers(dynamicResponseHeaders(csp()))
      .type('text/html; charset=utf-8')
      .send(renderErrorPage({ context, message, backAction: ROUTES.files }));
  }

  return { app, pool };
}

// ---- helpers -------------------------------------------------------------

function tryVerify(codec: SessionCodec, token: string): Session | undefined {
  try {
    return codec.verify(token);
  } catch {
    return undefined;
  }
}

interface FlowRow {
  issuer: string;
  client_id: string;
  deployment_id: string;
  subject: string;
  canvas_course_id: string | null;
}

/** Peeks at the pending flow so the callback knows which platform to talk to. */
async function readFlow(pool: DbPool, state: string | undefined): Promise<FlowRow | undefined> {
  if (!state) return undefined;
  const { rows } = await pool.query<FlowRow>(
    'SELECT issuer, client_id, deployment_id, subject, canvas_course_id FROM oauth_flows WHERE state = $1',
    [state],
  );
  return rows[0];
}

function errorCode(error: unknown): string | undefined {
  if (error instanceof LaunchError) return error.code;
  if (error instanceof OAuthError) return error.code;
  if (error instanceof FileError) return error.code;
  if (error instanceof RenderRefused) return error.reason;
  if (error instanceof SessionError) return error.code;
  return undefined;
}

function statusFor(error: unknown): number {
  if (error instanceof SessionError) return 401;
  if (error instanceof FileError) {
    if (error.code === 'forbidden') return 403;
    if (error.code === 'not_found') return 404;
    return 400;
  }
  if (error instanceof OAuthError) return 400;
  if (error instanceof RenderRefused) return 413;
  return 500;
}

function userFacingMessage(error: unknown, messages: ReturnType<typeof messagesFor>): string {
  if (error instanceof SessionError) return messages.errorLaunch;
  if (error instanceof RenderRefused) return messages.errorTooComplex;
  if (error instanceof OAuthError) {
    return error.code === 'authorization_denied'
      ? messages.authorizeDenied
      : messages.errorNotAuthorized;
  }
  if (error instanceof FileError) {
    switch (error.code) {
      case 'not_found':
        return messages.errorNotFound;
      case 'forbidden':
        return messages.errorForbidden;
      case 'not_markdown':
        return messages.errorNotMarkdown;
      case 'too_large':
        return messages.errorTooLarge;
      case 'unreadable':
        return messages.errorUnreadable;
      default:
        return messages.errorGeneric;
    }
  }
  if (error instanceof Error && error.message.includes('no Canvas authorisation')) {
    return messages.errorNotAuthorized;
  }
  return messages.errorGeneric;
}

function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

function sessionCookie(token: string, secure: boolean): string {
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=None', 'Max-Age=28800'];
  if (secure) attributes.push('Secure');
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; ${attributes.join('; ')}`;
}

function stateCookie(state: string, secure: boolean): string {
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=None', 'Max-Age=300'];
  if (secure) attributes.push('Secure');
  return `cmv_state=${encodeURIComponent(state)}; ${attributes.join('; ')}`;
}

/** Applies the CSP nonce to the single inline script a relay page carries. */
function withNonce(page: string, nonce: string): string {
  return page.replace('<script>', `<script nonce="${nonce}">`);
}
