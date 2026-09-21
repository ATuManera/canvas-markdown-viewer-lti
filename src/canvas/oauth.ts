import { createHash, randomBytes } from 'node:crypto';
import type { Platform } from '../config/platforms.ts';
import { open, seal, type KeyRing, type SecretBinding } from '../crypto/envelope.ts';
import type { DbPool } from '../db/pool.ts';
import { SafeFetcher, type SafeFetchOptions } from './safe-fetch.ts';
import { scopeParameter } from './scopes.ts';
import { TokenStore } from './token-store.ts';

/**
 * Canvas OAuth2, authorization-code flow with PKCE.
 *
 * Endpoints and parameters follow Canvas `doc/api/oauth.md` and `doc/api/oauth_endpoints.md`:
 *
 *   GET  /login/oauth2/auth    client_id, response_type=code, redirect_uri, state, scope
 *   POST /login/oauth2/token   grant_type=authorization_code | refresh_token
 *   DELETE /login/oauth2/token revoke
 *
 * PKCE is verified in Canvas source (`lib/canvas/oauth/pkce.rb`): S256 only, `plain` is not
 * accepted, and the challenge is remembered for ten minutes. It is opt-in from the client,
 * so this module always sends it — a platform that ignores it is no worse off, and one that
 * honours it closes the authorization-code interception window.
 */

const AUTH_PATH = '/login/oauth2/auth';
const TOKEN_PATH = '/login/oauth2/token';

/** Canvas access tokens last an hour; refresh a little early to avoid racing expiry. */
const ACCESS_TOKEN_SKEW_MS = 60_000;

const FLOW_TTL_MS = 10 * 60_000;

export type OAuthErrorCode =
  | 'unknown_flow'
  | 'expired_flow'
  | 'context_mismatch'
  | 'authorization_denied'
  | 'token_endpoint_error'
  | 'malformed_token_response'
  | 'not_authorized';

export class OAuthError extends Error {
  override readonly name = 'OAuthError';

  constructor(
    readonly code: OAuthErrorCode,
    /** Operator-facing detail. Never rendered, never carries a credential. */
    readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

/** The launch this authorization belongs to. The callback is checked against all of it. */
export interface FlowContext extends SecretBinding {
  readonly clientId: string;
  readonly canvasCourseId: string | undefined;
}

export interface AuthorizationRequest {
  readonly url: string;
  readonly state: string;
}

interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token?: string;
  readonly expires_in?: number;
  readonly scope?: string;
}

interface CachedAccessToken {
  readonly token: string;
  readonly expiresAt: number;
}

export interface CanvasOAuthOptions {
  readonly pool: DbPool;
  readonly keyRing: KeyRing;
  readonly tokens: TokenStore;
  /** This tool's OAuth2 callback URL. Fixed by configuration, never taken from a request. */
  readonly redirectUri: string;
  readonly fetchOptions: Omit<SafeFetchOptions, 'originHosts'>;
  readonly now?: () => Date;
}

/** `code_verifier` per RFC 7636 §4.1: 43–128 unreserved characters. */
export function createCodeVerifier(): string {
  return randomBytes(64).toString('base64url').slice(0, 96);
}

export function codeChallengeFor(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

export class CanvasOAuth {
  /**
   * Access tokens are held in memory only, never persisted, and only until they expire.
   * `#inFlight` coalesces concurrent refreshes inside one process; the database row lock in
   * {@link TokenStore.withRefreshLock} does the same across processes.
   */
  readonly #accessTokens = new Map<string, CachedAccessToken>();
  readonly #inFlight = new Map<string, Promise<string>>();

  constructor(private readonly options: CanvasOAuthOptions) {}

  /**
   * Starts an authorization. The verifier is sealed before it touches the database, so a
   * database dump does not let an attacker complete a captured authorization code.
   */
  async beginAuthorization(
    platform: Platform,
    context: FlowContext,
  ): Promise<AuthorizationRequest> {
    const state = randomBytes(32).toString('base64url');
    const verifier = createCodeVerifier();
    const now = this.options.now?.() ?? new Date();

    await this.options.pool.query(
      `INSERT INTO oauth_flows
         (state, sealed_verifier, issuer, client_id, deployment_id, subject, canvas_course_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        state,
        seal(verifier, context, this.options.keyRing),
        context.issuer,
        context.clientId,
        context.deploymentId,
        context.subject,
        context.canvasCourseId ?? null,
        new Date(now.getTime() + FLOW_TTL_MS),
      ],
    );

    const url = new URL(AUTH_PATH, platform.apiBaseUrl);
    url.searchParams.set('client_id', platform.apiClientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', this.options.redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('scope', scopeParameter());
    url.searchParams.set('code_challenge', codeChallengeFor(verifier));
    url.searchParams.set('code_challenge_method', 'S256');

    return { url: url.toString(), state };
  }

  /**
   * Completes an authorization.
   *
   * The flow row is deleted before anything else, which makes a `state` single-use, and the
   * launch it belongs to must match the one currently in hand: a code obtained during
   * another user's launch is refused even if the `state` is genuine.
   */
  async completeAuthorization(
    platform: Platform,
    params: { state?: string; code?: string; error?: string },
    expected: FlowContext,
  ): Promise<void> {
    if (params.error) {
      throw new OAuthError('authorization_denied', params.error);
    }
    if (!params.state || !params.code) {
      throw new OAuthError('unknown_flow', 'state or code missing');
    }

    const { rows } = await this.options.pool.query<{
      sealed_verifier: string;
      issuer: string;
      client_id: string;
      deployment_id: string;
      subject: string;
      canvas_course_id: string | null;
      expires_at: Date;
    }>(`DELETE FROM oauth_flows WHERE state = $1 RETURNING *`, [params.state]);

    const flow = rows[0];
    if (!flow) throw new OAuthError('unknown_flow', 'state is unknown or already used');

    const now = this.options.now?.() ?? new Date();
    if (flow.expires_at.getTime() <= now.getTime()) {
      throw new OAuthError('expired_flow');
    }

    if (
      flow.issuer !== expected.issuer ||
      flow.client_id !== expected.clientId ||
      flow.deployment_id !== expected.deploymentId ||
      flow.subject !== expected.subject ||
      (flow.canvas_course_id ?? undefined) !== expected.canvasCourseId
    ) {
      throw new OAuthError('context_mismatch', 'callback does not belong to this launch');
    }

    const binding: SecretBinding = {
      issuer: flow.issuer,
      deploymentId: flow.deployment_id,
      subject: flow.subject,
    };
    const verifier = open(flow.sealed_verifier, { ...binding }, this.options.keyRing);

    const response = await this.callTokenEndpoint(platform, {
      grant_type: 'authorization_code',
      client_id: platform.apiClientId,
      client_secret: platform.apiClientSecret,
      redirect_uri: this.options.redirectUri,
      code: params.code,
      code_verifier: verifier,
    });

    if (!response.refresh_token) {
      throw new OAuthError(
        'malformed_token_response',
        'authorization response carried no refresh_token',
      );
    }

    await this.options.tokens.save(binding, response.refresh_token, response.scope);
    this.cacheAccessToken(binding, response);
  }

  /**
   * Returns a usable access token, refreshing if needed.
   *
   * Three layers stop a stampede: the in-memory cache, the per-owner in-flight promise, and
   * the database row lock. A second caller for the same user therefore waits for the first
   * rather than opening a second exchange with Canvas.
   */
  async getAccessToken(platform: Platform, binding: SecretBinding): Promise<string> {
    const key = ownerKey(binding);
    const now = (this.options.now?.() ?? new Date()).getTime();

    const cached = this.#accessTokens.get(key);
    if (cached && cached.expiresAt > now + ACCESS_TOKEN_SKEW_MS) return cached.token;

    const existing = this.#inFlight.get(key);
    if (existing) return existing;

    const pending = this.refresh(platform, binding).finally(() => {
      this.#inFlight.delete(key);
    });
    this.#inFlight.set(key, pending);
    return pending;
  }

  private async refresh(platform: Platform, binding: SecretBinding): Promise<string> {
    return this.options.tokens.withRefreshLock(binding, async (current) => {
      const response = await this.callTokenEndpoint(platform, {
        grant_type: 'refresh_token',
        client_id: platform.apiClientId,
        client_secret: platform.apiClientSecret,
        refresh_token: current.refreshToken,
      });

      this.cacheAccessToken(binding, response);

      // Canvas does not return a new refresh token; the specification permits one, so it is
      // stored when present and the existing one kept when it is not.
      return { refreshToken: response.refresh_token, result: response.access_token };
    });
  }

  /**
   * Revokes the user's authorization: first at Canvas, then locally. The local row is
   * removed even if Canvas rejects the call, so a user asking to disconnect always ends up
   * disconnected from this tool's point of view.
   */
  async revoke(platform: Platform, binding: SecretBinding): Promise<void> {
    const key = ownerKey(binding);
    const cached = this.#accessTokens.get(key);
    this.#accessTokens.delete(key);

    try {
      if (cached) {
        await this.fetcher(platform).fetch(new URL(TOKEN_PATH, platform.apiBaseUrl).toString(), {
          method: 'POST',
          body: new URLSearchParams({ _method: 'DELETE' }).toString(),
          bearerToken: cached.token,
          followRedirects: false,
        });
      }
    } catch {
      // Canvas may already consider the grant gone. Local removal is what the user asked
      // for and must happen regardless.
    } finally {
      await this.options.tokens.revoke(binding);
    }
  }

  /** Drops any cached access token. Used on sign-out and when a token stops working. */
  forget(binding: SecretBinding): void {
    this.#accessTokens.delete(ownerKey(binding));
  }

  private cacheAccessToken(binding: SecretBinding, response: TokenResponse): void {
    const lifetimeMs = (response.expires_in ?? 3600) * 1000;
    const now = (this.options.now?.() ?? new Date()).getTime();
    this.#accessTokens.set(ownerKey(binding), {
      token: response.access_token,
      expiresAt: now + lifetimeMs,
    });
  }

  private fetcher(platform: Platform): SafeFetcher {
    return new SafeFetcher({
      ...this.options.fetchOptions,
      originHosts: [new URL(platform.apiBaseUrl).hostname],
    });
  }

  private async callTokenEndpoint(
    platform: Platform,
    form: Record<string, string>,
  ): Promise<TokenResponse> {
    const url = new URL(TOKEN_PATH, platform.apiBaseUrl).toString();

    const response = await this.fetcher(platform).fetch(url, {
      method: 'POST',
      body: new URLSearchParams(form).toString(),
      // A redirect from a token endpoint is never legitimate and is not followed.
      followRedirects: false,
      // OAuth2 puts its failures in the body of a 400 or 401, so they are read rather
      // than turned into a transport error that would hide the reason.
      readErrorBody: true,
    });

    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body.toString('utf8'));
    } catch {
      throw new OAuthError('malformed_token_response', 'response was not JSON');
    }

    if (typeof parsed !== 'object' || parsed === null) {
      throw new OAuthError('malformed_token_response', 'response was not an object');
    }

    const record = parsed as Record<string, unknown>;
    if (typeof record['error'] === 'string') {
      // The error code is safe to record; `error_description` may echo input, so it is not.
      throw new OAuthError('token_endpoint_error', record['error']);
    }
    if (response.status >= 400) {
      throw new OAuthError('token_endpoint_error', `status ${response.status}`);
    }
    if (typeof record['access_token'] !== 'string') {
      throw new OAuthError('malformed_token_response', 'no access_token in response');
    }

    return {
      access_token: record['access_token'],
      ...(typeof record['refresh_token'] === 'string'
        ? { refresh_token: record['refresh_token'] }
        : {}),
      ...(typeof record['expires_in'] === 'number' ? { expires_in: record['expires_in'] } : {}),
      ...(typeof record['scope'] === 'string' ? { scope: record['scope'] } : {}),
    };
  }
}

function ownerKey(binding: SecretBinding): string {
  return `${binding.issuer}\u0000${binding.deploymentId}\u0000${binding.subject}`;
}
