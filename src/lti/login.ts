import { randomBytes } from 'node:crypto';
import type { Platform, PlatformRegistry } from '../config/platforms.ts';
import { LaunchError } from './errors.ts';
import { usesPlatformStorage } from './platform-storage.ts';
import type { LaunchStateStore } from './state-store.ts';

/**
 * Third-party initiated login (1EdTech LTI 1.3 Core, §5.1.1).
 *
 * Canvas sends the tool to this endpoint; the tool answers with a redirect to the
 * platform's authorization endpoint carrying a fresh `state` and `nonce`.
 */

/** Parameters Canvas sends on the login initiation request. */
export interface LoginRequest {
  readonly iss?: string | undefined;
  readonly login_hint?: string | undefined;
  readonly target_link_uri?: string | undefined;
  readonly lti_message_hint?: string | undefined;
  readonly client_id?: string | undefined;
  readonly lti_deployment_id?: string | undefined;
  /**
   * Canvas's signal that LTI Platform Storage is available, and the name of the frame to
   * address. Absent means the tool must fall back to cookies
   * (`doc/api/lti_launch_overview.md`, "Launching without Cookies").
   */
  readonly lti_storage_target?: string | undefined;
}

export interface LoginResult {
  readonly redirectUrl: string;
  readonly state: string;
  readonly platform: Platform;
  /** The frame to address for Platform Storage, or undefined when it is unavailable. */
  readonly storageTarget: string | undefined;
  /**
   * Origin the Platform Storage messages must target. The specification requires the
   * platform's OIDC authorization origin, which is not always the Canvas domain.
   */
  readonly authorizationOrigin: string;
}

export interface LoginOptions {
  readonly registry: PlatformRegistry;
  readonly store: LaunchStateStore;
  /** Absolute URL of this tool's launch callback; must match the tool's registration. */
  readonly redirectUri: string;
  /** How long the browser has to come back with the id_token. */
  readonly stateTtlMs?: number;
  readonly now?: () => Date;
}

const DEFAULT_STATE_TTL_MS = 5 * 60_000;

/** 256 bits of entropy, URL-safe. Used for both `state` and `nonce`. */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export async function beginLogin(
  request: LoginRequest,
  options: LoginOptions,
): Promise<LoginResult> {
  const issuer = request.iss?.trim();
  if (!issuer) {
    throw new LaunchError('missing_parameter', 'iss');
  }
  if (!request.login_hint) {
    throw new LaunchError('missing_parameter', 'login_hint');
  }

  const platform = resolvePlatform(options.registry, issuer, request.client_id);

  const now = options.now?.() ?? new Date();
  const state = randomToken();
  const nonce = randomToken();

  await options.store.create({
    state,
    nonce,
    issuer: platform.issuer,
    clientId: platform.clientId,
    targetLinkUri: request.target_link_uri,
    expiresAt: new Date(now.getTime() + (options.stateTtlMs ?? DEFAULT_STATE_TTL_MS)),
  });

  const url = new URL(platform.authorizationEndpoint);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('response_type', 'id_token');
  // form_post keeps the id_token out of the URL, and therefore out of browser history,
  // referrer headers and server access logs.
  url.searchParams.set('response_mode', 'form_post');
  // The user already has a Canvas session; the platform must not prompt again.
  url.searchParams.set('prompt', 'none');
  url.searchParams.set('client_id', platform.clientId);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('login_hint', request.login_hint);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  if (request.lti_message_hint) {
    url.searchParams.set('lti_message_hint', request.lti_message_hint);
  }

  return {
    redirectUrl: url.toString(),
    state,
    platform,
    storageTarget: usesPlatformStorage(request.lti_storage_target)
      ? request.lti_storage_target
      : undefined,
    authorizationOrigin: new URL(platform.authorizationEndpoint).origin,
  };
}

/**
 * Canvas has sent `client_id` on the login request for a long time, but the LTI
 * specification marks it optional. When it is absent we can still proceed if the issuer
 * identifies exactly one registration; with several, guessing would risk validating a
 * launch against the wrong developer key, so we refuse instead.
 */
function resolvePlatform(
  registry: PlatformRegistry,
  issuer: string,
  clientId: string | undefined,
): Platform {
  if (clientId) {
    const platform = registry.find(issuer, clientId);
    if (!platform) {
      throw new LaunchError('unknown_platform', `iss=${issuer}`);
    }
    return platform;
  }

  const candidates = registry.findByIssuer(issuer);
  const [only] = candidates;
  if (candidates.length === 1 && only) return only;

  throw new LaunchError(
    'unknown_platform',
    candidates.length === 0
      ? `iss=${issuer}`
      : `iss=${issuer} has ${candidates.length} registrations and no client_id was sent`,
  );
}
