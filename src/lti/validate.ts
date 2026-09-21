import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { Platform, PlatformRegistry } from '../config/platforms.ts';
import {
  asCanvasId,
  CLAIM,
  CUSTOM_FIELD,
  expandedOrUndefined,
  LTI_VERSION,
  RESOURCE_LINK_REQUEST,
  type LaunchContext,
} from './claims.ts';
import { LaunchError } from './errors.ts';
import type { LaunchStateStore } from './state-store.ts';

/**
 * Validation of an LTI 1.3 launch.
 *
 * Cryptography is delegated entirely to `jose`: `createRemoteJWKSet` fetches, caches and
 * rotates the platform's keys, and `jwtVerify` checks the signature together with `iss`,
 * `aud`, `exp` and `nbf`. What this module adds is the LTI-specific part no JOSE library
 * can know about — `nonce` single use, `deployment_id`, message type and version — plus the
 * binding of the callback to the `state` that started it.
 *
 * Reference: 1EdTech LTI 1.3 Core, §5.1.3 "Authentication Response Validation".
 */

/** Signature algorithms accepted. Canvas signs id_tokens with RS256. */
const ALLOWED_ALGORITHMS = ['RS256'] as const;

/** Tolerance for clock skew between the platform and this tool. */
const CLOCK_TOLERANCE_SECONDS = 60;

/** How long a consumed nonce is remembered, so a captured token cannot be re-paired. */
const NONCE_MEMORY_MS = 10 * 60_000;

export interface LaunchRequest {
  readonly id_token?: string | undefined;
  readonly state?: string | undefined;
}

export interface ValidateOptions {
  readonly registry: PlatformRegistry;
  readonly store: LaunchStateStore;
  /** Overrides the JWKS resolver. Tests inject a local key set; production does not. */
  readonly keyResolver?: (platform: Platform) => JWTVerifyGetKey;
  readonly now?: () => Date;
}

export interface ValidatedLaunch {
  readonly context: LaunchContext;
  readonly platform: Platform;
  /** The raw claims, for callers that need something this module does not surface. */
  readonly claims: JWTPayload;
}

/** One remote key set per JWKS URI, so keys are cached and rotated across launches. */
const remoteKeySets = new Map<string, JWTVerifyGetKey>();

function defaultKeyResolver(platform: Platform): JWTVerifyGetKey {
  let keySet = remoteKeySets.get(platform.jwksUri);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(platform.jwksUri), {
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
      timeoutDuration: 5_000,
    });
    remoteKeySets.set(platform.jwksUri, keySet);
  }
  return keySet;
}

export async function validateLaunch(
  request: LaunchRequest,
  options: ValidateOptions,
): Promise<ValidatedLaunch> {
  if (!request.state) throw new LaunchError('missing_parameter', 'state');
  if (!request.id_token) throw new LaunchError('missing_parameter', 'id_token');

  // Consuming the state first makes every launch single-use, whatever happens next.
  const stateRecord = await options.store.consume(request.state);
  if (!stateRecord) {
    throw new LaunchError('unknown_state', 'state is unknown, already used, or expired');
  }

  const platform = options.registry.find(stateRecord.issuer, stateRecord.clientId);
  if (!platform) {
    throw new LaunchError('unknown_platform', `iss=${stateRecord.issuer}`);
  }

  const resolveKey = options.keyResolver ?? defaultKeyResolver;

  let claims: JWTPayload;
  try {
    const verified = await jwtVerify(request.id_token, resolveKey(platform), {
      issuer: platform.issuer,
      audience: platform.clientId,
      algorithms: [...ALLOWED_ALGORITHMS],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    claims = verified.payload;
  } catch (error) {
    throw translateJoseError(error);
  }

  await checkNonce(claims, stateRecord.nonce, platform.issuer, options);
  checkAuthorizedParty(claims, platform);
  checkDeployment(claims, platform);
  checkMessageShape(claims);

  return { context: buildContext(claims, platform), platform, claims };
}

/**
 * `jose` reports failures through error codes. They are mapped to our own codes so the log
 * says which check failed while the user still sees one generic message.
 */
function translateJoseError(error: unknown): LaunchError {
  const code = errorCode(error);
  switch (code) {
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
    case 'ERR_JWKS_NO_MATCHING_KEY':
    case 'ERR_JWKS_MULTIPLE_MATCHING_KEYS':
      return new LaunchError('invalid_signature', code);
    case 'ERR_JWT_EXPIRED':
      return new LaunchError('token_expired', code);
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED': {
      const claim = errorClaim(error);
      if (claim === 'aud' || claim === 'iss') {
        return new LaunchError('audience_mismatch', `claim=${claim}`);
      }
      return new LaunchError('invalid_token', `claim=${claim ?? 'unknown'}`);
    }
    default:
      return new LaunchError('invalid_token', code);
  }
}

/** Reads `jose`'s error code without trusting the shape of an arbitrary thrown value. */
function errorCode(error: unknown): string | undefined {
  const value = (error as { code?: unknown } | null | undefined)?.code;
  return typeof value === 'string' ? value : undefined;
}

function errorClaim(error: unknown): string | undefined {
  const value = (error as { claim?: unknown } | null | undefined)?.claim;
  return typeof value === 'string' ? value : undefined;
}

async function checkNonce(
  claims: JWTPayload,
  expected: string,
  issuer: string,
  options: ValidateOptions,
): Promise<void> {
  const nonce = claims['nonce'];
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new LaunchError('nonce_mismatch', 'token carries no nonce');
  }
  if (nonce !== expected) {
    // A token minted for a different login attempt, presented against this state.
    throw new LaunchError('nonce_mismatch', 'nonce does not match the one sent at login');
  }

  const now = options.now?.() ?? new Date();
  const fresh = await options.store.markNonceUsed(
    issuer,
    nonce,
    new Date(now.getTime() + NONCE_MEMORY_MS),
  );
  if (!fresh) {
    throw new LaunchError('nonce_reused', 'nonce has already been used');
  }
}

/**
 * When `aud` holds more than one value, or when `azp` is present, the specification
 * requires `azp` to identify this tool.
 */
function checkAuthorizedParty(claims: JWTPayload, platform: Platform): void {
  const azp = claims['azp'];
  if (azp === undefined) {
    if (Array.isArray(claims.aud) && claims.aud.length > 1) {
      throw new LaunchError('audience_mismatch', 'multi-valued aud without azp');
    }
    return;
  }
  if (azp !== platform.clientId) {
    throw new LaunchError('audience_mismatch', 'azp does not identify this tool');
  }
}

function checkDeployment(claims: JWTPayload, platform: Platform): void {
  const deploymentId = claims[CLAIM.deploymentId];
  if (typeof deploymentId !== 'string' || deploymentId.length === 0) {
    throw new LaunchError('unknown_deployment', 'deployment_id claim is missing');
  }
  if (!platform.deploymentIds.includes(deploymentId)) {
    throw new LaunchError('unknown_deployment', 'deployment_id is not registered');
  }
}

function checkMessageShape(claims: JWTPayload): void {
  const messageType = claims[CLAIM.messageType];
  if (messageType !== RESOURCE_LINK_REQUEST) {
    throw new LaunchError('unsupported_message_type', String(messageType));
  }
  const version = claims[CLAIM.version];
  if (version !== LTI_VERSION) {
    throw new LaunchError('unsupported_version', String(version));
  }
}

function buildContext(claims: JWTPayload, platform: Platform): LaunchContext {
  const custom = asRecord(claims[CLAIM.custom]);
  const context = asRecord(claims[CLAIM.context]);
  const presentation = asRecord(claims[CLAIM.launchPresentation]);

  const subject = claims.sub;
  if (typeof subject !== 'string' || subject.length === 0) {
    throw new LaunchError('invalid_token', 'sub claim is missing');
  }

  const targetLinkUri = claims[CLAIM.targetLinkUri];
  if (typeof targetLinkUri !== 'string' || targetLinkUri.length === 0) {
    throw new LaunchError('invalid_token', 'target_link_uri claim is missing');
  }

  const deploymentId = claims[CLAIM.deploymentId] as string;

  return {
    identity: {
      issuer: platform.issuer,
      clientId: platform.clientId,
      deploymentId,
      subject,
    },
    canvasCourseId: asCanvasId(custom[CUSTOM_FIELD.courseId]),
    canvasUserId: asCanvasId(custom[CUSTOM_FIELD.userId]),
    canvasApiDomain: expandedOrUndefined(custom[CUSTOM_FIELD.apiDomain]),
    contextTitle: expandedOrUndefined(context['title']),
    roles: Array.isArray(claims[CLAIM.roles])
      ? (claims[CLAIM.roles] as unknown[]).filter((r): r is string => typeof r === 'string')
      : [],
    locale: expandedOrUndefined(presentation['locale']),
    targetLinkUri,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
