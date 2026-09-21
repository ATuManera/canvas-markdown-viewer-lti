import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { CLAIM, CUSTOM_FIELD, LTI_VERSION, RESOURCE_LINK_REQUEST } from '../../src/lti/claims.ts';
import { platformsSchema, PlatformRegistry, type Platform } from '../../src/config/platforms.ts';

/**
 * Test doubles for an LTI platform. Keys are generated per test run: no key material,
 * real or fake, is committed to this repository.
 */

export const ISSUER = 'https://canvas.test.edu';
export const CLIENT_ID = '10000000000001';
export const DEPLOYMENT_ID = '1:deployment-abc';
export const COURSE_ID = '4321';
export const USER_ID = '99';
export const TOOL_LAUNCH_URI = 'https://md.test.edu/lti/launch';

export function buildPlatform(overrides: Partial<Platform> = {}): Platform {
  return platformsSchema.parse([
    {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      deploymentIds: [DEPLOYMENT_ID],
      authorizationEndpoint: `${ISSUER}/api/lti/authorize_redirect`,
      jwksUri: `${ISSUER}/api/lti/security/jwks`,
      apiBaseUrl: ISSUER,
      apiClientId: '10000000000002',
      apiClientSecret: 'test-api-secret',
      ...overrides,
    },
  ])[0]!;
}

export function buildRegistry(...platforms: Platform[]): PlatformRegistry {
  return new PlatformRegistry(platforms.length > 0 ? platforms : [buildPlatform()]);
}

export interface SigningKey {
  readonly kid: string;
  readonly sign: (claims: Record<string, unknown>, header?: { kid?: string }) => Promise<string>;
  readonly resolver: JWTVerifyGetKey;
}

/** Generates an RS256 key pair and the matching local JWKS resolver. */
export async function createSigningKey(kid = 'test-key-1'): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const resolver = createLocalJWKSet({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });

  return {
    kid,
    resolver,
    sign: (claims, header) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: header?.kid ?? kid, typ: 'JWT' })
        .sign(privateKey),
  };
}

export interface LaunchClaimOptions {
  readonly nonce: string;
  readonly issuer?: string;
  readonly audience?: string | string[];
  readonly azp?: string;
  readonly subject?: string;
  readonly deploymentId?: string;
  readonly messageType?: string;
  readonly version?: string;
  readonly courseId?: string | null;
  readonly userId?: string | null;
  readonly apiDomain?: string | null;
  readonly locale?: string;
  readonly targetLinkUri?: string;
  readonly issuedAt?: number;
  readonly expiresAt?: number;
  readonly roles?: string[];
}

const TEACHER_ROLE = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor' as const;

/** Builds a claim set that is valid unless an override makes it otherwise. */
export function launchClaims(options: LaunchClaimOptions): Record<string, unknown> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const custom: Record<string, string> = {};
  if (options.courseId !== null) custom[CUSTOM_FIELD.courseId] = options.courseId ?? COURSE_ID;
  if (options.userId !== null) custom[CUSTOM_FIELD.userId] = options.userId ?? USER_ID;
  if (options.apiDomain !== null) {
    custom[CUSTOM_FIELD.apiDomain] = options.apiDomain ?? 'canvas.test.edu';
  }

  const claims: Record<string, unknown> = {
    iss: options.issuer ?? ISSUER,
    aud: options.audience ?? CLIENT_ID,
    sub: options.subject ?? 'lti-user-subject-1',
    iat: options.issuedAt ?? nowSeconds,
    exp: options.expiresAt ?? nowSeconds + 300,
    nonce: options.nonce,
    [CLAIM.messageType]: options.messageType ?? RESOURCE_LINK_REQUEST,
    [CLAIM.version]: options.version ?? LTI_VERSION,
    [CLAIM.deploymentId]: options.deploymentId ?? DEPLOYMENT_ID,
    [CLAIM.targetLinkUri]: options.targetLinkUri ?? TOOL_LAUNCH_URI,
    [CLAIM.roles]: options.roles ?? [TEACHER_ROLE],
    [CLAIM.context]: { id: 'ctx-1', title: 'Curso de prueba', type: ['CourseOffering'] },
    [CLAIM.resourceLink]: { id: 'rl-1' },
    [CLAIM.launchPresentation]: {
      document_target: 'iframe',
      locale: options.locale ?? 'es',
      return_url: `${ISSUER}/courses/${COURSE_ID}/external_content/success/external_tool_redirect`,
    },
    [CLAIM.custom]: custom,
  };

  if (options.azp !== undefined) claims['azp'] = options.azp;
  return claims;
}
