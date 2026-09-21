import { z } from 'zod';

/**
 * Configuration for one Canvas instance ("platform" in LTI terms).
 *
 * Canvas issues developer keys scoped to the institution, so a tool serving several
 * institutions must look up the right key per launch. See Canvas `doc/api/oauth.md`:
 * "tool providers that serve multiple institutions should store and look up the correct
 * developer key based on the launch parameters".
 *
 * The OIDC auth domain is NOT always the issuer's domain. Canvas `lib/lti/oidc.rb`
 * documents that Instructure-hosted Canvas uses `canvas.instructure.com` as the issuer
 * and `sso.canvaslms.com` for the OIDC auth endpoint. Both are therefore configured
 * independently rather than derived from one another.
 */
/**
 * HTTPS, with one exception: a loopback host may use plain http.
 *
 * Browsers treat `http://localhost` as a secure context, and a developer running Canvas
 * locally has no certificate for it. Anything reachable from elsewhere must still be https,
 * and `loadConfig` refuses a non-https PUBLIC_URL in production regardless.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

const httpsUrl = z.url().refine(
  (value) => {
    const url = new URL(value);
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  },
  { message: 'must use https, except on a loopback host' },
);

/** Hostname, optionally with a leading `*.` wildcard for a single label. */
const hostPattern = z
  .string()
  .min(1)
  .regex(/^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i, {
    message: 'must be a hostname, optionally prefixed with "*."',
  });

export const platformSchema = z
  .object({
    /** The `iss` claim Canvas puts in the id_token. Exact string match, no normalisation. */
    issuer: z.string().min(1),

    /** Human-readable label used in the UI and in logs. Never a secret. */
    label: z.string().min(1).optional(),

    /** The LTI developer key's client id (`aud` of the id_token). */
    clientId: z.string().min(1),

    /**
     * Deployment ids allowed for this platform. A launch whose
     * `https://purl.imsglobal.org/spec/lti/claim/deployment_id` is not listed is rejected.
     */
    deploymentIds: z.array(z.string().min(1)).min(1),

    /** Canvas `/api/lti/authorize_redirect` on the auth domain. */
    authorizationEndpoint: httpsUrl,

    /** Canvas `/api/lti/security/jwks` on the auth domain. */
    jwksUri: httpsUrl,

    /** Base URL of the Canvas REST API for this instance, without a trailing slash. */
    apiBaseUrl: httpsUrl,

    /** Client id of the separate Canvas API developer key. */
    apiClientId: z.string().min(1),

    /** Client secret of the Canvas API developer key. Never logged, never rendered. */
    apiClientSecret: z.string().min(1),

    /**
     * Extra hosts the file download may redirect to, beyond the API host itself.
     * Needed when the instance uses a separate files domain or InstFS/S3 storage.
     */
    downloadHostAllowlist: z.array(hostPattern).default([]),
  })
  .strict();

export type Platform = z.infer<typeof platformSchema>;

export const platformsSchema = z
  .array(platformSchema)
  .min(1, 'at least one Canvas platform must be configured')
  .superRefine((platforms, ctx) => {
    const seen = new Set<string>();
    for (const [index, platform] of platforms.entries()) {
      const key = `${platform.issuer}\u0000${platform.clientId}`;
      if (seen.has(key)) {
        ctx.addIssue({
          code: 'custom',
          path: [index, 'issuer'],
          message: `duplicate issuer/clientId pair: ${platform.issuer}`,
        });
      }
      seen.add(key);
    }
  });

/** Indexed lookup so a launch resolves its platform in constant time. */
export class PlatformRegistry {
  readonly #byIssuerAndClient = new Map<string, Platform>();

  constructor(platforms: readonly Platform[]) {
    for (const platform of platforms) {
      this.#byIssuerAndClient.set(key(platform.issuer, platform.clientId), platform);
    }
  }

  /**
   * Resolves the platform for a launch. Both the issuer and the audience must match a
   * configured entry: an unknown issuer, or a known issuer with an audience belonging to a
   * different tool, is not a platform we serve.
   */
  find(issuer: string, clientId: string): Platform | undefined {
    return this.#byIssuerAndClient.get(key(issuer, clientId));
  }

  /** Every platform registered with this issuer, regardless of client id. */
  findByIssuer(issuer: string): Platform[] {
    return [...this.#byIssuerAndClient.values()].filter((p) => p.issuer === issuer);
  }

  get size(): number {
    return this.#byIssuerAndClient.size;
  }
}

function key(issuer: string, clientId: string): string {
  return `${issuer}\u0000${clientId}`;
}
