import type { Platform } from '../config/platforms.ts';

/**
 * Response headers.
 *
 * The Content-Security-Policy is restrictive by construction rather than by exception:
 * nothing is allowed by default, scripts and styles come only from this origin, and the
 * page may only be framed by a Canvas instance this tool is actually installed in.
 *
 * `frame-ancestors` is derived from the configured platforms rather than being a wildcard,
 * so an institution that installs the tool gets an allowlist of exactly its own Canvas.
 *
 * `form-action` is derived the same way from each platform's `authorizationEndpoint`.
 * Chrome enforces `form-action` against the whole redirect chain that follows a form
 * submission, not just the form's own `action` attribute: `/app/authorize` submits to
 * itself and answers with a redirect to the platform's authorization endpoint, so that
 * origin must be allowed here or the browser blocks its own 303.
 */

export interface CspOptions {
  /** Extra origins permitted to frame the tool, for an unusual deployment. */
  readonly extraFrameAncestors?: readonly string[];
  /** Nonce for the one inline script the LTI relay pages need. */
  readonly scriptNonce?: string;
  /** Whether remote images may load at all. Off by default. */
  readonly allowExternalImages?: boolean;
}

/** Origins that may frame the tool: every configured Canvas, and nothing else. */
export function frameAncestorsFor(
  platforms: readonly Platform[],
  extra: readonly string[] = [],
): string[] {
  const origins = new Set<string>();

  for (const platform of platforms) {
    for (const candidate of [
      platform.apiBaseUrl,
      platform.issuer,
      platform.authorizationEndpoint,
    ]) {
      try {
        const url = new URL(candidate);
        if (url.protocol === 'https:' || url.protocol === 'http:') origins.add(url.origin);
      } catch {
        // `issuer` is an opaque identifier and need not be a URL. Skipping it is correct.
      }
    }
  }

  for (const origin of extra) origins.add(origin);
  return [...origins].sort();
}

/**
 * Origins the OAuth2 authorization form may redirect to, beyond this tool itself: the
 * `authorizationEndpoint` of every configured platform, as an https origin only. Only
 * `URL.origin` is used (no path, no wildcard), and anything that isn't a valid https URL
 * is dropped rather than widening the policy.
 */
export function formActionOriginsFor(platforms: readonly Platform[]): string[] {
  const origins = new Set<string>();

  for (const platform of platforms) {
    try {
      const url = new URL(platform.authorizationEndpoint);
      if (url.protocol === 'https:') origins.add(url.origin);
    } catch {
      // Invalid values are dropped, never allowed through.
    }
  }

  return [...origins].sort();
}

export function contentSecurityPolicy(
  platforms: readonly Platform[],
  options: CspOptions = {},
): string {
  const ancestors = frameAncestorsFor(platforms, options.extraFrameAncestors);
  const script = options.scriptNonce ? `'self' 'nonce-${options.scriptNonce}'` : "'self'";
  const img = options.allowExternalImages ? "'self' data: https:" : "'self' data:";
  const formAction = ["'self'", ...formActionOriginsFor(platforms)].join(' ');

  return [
    "default-src 'none'",
    `script-src ${script}`,
    "style-src 'self'",
    `img-src ${img}`,
    "font-src 'self'",
    "connect-src 'self'",
    `form-action ${formAction}`,
    "base-uri 'none'",
    "object-src 'none'",
    `frame-ancestors ${ancestors.length > 0 ? ancestors.join(' ') : "'none'"}`,
  ].join('; ');
}

/**
 * Headers applied to every dynamic response.
 *
 * `Cache-Control: no-store` is deliberate and broad: launches, OAuth2 callbacks, sessions,
 * file listings and rendered documents are all specific to one user, and none of them may
 * be held by Cloudflare, by a corporate proxy or by the browser's back-forward cache.
 */
export function dynamicResponseHeaders(csp: string): Record<string, string> {
  return {
    'content-security-policy': csp,
    'cache-control': 'no-store, no-cache, must-revalidate, private',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'cross-origin-resource-policy': 'same-origin',
    // X-Frame-Options is deliberately absent: it cannot express an allowlist, and setting
    // it to DENY or SAMEORIGIN would stop Canvas framing the tool at all. `frame-ancestors`
    // in the CSP does the job properly, and every browser this tool supports honours it.
  };
}

/** Headers for the static assets, which are identical for everyone and may be cached. */
export function staticResponseHeaders(): Record<string, string> {
  return {
    'cache-control': 'public, max-age=3600, must-revalidate',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  };
}
