/**
 * Canvas REST API scopes this tool asks for.
 *
 * Canvas builds a scope string as `url:{VERB}|{path}` from its own routing table
 * (`lib/token_scopes_helper.rb#scope_from_route`). The three below were derived from the
 * routes in `config/routes.rb`:
 *
 *   GET /api/v1/courses/:course_id/files         (files#api_index, "List files")
 *   GET /api/v1/courses/:course_id/files/:id     (files#api_show,  "Get file")
 *   GET /courses/:course_id/files/:id/download   (files#show,      "Download file")
 *
 * The download route is scopable through an explicit exception in the regex that decides
 * which routes may appear in a developer key (`lib/token_scopes.rb#api_routes`).
 *
 * **Status: verified in Canvas source, pending physical validation.** The exact strings
 * must be confirmed against the target installation before the installation guide is
 * published, either from the developer key screen or from
 * `GET /api/v1/accounts/:account_id/scopes`. See `docs/research/canvas-lti-file-menu.md` §9.3.
 *
 * All three are read-only. The tool asks for no write scope of any kind.
 */
export const CANVAS_API_SCOPES = [
  'url:GET|/api/v1/courses/:course_id/files',
  'url:GET|/api/v1/courses/:course_id/files/:id',
  'url:GET|/courses/:course_id/files/:id/download',
] as const;

/**
 * Canvas expects the scope parameter once, with values separated by spaces. Passing it
 * several times makes only the last value count (`doc/api/oauth_endpoints.md`), which would
 * silently narrow the grant.
 */
export function scopeParameter(scopes: readonly string[] = CANVAS_API_SCOPES): string {
  return scopes.join(' ');
}
