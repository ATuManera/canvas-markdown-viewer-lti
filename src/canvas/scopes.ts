/**
 * Canvas REST API scopes this tool asks for.
 *
 * Canvas builds a scope string as `url:{VERB}|{path}` from its own routing table
 * (`lib/token_scopes_helper.rb#scope_from_route`), but it only offers a scope for routes
 * its filter accepts. On the installation this tool was tested against that filter is:
 *
 *     Rails.application.routes.routes.select { |route|
 *       %r{^/api/(v1|sis)} =~ route.path.spec.to_s
 *     }
 *
 * So **only `/api/v1` and `/api/sis` routes are scopable**. The web download route
 * `/courses/:course_id/files/:id/download` has no scope and cannot be selected on a
 * developer key.
 *
 * An earlier revision of this file listed that download route as a third scope. It was
 * inferred from a wider filter present in `instructure/canvas-lms` on `master`, and the
 * physical test refuted it: the scope does not exist on the target Canvas. The download is
 * therefore performed through the `url` the File object carries, which is the mechanism
 * this version of Canvas provides. See `docs/architecture/ADR-002-canvas-file-access.md`.
 *
 * Both scopes below are read-only. The tool asks for no write scope of any kind, and for no
 * scope beyond these two.
 */
export const CANVAS_API_SCOPES = [
  'url:GET|/api/v1/courses/:course_id/files',
  'url:GET|/api/v1/courses/:course_id/files/:id',
] as const;

/**
 * Canvas expects the scope parameter once, with values separated by spaces. Passing it
 * several times makes only the last value count (`doc/api/oauth_endpoints.md`), which would
 * silently narrow the grant.
 */
export function scopeParameter(scopes: readonly string[] = CANVAS_API_SCOPES): string {
  return scopes.join(' ');
}
