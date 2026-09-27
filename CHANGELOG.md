# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-26

First release. LTI 1.3 launch, OAuth2 with Canvas, and the Markdown viewer have been
verified end to end against a live Canvas installation.

### Fixed

- `form-action` in the Content-Security-Policy only allowed `'self'`, but Chrome enforces
  `form-action` across the whole redirect chain that follows a form submission, not just
  the form's own `action` attribute. `/app/authorize` submits to itself and then answers
  with a redirect to the platform's `authorizationEndpoint`, so Canvas's OAuth2 authorize
  page was being blocked. `form-action` now also allows the https origin of every
  configured platform's `authorizationEndpoint`, derived the same way `frame-ancestors`
  already is, with no platform hardcoded.
- The OAuth2 request asked for a third scope,
  `url:GET|/courses/:course_id/files/:id/download`, which does not exist: Canvas publishes
  scopes for `/api/v1` and `/api/sis` routes only. It was inferred from a wider filter on
  `instructure/canvas-lms` `master` and refuted by testing against a real installation.
  The content is now fetched through the `url` the File object supplies, treated as the
  ephemeral bearer credential it is — consumed once, never stored, never returned to a
  browser, never logged, and sent no `Authorization` header.

### Added

- LTI 1.3 launch validation: signature against the platform JWKS, issuer, audience, `azp`,
  expiry, single-use `state`, single-use `nonce`, deployment id and message type.
- Canvas REST API access through OAuth2 with PKCE S256, on each user's own token, asking for
  exactly two read-only scopes.
- Refresh tokens sealed with AES-256-GCM, bound to their owner, with key versioning and
  rotation.
- SSRF-hardened HTTP client: per-hop scheme, host and address checks, connection pinning,
  bounded redirects, timeout, and a size limit applied while streaming.
- The bearer credential is dropped whenever a redirect changes origin.
- CommonMark and GitHub Flavored Markdown rendering behind two independent barriers: a
  parser that never emits raw HTML, and DOMPurify with an explicit allowlist.
- External images blocked by default.
- Operation inside the Canvas iframe without third-party cookies, using the 1EdTech LTI
  Platform Storage specification that Canvas implements.
- Server-rendered bilingual interface, Spanish and English, with light and dark themes.
- Container image, Compose deployment, and an installation guide for self-hosted Canvas.
