# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing released yet. The first release will be cut once the tool has been verified against
a live Canvas installation; see `docs/roadmap.md`.

### Added

- LTI 1.3 launch validation: signature against the platform JWKS, issuer, audience, `azp`,
  expiry, single-use `state`, single-use `nonce`, deployment id and message type.
- Canvas REST API access through OAuth2 with PKCE S256, on each user's own token.
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
