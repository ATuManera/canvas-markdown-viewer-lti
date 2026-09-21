# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[security advisories](https://github.com/ATuManera/canvas-markdown-viewer-lti/security/advisories/new)
for this repository. That creates a private thread only the maintainers can see.

Please include:

- what the problem is, and what an attacker could achieve with it;
- the steps or the input that reproduce it;
- the version or commit you tested;
- whether you have told anyone else.

**Do not include** real tokens, real student data, or a working exploit against a live
installation. A minimal reproduction against a test instance is enough, and is safer for
everyone.

### What to expect

|             |                                          |
| ----------- | ---------------------------------------- |
| First reply | Within 5 working days                    |
| Assessment  | Within 10 working days                   |
| Fix or plan | Communicated as soon as it is understood |

This is a volunteer-maintained project, not a commercial product. Those are intentions, not
a contractual commitment. If you need a guaranteed response time, say so in the report and
we will be honest about what we can offer.

Credit is given in the advisory and the changelog unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. There is no long-term support branch.

## Scope

**In scope:** this repository's code, its container image, its default configuration, its
documented deployment, and the way it handles Canvas credentials and Markdown content.

**Out of scope:** Canvas LMS itself — report those to Instructure; an operator's own
infrastructure, reverse proxy or network; and findings that require an attacker to already
have administrative access to the machine or the database.

## What this project already does

Each of these is enforced by a test; see `docs/security/threat-model.md` for the full table.

- Full LTI 1.3 launch validation: signature against the platform's JWKS, issuer, audience,
  `azp`, expiry, single-use `state`, single-use `nonce`, deployment id, message type.
- Canvas is read on the **user's own** OAuth2 token, so Canvas re-evaluates their
  permissions on every request. No administrative or service token is used.
- The bearer credential is dropped the moment a redirect changes origin, so file storage
  never sees it.
- SSRF defences on every hop: https, host allowlist, rejection of private, loopback,
  link-local and cloud-metadata addresses, connection pinned to a validated address, bounded
  redirects, timeout and size limit applied while streaming.
- Refresh tokens sealed with AES-256-GCM and bound to their owner as additional
  authenticated data, so a row moved onto another user does not decrypt.
- Two independent barriers against XSS: the Markdown parser never emits raw HTML, and the
  output is reduced to an explicit allowlist by DOMPurify.
- External images are blocked by default, so no remote host learns who is reading what.
- Logs never contain document content, tokens, secrets, `verifier` values, cookies,
  authorization headers, names or email addresses.

## Known limitations

These are design consequences, documented rather than hidden:

- An operator with access to the process environment can decrypt the stored tokens. That is
  inherent to holding delegated credentials; see `docs/security/privacy.md`.
- The tool trusts the Canvas instance it is registered with. A compromised Canvas can
  present a valid launch.
- A user who can legitimately read a file can read it through this tool. That is the point.
