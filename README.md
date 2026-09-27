# canvas-markdown-viewer-lti

**Open-source Markdown file viewer for Canvas LMS, built with LTI 1.3.**

[![CI](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml/badge.svg)](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> 🇪🇸 **[Léeme en español](README.es.md)**

---

## The problem

Upload a `.md` file to a Canvas course and Canvas offers to download it. It will not render
it. Students get a file; teachers get a support question.

This tool adds **Ver Markdown** / **View Markdown** to a file's context menu. Selecting it
opens the document, rendered and readable, inside Canvas.

It is a standard LTI 1.3 tool. It does not modify Canvas, does not require a fork, and does
not depend on the Canvas theme's JavaScript.

**Author / Autor:** A Tu Manera Digital — Fernando Gallarday ([@fgallarday](https://github.com/fgallarday))

**AI Assistance / Asistencia de IA:** Developed with the support of GPT 5.6 Sol, Claude Opus 5, and Claude Sonnet 5.

**Version / Versión:** 0.1.0

## What it looks like

No screenshot yet. One will be added here once the interface has settled.

## Status

**Released, v0.1.0.** The LTI 1.3 launch, the OAuth2 consent and the full read-and-render
flow have been exercised end to end against a live, self-hosted Canvas installation.

What that means in practice:

- ✅ Every component is covered by automated tests, including the negative security cases.
- ✅ The container builds and passes a smoke test.
- ✅ The LTI launch, the OAuth2 consent and the browser behaviour have been verified against
  a live Canvas.
- ✅ The Canvas API scope strings have been confirmed against a real installation. One of the
  three originally inferred did not exist, and the download now uses the URL the File object
  supplies.

See [`CHANGELOG.md`](CHANGELOG.md) for what shipped in each version.

## How it works

```
Canvas file menu  ──►  LTI 1.3 launch  ──►  this tool  ──►  Canvas REST API
   "View Markdown"       (signed)              │            (the user's own token)
                                               ▼
                                     parse → sanitise → render
```

1. Canvas launches the tool from the `file_menu` placement with a signed `id_token`.
2. The tool validates the launch completely: signature, issuer, audience, expiry, single-use
   `state` and `nonce`, deployment id, message type.
3. The user authorises the tool to read files **as themselves**, once, through Canvas's
   OAuth2. No administrative or shared service token is ever used.
4. The tool lists the Markdown files that user can see, fetches the chosen one, and renders
   it behind two independent barriers against XSS.

The architecture decisions and threat model behind this are kept in the project's internal
documentation, not published in this repository.

### One thing to know before you install

**Canvas does not tell an LTI 1.3 tool which file the menu was opened from.**

That is not an oversight in this project. The file id exists only in a Canvas-internal URL
and is consumed by the legacy LTI 1.1 code path; the 1.3 launch carries no reference to it,
and Canvas exposes no LTI Advantage scope for reading course files at all. This was confirmed
by reading the relevant Canvas source directly.

So the flow is: **View Markdown → choose the file → read it.** The picker shows Markdown
first, has search, and explains why it is there. It is one extra click, and the tool says so
rather than pretending otherwise.

Improving this upstream in Canvas is on the roadmap.

## Compatibility

|            |                                                                                                                                                                         |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Canvas     | Self-hosted, verified against a live installation. Instructure-hosted Canvas should work — the tool handles the separate OIDC auth domain — but this is **unverified**. |
| LTI        | 1.3 only. LTI 1.1 is not supported and will not be.                                                                                                                     |
| Node.js    | 24 LTS, if you run it without the container                                                                                                                             |
| PostgreSQL | 12 or later                                                                                                                                                             |
| Browsers   | Chrome, Safari, Firefox, and mobile browsers. Works where third-party cookies are blocked.                                                                              |

The specific Canvas release tested is not tracked publicly here; treat any recent
self-hosted Canvas as the target.

## Quick start

```bash
git clone https://github.com/ATuManera/canvas-markdown-viewer-lti.git
cd canvas-markdown-viewer-lti
cp .env.example .env

# Generate the secrets, then edit .env
node -e "console.log('ENCRYPTION_KEYS=1:' + require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('STATE_SECRET=' + require('crypto').randomBytes(48).toString('base64url'))"
node -e "console.log('POSTGRES_PASSWORD=' + require('crypto').randomBytes(24).toString('base64url'))"

docker compose up -d --build
curl -s http://127.0.0.1:3000/healthz     # {"status":"ok"}
```

The tool does not terminate TLS. Put a reverse proxy in front of it with a valid
certificate.

## Installing it in Canvas

A full step-by-step installation guide is not published in this repository. The short
version: create an LTI key from
[`config/canvas-lti.example.json`](config/canvas-lti.example.json), create an API key with
_Enforce Scopes_ and two read-only scopes, install the app by client id, and put the
deployment id in `.env`.

## Security and privacy

Both are enforced by tests, not just asserted. The parts worth knowing before you install:

- **Canvas is read as the user, never as an administrator.** Canvas re-evaluates their
  permissions on every request; this tool does not reimplement them.
- **Refresh tokens are encrypted** with AES-256-GCM and bound to their owner as additional
  authenticated data, so a row moved onto another user's record does not decrypt. A database
  dump without the key is useless.
- **Document content is never stored.** Not on disk, not in the database, not in the logs.
- **External images are blocked by default**, so no remote host learns who is reading what.
- **The bearer credential never crosses an origin.** When a download redirects to file
  storage, the token is dropped.
- **Logs contain no tokens, secrets, document content, names or email addresses** — and a
  test fails if they ever do.
- **No analytics, no telemetry, no third-party calls, no CDN.**

Report a vulnerability privately: [`SECURITY.md`](SECURITY.md).

## Limitations

Stated plainly, because finding them after installing is worse:

- **The file has to be chosen from a list.** See [above](#one-thing-to-know-before-you-install).
- **Each user authorises once**, through a Canvas consent screen. There is no way to skip it
  without using a shared token, which would break the permission model.
- **Two developer keys are required**, because Canvas separates LTI from REST API access.
- **PostgreSQL is required.** It holds encrypted tokens and launch state.
- **Clicking the file name still opens Canvas's own preview.** This tool adds a menu entry;
  it does not replace Canvas's behaviour.
- **No editing.** It is a viewer. It requests no write scope of any kind.
- **No Mermaid, no KaTeX, no JavaScript from documents.** Each would need its own security
  review; they are on the roadmap, not in the product.

## Roadmap

Next up: a navigable table of contents for long documents, section permalinks, and a
proposal to Canvas for letting a `file_menu` launch identify its file securely. Track
progress through this repository's [issues](https://github.com/ATuManera/canvas-markdown-viewer-lti/issues).

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md). Open an issue before writing code for anything beyond a
typo; a change to security behaviour needs a test that fails without it.

## Licence

[Apache License 2.0](LICENSE). Third-party dependencies and their licences:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

Canvas LMS is a trademark of Instructure, Inc. This independent project is not affiliated
with, sponsored by, or endorsed by Instructure.
