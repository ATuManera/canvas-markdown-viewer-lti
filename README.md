# canvas-markdown-viewer-lti

**Open-source Markdown file viewer for Canvas LMS, built with LTI 1.3.**

[![CI](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml/badge.svg)](https://github.com/ATuManera/canvas-markdown-viewer-lti/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> 🇪🇸 **[Léeme en español](README.es.md)** · 📘 **[Installation guide](docs/installation/canvas-self-hosted.md)**

---

## The problem

Upload a `.md` file to a Canvas course and Canvas offers to download it. It will not render
it. Students get a file; teachers get a support question.

This tool adds **Ver Markdown** / **View Markdown** to a file's context menu. Selecting it
opens the document, rendered and readable, inside Canvas.

It is a standard LTI 1.3 tool. It does not modify Canvas, does not require a fork, and does
not depend on the Canvas theme's JavaScript.

## What it looks like

No screenshot yet. This project has not been verified against a live Canvas installation, so
there is nothing to show that would not be staged. One will be added here once it has, and
this sentence will be replaced.

That is also why there is no released version. See [Status](#status).

## Status

**Not yet released.** The code is complete and tested; it has not been run against a real
Canvas installation. Until it has, this project makes no claim that it works in production,
and no version is tagged.

What that means in practice:

- ✅ Every component is covered by automated tests, including the negative security cases.
- ✅ The container builds and passes a smoke test.
- ⏳ The LTI launch, the OAuth2 consent and the browser behaviour have not been exercised
  against a live Canvas.
- ⏳ The exact Canvas API scope strings are derived from Canvas source and must be confirmed
  against a target installation.

Progress is in [`docs/roadmap.md`](docs/roadmap.md).

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

Full detail: [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

### One thing to know before you install

**Canvas does not tell an LTI 1.3 tool which file the menu was opened from.**

That is not an oversight in this project. The file id exists only in a Canvas-internal URL
and is consumed by the legacy LTI 1.1 code path; the 1.3 launch carries no reference to it,
and Canvas exposes no LTI Advantage scope for reading course files at all. The evidence, read
from Canvas source, is in
[`docs/research/canvas-lti-file-menu.md`](docs/research/canvas-lti-file-menu.md).

So the flow is: **View Markdown → choose the file → read it.** The picker shows Markdown
first, has search, and explains why it is there. It is one extra click, and the tool says so
rather than pretending otherwise.

Improving this upstream in Canvas is on the roadmap.

## Compatibility

|            |                                                                                                                                   |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Canvas     | Self-hosted. Instructure-hosted Canvas should work — the tool handles the separate OIDC auth domain — but this is **unverified**. |
| LTI        | 1.3 only. LTI 1.1 is not supported and will not be.                                                                               |
| Node.js    | 24 LTS, if you run it without the container                                                                                       |
| PostgreSQL | 12 or later                                                                                                                       |
| Browsers   | Chrome, Safari, Firefox, and mobile browsers. Works where third-party cookies are blocked.                                        |

No Canvas version is claimed as tested, because none has been.

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

The full procedure — two developer keys and why both are needed, the scopes, the deployment
id, TLS at the origin, Cloudflare, and how to undo all of it — is in
**[`docs/installation/canvas-self-hosted.md`](docs/installation/canvas-self-hosted.md)**.

The short version: create an LTI key from
[`config/canvas-lti.example.json`](config/canvas-lti.example.json), create an API key with
_Enforce Scopes_ and three read-only scopes, install the app by client id, and put the
deployment id in `.env`.

## Security and privacy

Both are documented rather than asserted:
[`docs/security/threat-model.md`](docs/security/threat-model.md) lists every threat with the
control that addresses it and the test that proves it;
[`docs/security/privacy.md`](docs/security/privacy.md) says exactly what is stored.

The parts worth knowing before you install:

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
- **Not verified against a live Canvas yet.** See [Status](#status).

## Roadmap

[`docs/roadmap.md`](docs/roadmap.md). In short: finish verification against a real Canvas,
then look at a table of contents, section permalinks, and a proposal to Canvas for letting a
`file_menu` launch identify its file securely.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md). Open an issue before writing code for anything beyond a
typo; a change to security behaviour needs a test that fails without it.

## Licence

[Apache License 2.0](LICENSE). Third-party dependencies and their licences:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

Canvas LMS is a trademark of Instructure, Inc. This independent project is not affiliated
with, sponsored by, or endorsed by Instructure.
