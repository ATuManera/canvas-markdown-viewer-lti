# Support

## What this project is

An open-source tool, maintained by volunteers at [ATuManera](https://github.com/ATuManera).
There is no commercial support contract behind it, and no guaranteed response time.

Being honest about that up front is better than implying otherwise.

## Where to go

| You want to                      | Go to                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------ |
| Install it                       | [`docs/installation/canvas-self-hosted.md`](docs/installation/canvas-self-hosted.md) |
| Understand why it works this way | [`docs/architecture/`](docs/architecture/)                                           |
| Ask a question                   | [Discussions](https://github.com/ATuManera/canvas-markdown-viewer-lti/discussions)   |
| Report a bug                     | [Issues](https://github.com/ATuManera/canvas-markdown-viewer-lti/issues)             |
| Report a vulnerability           | [`SECURITY.md`](SECURITY.md) — **not** a public issue                                |
| Propose a change                 | [`CONTRIBUTING.md`](CONTRIBUTING.md)                                                 |

## Before you open an issue

Most reports are resolved faster with these three things:

1. **What Canvas says.** Self-hosted or Instructure-hosted, and the version.
2. **What the tool logged.** `docker compose logs app`, with the correlation id from the
   error page. The logs are designed to be safe to share — they never contain tokens,
   secrets or document content — but read them before pasting anyway.
3. **What you expected, and what happened instead.**

**Never paste** a token, a `client_secret`, an `ENCRYPTION_KEYS` value, a student's name or
the content of a real course document.

## What is maintained

- The latest release receives bug fixes and security fixes.
- Older releases do not.
- Compatibility is tested against the Canvas versions listed in the README. Anything else
  may work; we cannot claim it does.

## What is not offered

- Installation performed for you.
- Guaranteed response times.
- Custom features on request, without discussion.
- Support for forks.
