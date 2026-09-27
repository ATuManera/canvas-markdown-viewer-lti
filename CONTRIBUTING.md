# Contributing

Thank you for considering it. This document is short, and none of it is ceremony: every rule
here exists because it prevents a specific problem.

## Before you write code

Open an issue first for anything beyond a typo. It is easier to discuss a direction in
prose than to discuss it in a diff that took you an evening.

For a security problem, do **not** open an issue. See [`SECURITY.md`](SECURITY.md).

## Getting set up

```bash
git clone https://github.com/ATuManera/canvas-markdown-viewer-lti.git
cd canvas-markdown-viewer-lti
npm ci
npm run verify          # lint, typecheck, tests, build
```

The integration tests need PostgreSQL. Without it they skip, and the suite still passes —
but your change is then less tested than CI will test it:

```bash
docker run -d --rm --name cmv-pg -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \
  -e POSTGRES_DB=cmv_test -p 5433:5432 postgres:17-alpine

TEST_DATABASE_URL="postgres://test:test@127.0.0.1:5433/cmv_test" npm test
```

## What a change needs

**Tests.** Not as a formality: a change to security behaviour needs a test that fails
without it. The suite already contains the negative cases — forged signatures, replayed
launches, SSRF targets, XSS vectors — and a new control belongs alongside them.

**Comments that explain why.** The codebase documents reasoning, not mechanics. `// loop
over the files` adds nothing; "the course-scoped route is used so Canvas enforces
membership rather than this code inferring it" is the kind of thing that survives.

**Green checks.** `npm run verify` must pass. CI runs the same commands plus a dependency
audit, a secret scan and a container build.

**No new dependency without a reason in the pull request.** Every package is a thing someone
has to audit and update. If the standard library or twenty lines of our own code will do,
prefer that.

## What a change must not contain

- A secret, a token, a real Canvas hostname belonging to an institution, or anything from a
  real course. The fixtures are invented on purpose.
- A `console.log`. The logger redacts; `console` does not.
- A loosened security control without a written argument in the pull request for why it is
  safe. "The test was annoying" is not one.
- Analytics, telemetry, or a call to any third-party service.

## Keeping the documentation true

If a change alters something the documentation describes — a stored field, a setting, a
security property — **update the README, CHANGELOG or SECURITY.md in the same change**. A
document that has drifted from the code is worse than none, because people trust it.

This project's architecture decisions and threat model are kept in an internal design
document, not published in this repository. If your change affects either, say so in the
pull request; the maintainer will update that document separately.

## Commits and pull requests

Commit messages use [Conventional Commits](https://www.conventionalcommits.org):
`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. Write the body in the imperative,
and say **why**, not just what.

In the pull request, tell us:

- what it changes and why;
- what you tested, and how;
- anything you are unsure about — that is useful information, not a weakness.

## Translations

The interface is Spanish and English. Both live in `src/i18n/catalog.ts`, typed, so a
missing string is a compile error rather than a key shown to a student.

To add a language: add it to `LOCALES`, add the catalogue, and add it to the language test.
Please translate the meaning rather than the words — especially the explanation of why the
file has to be chosen, which is the one piece of text users actually read.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0,
the same as the project.
