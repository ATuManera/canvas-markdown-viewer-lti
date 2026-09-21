import { escapeHtml, jsonForScript } from '../web/html.ts';

/**
 * LTI Platform Storage, the standards-based replacement for a third-party cookie.
 *
 * Canvas implements the 1EdTech specification and signals it with `lti_storage_target`,
 * present on both the login and the launch request
 * (`doc/lti/17_platform_storage.md`, `doc/api/lti_launch_overview.md`). This module produces
 * the two small pages the flow needs; the rules it follows come from Canvas's own
 * documentation:
 *
 *  - The message goes to the frame named by `lti_storage_target`, found at
 *    `window.parent.frames[name]`, except for the default `_parent`, which means
 *    `window.parent`.
 *  - Its target origin must be the platform's **OIDC authorization** origin, which is not
 *    always the Canvas domain: Instructure-hosted Canvas uses `sso.canvaslms.com`.
 *  - If the sibling frame does not answer in time — the case Canvas documents for launches
 *    inside the rich content editor — the tool retries against `window.parent` with `*`.
 *  - When `lti_storage_target` is absent, the tool must not use the API at all and falls
 *    back to cookies.
 *
 * The key carries the value, as Canvas recommends, so several launches in one browser
 * cannot collide: `state-<state>`.
 */

export const PLATFORM_STORAGE_TIMEOUT_MS = 1_000;

export function storageKeyFor(state: string): string {
  return `state-${state}`;
}

/** `_parent` is the specification's default and means the parent window itself. */
export function usesPlatformStorage(target: string | undefined): boolean {
  return typeof target === 'string' && target.length > 0;
}

export interface LoginPageOptions {
  readonly state: string;
  readonly storageTarget: string | undefined;
  /** Origin of the platform's OIDC authorization endpoint — the required message target. */
  readonly authorizationOrigin: string;
  /** Where the browser continues once the state has been stored. */
  readonly redirectUrl: string;
  readonly texts: { readonly title: string; readonly continueLabel: string };
  readonly locale: string;
}

/**
 * Step 2 of the OIDC flow: store the `state`, then continue to the platform.
 *
 * The page continues whether or not the storage call succeeds. A failure here is not fatal:
 * the server-side `launch_states` row is the control that actually prevents replay, and
 * Platform Storage only adds the browser-binding the specification asks for.
 */
export function renderLoginRelay(options: LoginPageOptions): string {
  const payload = {
    key: storageKeyFor(options.state),
    value: options.state,
    target: options.storageTarget ?? '_parent',
    origin: options.authorizationOrigin,
    redirect: options.redirectUrl,
    timeout: PLATFORM_STORAGE_TIMEOUT_MS,
  };

  return page({
    locale: options.locale,
    title: options.texts.title,
    noscript: options.texts.continueLabel,
    noscriptHref: options.redirectUrl,
    script: `
const config = ${jsonForScript(payload)};
let done = false;
function go() { if (!done) { done = true; window.location.replace(config.redirect); } }

function frameFor(name) {
  if (name === '_parent') return window.parent;
  try { return window.parent.frames[name] || window.parent; } catch (e) { return window.parent; }
}

function send(target, origin) {
  try {
    target.postMessage(
      { subject: 'lti.put_data', key: config.key, value: config.value, message_id: config.key },
      origin,
    );
    return true;
  } catch (e) { return false; }
}

window.addEventListener('message', function (event) {
  const data = event.data;
  if (data && data.subject === 'lti.put_data.response' && data.key === config.key) go();
});

if (!send(frameFor(config.target), config.origin)) go();
// Canvas documents that the sibling frame may be unavailable, for instance inside the rich
// content editor. Retry against the parent, then continue regardless.
setTimeout(function () { if (!done) send(window.parent, '*'); }, config.timeout / 2);
setTimeout(go, config.timeout);
`,
  });
}

export interface LaunchVerifyPageOptions {
  readonly state: string;
  readonly storageTarget: string | undefined;
  readonly authorizationOrigin: string;
  /** Endpoint the page posts to once the stored state has been compared. */
  readonly continueUrl: string;
  /** Opaque handle for the already-validated launch, posted back with the verdict. */
  readonly launchHandle: string;
  readonly texts: {
    readonly title: string;
    readonly checking: string;
    readonly mismatch: string;
    readonly continueLabel: string;
  };
  readonly locale: string;
}

/**
 * Step 4: read the stored `state` back and compare it in the browser.
 *
 * The comparison has to happen in Javascript because that is where the value lives, so the
 * page renders a short notice, checks, and then posts the verdict back. A mismatch shows an
 * error and posts nothing.
 */
export function renderLaunchVerification(options: LaunchVerifyPageOptions): string {
  const payload = {
    key: storageKeyFor(options.state),
    expected: options.state,
    target: options.storageTarget ?? '_parent',
    origin: options.authorizationOrigin,
    timeout: PLATFORM_STORAGE_TIMEOUT_MS,
  };

  return page({
    locale: options.locale,
    title: options.texts.title,
    body: `<p id="status">${escapeHtml(options.texts.checking)}</p>
<form id="continue" method="post" action="${escapeHtml(options.continueUrl)}">
  <input type="hidden" name="launch" value="${escapeHtml(options.launchHandle)}">
  <input type="hidden" name="storage_verified" id="verified" value="unavailable">
  <noscript><button type="submit">${escapeHtml(options.texts.continueLabel)}</button></noscript>
</form>`,
    script: `
const config = ${jsonForScript(payload)};
const mismatchText = ${jsonForScript(options.texts.mismatch)};
let settled = false;

function proceed(verdict) {
  if (settled) return;
  settled = true;
  document.getElementById('verified').value = verdict;
  document.getElementById('continue').submit();
}

function fail() {
  if (settled) return;
  settled = true;
  document.getElementById('status').textContent = mismatchText;
}

function frameFor(name) {
  if (name === '_parent') return window.parent;
  try { return window.parent.frames[name] || window.parent; } catch (e) { return window.parent; }
}

window.addEventListener('message', function (event) {
  const data = event.data;
  if (!data || data.subject !== 'lti.get_data.response' || data.key !== config.key) return;
  if (data.value === null || data.value === undefined) {
    // Nothing stored: the launch was not started in this browser, or storage is
    // unavailable. The server-side single-use state already covers replay, so the launch
    // continues and the absence is recorded.
    proceed('unavailable');
  } else if (data.value === config.expected) {
    proceed('match');
  } else {
    fail();
  }
});

try {
  frameFor(config.target).postMessage(
    { subject: 'lti.get_data', key: config.key, message_id: config.key },
    config.origin,
  );
} catch (e) { proceed('unavailable'); }

setTimeout(function () { proceed('unavailable'); }, config.timeout);
`,
  });
}

interface PageOptions {
  readonly locale: string;
  readonly title: string;
  readonly body?: string;
  readonly noscript?: string;
  readonly noscriptHref?: string;
  readonly script: string;
}

/**
 * These two pages carry inline script, which is the one place the tool does. They are
 * served with a `script-src` restricted to this page's nonce; no other page in the tool
 * allows inline script at all.
 */
function page(options: PageOptions): string {
  const noscript =
    options.noscript && options.noscriptHref
      ? `<noscript><a href="${escapeHtml(options.noscriptHref)}">${escapeHtml(options.noscript)}</a></noscript>`
      : '';

  return `<!doctype html>
<html lang="${escapeHtml(options.locale)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(options.title)}</title>
</head>
<body>
${options.body ?? `<p>${escapeHtml(options.title)}</p>`}
${noscript}
<script>${options.script}</script>
</body>
</html>`;
}
