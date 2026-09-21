import type { CanvasFile } from '../canvas/files.ts';
import { formatBytes, formatDate, type Locale, type Messages } from '../i18n/catalog.ts';
import { escapeHtml } from '../web/html.ts';

/**
 * The viewer's pages.
 *
 * Everything is rendered on the server and served as plain HTML, so the viewer works with
 * Javascript switched off and the Content-Security-Policy can forbid inline script
 * entirely. The only script is one small external file, for the theme control and the
 * full-window transition.
 *
 * Navigation is by form POST carrying the session token in a hidden field: the token must
 * never appear in a URL, where it would reach browser history, `Referer` headers and proxy
 * logs. See ADR-003.
 */

export const SESSION_FIELD = 'session';

export interface PageContext {
  readonly locale: Locale;
  readonly messages: Messages;
  readonly sessionToken: string;
  readonly basePath: string;
  /** Correlation id, shown on error pages so a user can quote it to support. */
  readonly requestId: string;
}

interface ShellOptions {
  readonly context: PageContext;
  readonly title: string;
  readonly body: string;
  readonly header?: string;
  /** Nonce for the one inline script the relay pages need. Omitted elsewhere. */
  readonly scriptNonce?: string;
}

function shell(options: ShellOptions): string {
  const { context, title, body } = options;
  const m = context.messages;

  return `<!doctype html>
<html lang="${escapeHtml(context.locale)}" data-theme="system">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)} · ${escapeHtml(m.appName)}</title>
<link rel="stylesheet" href="${escapeHtml(context.basePath)}/assets/viewer.css">
</head>
<body>
<a class="skip-link" href="#main">${escapeHtml(m.viewerBack)}</a>
<header class="app-header">
  <h1 class="app-title">${escapeHtml(m.appName)}</h1>
  ${options.header ?? ''}
  <div class="theme-control" data-theme-control hidden>
    <label for="theme-select">${escapeHtml(m.viewerTheme)}</label>
    <select id="theme-select" data-theme-select>
      <option value="system">${escapeHtml(m.viewerThemeSystem)}</option>
      <option value="light">${escapeHtml(m.viewerThemeLight)}</option>
      <option value="dark">${escapeHtml(m.viewerThemeDark)}</option>
    </select>
  </div>
</header>
<main id="main" class="app-main">
${body}
</main>
<footer class="app-footer">
  <p class="notice">${escapeHtml(m.independenceNotice)}</p>
</footer>
<script src="${escapeHtml(context.basePath)}/assets/viewer.js" defer></script>
</body>
</html>`;
}

function sessionField(context: PageContext): string {
  return `<input type="hidden" name="${SESSION_FIELD}" value="${escapeHtml(context.sessionToken)}">`;
}

/** The consent prompt, with both routes out of the iframe. */
export interface AuthorizePageOptions {
  readonly context: PageContext;
  readonly authorizeAction: string;
  readonly fullWindowAction: string;
  readonly denied?: boolean;
}

export function renderAuthorizePage(options: AuthorizePageOptions): string {
  const { context } = options;
  const m = context.messages;

  const denied = options.denied
    ? `<p class="alert alert-warning" role="status">${escapeHtml(m.authorizeDenied)}</p>`
    : '';

  return shell({
    context,
    title: m.authorizeTitle,
    body: `<section class="card">
  <h2>${escapeHtml(m.authorizeTitle)}</h2>
  ${denied}
  <p>${escapeHtml(m.authorizeExplanation)}</p>
  <p class="muted">${escapeHtml(m.authorizeScopes)}</p>
  <form method="post" action="${escapeHtml(options.authorizeAction)}" class="actions">
    ${sessionField(context)}
    <button type="submit" class="button button-primary">${escapeHtml(m.authorizeButton)}</button>
  </form>
  <form method="post" action="${escapeHtml(options.fullWindowAction)}" class="actions" data-full-window>
    ${sessionField(context)}
    <button type="submit" class="button">${escapeHtml(m.authorizeFullWindow)}</button>
    <p class="muted">${escapeHtml(m.authorizeFullWindowHint)}</p>
  </form>
</section>`,
  });
}

export interface PickerPageOptions {
  readonly context: PageContext;
  readonly files: readonly CanvasFile[];
  readonly openAction: string;
  readonly searchAction: string;
  readonly revokeAction: string;
  readonly search?: string | undefined;
  readonly lastOpenedId?: string | undefined;
}

export function renderPickerPage(options: PickerPageOptions): string {
  const { context, files } = options;
  const m = context.messages;

  const markdown = files.filter((file) => file.isMarkdown);
  const others = files.filter((file) => !file.isMarkdown);

  const emptyMessage = options.search ? m.pickerEmptySearch : m.pickerEmpty;
  const list =
    markdown.length > 0
      ? fileTable(markdown, options, m.pickerMarkdownGroup)
      : `<p class="empty" role="status">${escapeHtml(emptyMessage)}</p>`;

  const otherList =
    others.length > 0
      ? `<details class="other-files">
  <summary>${escapeHtml(m.pickerOtherGroup)} (${others.length})</summary>
  ${fileTable(others, options, m.pickerOtherGroup, false)}
</details>`
      : '';

  return shell({
    context,
    title: m.pickerTitle,
    body: `<section class="card">
  <h2>${escapeHtml(m.pickerTitle)}</h2>

  <details class="explain">
    <summary>${escapeHtml(m.pickerWhyTitle)}</summary>
    <p>${escapeHtml(m.pickerWhy)}</p>
  </details>

  <form method="post" action="${escapeHtml(options.searchAction)}" class="search" role="search">
    ${sessionField(context)}
    <label for="search-term">${escapeHtml(m.pickerSearchLabel)}</label>
    <input type="search" id="search-term" name="search" value="${escapeHtml(options.search ?? '')}"
           autocomplete="off" spellcheck="false">
    <button type="submit" class="button">${escapeHtml(m.pickerSearchButton)}</button>
  </form>

  ${list}
  ${otherList}
</section>

<form method="post" action="${escapeHtml(options.revokeAction)}" class="actions actions-quiet">
  ${sessionField(context)}
  <button type="submit" class="button button-quiet">${escapeHtml(m.viewerSignOut)}</button>
</form>`,
  });
}

function fileTable(
  files: readonly CanvasFile[],
  options: PickerPageOptions,
  caption: string,
  highlightLast = true,
): string {
  const { context } = options;
  const m = context.messages;

  const rows = files
    .map((file) => {
      const isLast = highlightLast && file.id === options.lastOpenedId;
      const updated = formatDate(file.updatedAt, context.locale);
      return `<tr${isLast ? ' class="row-last"' : ''}>
  <th scope="row">
    <form method="post" action="${escapeHtml(options.openAction)}">
      ${sessionField(context)}
      <input type="hidden" name="file" value="${escapeHtml(file.id)}">
      <button type="submit" class="link-button">${escapeHtml(file.displayName)}</button>
    </form>
    ${isLast ? `<span class="badge">${escapeHtml(m.pickerLastOpened)}</span>` : ''}
  </th>
  <td>${escapeHtml(file.folderId ?? '—')}</td>
  <td>${escapeHtml(formatBytes(file.size, context.locale))}</td>
  <td>${escapeHtml(updated ?? '—')}</td>
</tr>`;
    })
    .join('\n');

  return `<table class="files">
  <caption class="visually-hidden">${escapeHtml(caption)}</caption>
  <thead>
    <tr>
      <th scope="col">${escapeHtml(m.pickerColumnName)}</th>
      <th scope="col">${escapeHtml(m.pickerColumnFolder)}</th>
      <th scope="col">${escapeHtml(m.pickerColumnSize)}</th>
      <th scope="col">${escapeHtml(m.pickerColumnUpdated)}</th>
    </tr>
  </thead>
  <tbody>
${rows}
  </tbody>
</table>`;
}

export interface DocumentPageOptions {
  readonly context: PageContext;
  readonly file: CanvasFile;
  /** Already sanitised by the Markdown pipeline. Inserted verbatim. */
  readonly contentHtml: string;
  readonly backAction: string;
  readonly downloadAction: string;
  readonly externalImagesBlocked: boolean;
}

export function renderDocumentPage(options: DocumentPageOptions): string {
  const { context, file } = options;
  const m = context.messages;

  const warning = options.externalImagesBlocked
    ? `<p class="alert alert-info" role="status">${escapeHtml(m.viewerExternalImagesBlocked)}</p>`
    : '';

  return shell({
    context,
    title: file.displayName,
    header: `<p class="document-name">${escapeHtml(file.displayName)}</p>`,
    body: `<div class="toolbar">
  <form method="post" action="${escapeHtml(options.backAction)}">
    ${sessionField(context)}
    <button type="submit" class="button">${escapeHtml(m.viewerBack)}</button>
  </form>
  <form method="post" action="${escapeHtml(options.downloadAction)}">
    ${sessionField(context)}
    <input type="hidden" name="file" value="${escapeHtml(file.id)}">
    <button type="submit" class="button">${escapeHtml(m.viewerDownload)}</button>
  </form>
</div>

${warning}

<article class="markdown-body">
${options.contentHtml}
</article>`,
  });
}

export interface ErrorPageOptions {
  readonly context: PageContext;
  readonly message: string;
  readonly backAction?: string;
}

export function renderErrorPage(options: ErrorPageOptions): string {
  const { context } = options;
  const m = context.messages;

  const back = options.backAction
    ? `<form method="post" action="${escapeHtml(options.backAction)}" class="actions">
  ${sessionField(context)}
  <button type="submit" class="button">${escapeHtml(m.viewerBack)}</button>
</form>`
    : '';

  return shell({
    context,
    title: m.errorTitle,
    body: `<section class="card">
  <h2>${escapeHtml(m.errorTitle)}</h2>
  <p class="alert alert-error" role="alert">${escapeHtml(options.message)}</p>
  ${back}
  <p class="muted reference">${escapeHtml(m.errorReference)}: <code>${escapeHtml(context.requestId)}</code></p>
</section>`,
  });
}

/**
 * The error page shown before a session exists — a launch that failed validation, for
 * instance. It carries no session field and no navigation back into the tool.
 */
export function renderStandaloneError(
  locale: Locale,
  messages: Messages,
  basePath: string,
  message: string,
  requestId: string,
): string {
  return renderErrorPage({
    context: { locale, messages, sessionToken: '', basePath, requestId },
    message,
  });
}
