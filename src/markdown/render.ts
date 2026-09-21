import MarkdownItCallable, { type MarkdownIt, type Token } from 'markdown-it';
import { highlightCode } from './highlight.ts';
import { isAllowedUrl, sanitizeHtml } from './sanitize.ts';

/**
 * CommonMark and GitHub Flavored Markdown, rendered safely.
 *
 * Two independent barriers stand between a document and the page:
 *
 *  1. The parser runs with `html: false`, so raw HTML in a document is escaped into text
 *     and never becomes markup.
 *  2. The output is reduced to an explicit allowlist by DOMPurify.
 *
 * Neither depends on the other being correct.
 *
 * A third concern is cost rather than safety: a document can be syntactically valid and
 * still be expensive, so the token stream is measured before anything is rendered.
 */

export interface RenderTexts {
  readonly externalImageBlocked: string;
  readonly externalLink: string;
}

export interface RenderOptions {
  /** Off by default: loading a remote image tells its host who is reading what. */
  readonly allowExternalImages?: boolean;
  readonly maxTokens?: number;
  readonly maxNestingDepth?: number;
  readonly maxRenderMs?: number;
  readonly texts?: Partial<RenderTexts>;
}

export type RenderWarning = 'external_image_blocked' | 'external_link_present';

export interface RenderResult {
  readonly html: string;
  readonly warnings: readonly RenderWarning[];
  readonly stats: {
    readonly tokens: number;
    readonly maxDepth: number;
    readonly renderMs: number;
  };
}

export type RenderRefusalReason = 'too_many_tokens' | 'too_deeply_nested' | 'too_slow';

export class RenderRefused extends Error {
  override readonly name = 'RenderRefused';
  constructor(
    readonly reason: RenderRefusalReason,
    readonly detail: string,
  ) {
    super(`${reason}: ${detail}`);
  }
}

const DEFAULTS = {
  maxTokens: 50_000,
  maxNestingDepth: 32,
  maxRenderMs: 3_000,
} as const;

const DEFAULT_TEXTS: RenderTexts = {
  externalImageBlocked: 'External image not shown',
  externalLink: 'Opens in a new tab',
};

/**
 * markdown-it covers CommonMark plus the GFM pieces the MVP promises — tables, strikethrough
 * and autolinks — natively. Task lists are added below as a small local rule rather than a
 * dependency: it is a dozen lines against a token stream we already walk.
 */
function createParser(): MarkdownIt {
  return MarkdownItCallable({
    // Raw HTML never becomes markup. This is the structural barrier.
    html: false,
    // Autolink bare URLs, as GitHub does.
    linkify: true,
    // A single newline stays a space, as CommonMark specifies.
    breaks: false,
    typographer: false,
    langPrefix: 'hljs language-',
  });
}

export function renderMarkdown(source: string, options: RenderOptions = {}): RenderResult {
  const maxTokens = options.maxTokens ?? DEFAULTS.maxTokens;
  const maxDepth = options.maxNestingDepth ?? DEFAULTS.maxNestingDepth;
  const maxRenderMs = options.maxRenderMs ?? DEFAULTS.maxRenderMs;
  const texts = { ...DEFAULT_TEXTS, ...options.texts };
  const allowExternalImages = options.allowExternalImages ?? false;

  const md = createParser();
  const env: Record<string, unknown> = {};

  const started = performance.now();
  const tokens = md.parse(source, env);

  const measured = measure(tokens);
  if (measured.count > maxTokens) {
    throw new RenderRefused('too_many_tokens', `${measured.count} > ${maxTokens}`);
  }
  if (measured.maxDepth > maxDepth) {
    throw new RenderRefused('too_deeply_nested', `${measured.maxDepth} > ${maxDepth}`);
  }

  const warnings = new Set<RenderWarning>();
  applyTaskLists(tokens);
  installRenderRules(md, { allowExternalImages, texts, warnings });

  const rendered = md.renderer.render(tokens, md.options, env);
  const renderMs = performance.now() - started;

  if (renderMs > maxRenderMs) {
    // The work is already done, so this cannot pre-empt it; what it does is refuse to serve
    // a document that would let a handful of requests occupy the process.
    throw new RenderRefused('too_slow', `${Math.round(renderMs)}ms > ${maxRenderMs}ms`);
  }

  return {
    html: sanitizeHtml(rendered),
    warnings: [...warnings],
    stats: { tokens: measured.count, maxDepth: measured.maxDepth, renderMs },
  };
}

function measure(tokens: readonly Token[]): { count: number; maxDepth: number } {
  let count = 0;
  let maxDepth = 0;

  const walk = (list: readonly Token[]): void => {
    for (const token of list) {
      count += 1;
      if (token.level > maxDepth) maxDepth = token.level;
      if (token.children) walk(token.children);
    }
  };
  walk(tokens);

  return { count, maxDepth };
}

/**
 * GFM task lists. `- [x] done` parses as a list item whose first inline token starts with
 * `[x] `; the marker is replaced with a disabled checkbox and the item is flagged so the
 * stylesheet can drop its bullet.
 */
function applyTaskLists(tokens: Token[]): void {
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token?.type !== 'inline') continue;

    const match = /^\[([ xX])\]\s+/.exec(token.content);
    if (!match) continue;

    const previous = tokens[i - 1];
    const grandparent = tokens[i - 2];
    if (previous?.type !== 'paragraph_open' || grandparent?.type !== 'list_item_open') continue;

    const checked = match[1] !== ' ';
    token.content = token.content.slice(match[0].length);

    const first = token.children?.[0];
    if (first?.type === 'text') {
      first.content = first.content.replace(/^\[([ xX])\]\s+/, '');
    }

    grandparent.attrJoin('class', 'md-task-item');
    previous.attrJoin('class', 'md-task');

    const checkbox = new (token.constructor as typeof Token)('html_inline', '', 0);
    checkbox.content = `<input type="checkbox" disabled${checked ? ' checked' : ''}> `;
    token.children?.unshift(checkbox);
  }
}

interface RuleContext {
  readonly allowExternalImages: boolean;
  readonly texts: RenderTexts;
  readonly warnings: Set<RenderWarning>;
}

function installRenderRules(md: MarkdownIt, context: RuleContext): void {
  const defaultFence = md.renderer.rules['fence'];

  md.renderer.rules['fence'] = (tokens, index, opts, env, self) => {
    const token = tokens[index];
    if (!token) return defaultFence?.(tokens, index, opts, env, self) ?? '';

    const { html, language } = highlightCode(token.content, token.info);
    const languageAttr = language ? ` data-language="${language}"` : '';
    const classAttr = language ? ` class="hljs language-${language}"` : ' class="hljs"';
    return `<pre${languageAttr}><code${classAttr}>${html}</code></pre>\n`;
  };

  md.renderer.rules['link_open'] = (tokens, index, opts, _env, self) => {
    const token = tokens[index];
    if (!token) return '';

    const href = attrString(token, 'href');
    if (!isAllowedUrl(href)) {
      // The scheme is not one we follow. The text stays; the link does not.
      token.attrSet('href', '#');
      token.attrSet('class', 'md-link-blocked');
      return self.renderToken(tokens, index, opts);
    }

    if (/^https?:/i.test(href)) {
      context.warnings.add('external_link_present');
      token.attrSet('target', '_blank');
      token.attrSet('rel', 'noopener noreferrer nofollow');
      token.attrSet('title', attrString(token, 'title') || context.texts.externalLink);
    }

    return self.renderToken(tokens, index, opts);
  };

  md.renderer.rules['image'] = (tokens, index, opts, _env, self) => {
    const token = tokens[index];
    if (!token) return '';

    const src = attrString(token, 'src');
    const alt = token.content;
    const isRemote = /^https?:/i.test(src);

    if (isRemote && !context.allowExternalImages) {
      context.warnings.add('external_image_blocked');
      // The image is replaced by a figure naming it. Nothing is requested from the remote
      // host, so the reader's address and habits are not disclosed to it.
      return (
        `<span class="md-image-blocked" data-external-image="blocked">` +
        escape(alt || context.texts.externalImageBlocked) +
        `<span class="md-image-blocked-note"> — ${escape(context.texts.externalImageBlocked)}</span>` +
        `</span>`
      );
    }

    if (!isAllowedUrl(src)) {
      return `<span class="md-image-blocked">${escape(alt)}</span>`;
    }

    return self.renderToken(tokens, index, opts);
  };
}

/** markdown-it types an attribute as `string | number`; the renderer always wants text. */
function attrString(token: Token, name: string): string {
  const value = token.attrGet(name);
  return value === null ? '' : String(value);
}

function escape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
