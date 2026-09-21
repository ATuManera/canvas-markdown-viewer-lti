import DOMPurify from 'isomorphic-dompurify';

/**
 * The second of two independent barriers against XSS.
 *
 * The first is structural: the Markdown parser runs with `html: false`, so raw HTML in a
 * document is escaped into text and never becomes markup at all. This module does not rely
 * on that. It takes whatever HTML it is given and reduces it to an explicit allowlist, so
 * that a bug in the renderer — or a future change to it — cannot produce executable output.
 *
 * The allowlist is deliberately small. Anything a course document needs to express is here;
 * anything that can load, execute or embed is not.
 */

/** Elements the viewer will render. No `iframe`, `object`, `embed`, `form` or `style`. */
const ALLOWED_TAGS = [
  'p',
  'br',
  'hr',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'strong',
  'em',
  's',
  'del',
  'ins',
  'sub',
  'sup',
  'mark',
  'small',
  'blockquote',
  'ul',
  'ol',
  'li',
  'dl',
  'dt',
  'dd',
  'table',
  'thead',
  'tbody',
  'tfoot',
  'tr',
  'th',
  'td',
  'caption',
  'code',
  'pre',
  'kbd',
  'samp',
  'var',
  'a',
  'img',
  'span',
  'div',
  'figure',
  'figcaption',
  'abbr',
  'input', // only a disabled checkbox survives the attribute rules below
] as const;

/**
 * Attributes kept. No `style`, so nothing in a document can position or hide an element;
 * no `id` either, so a document cannot collide with the viewer's own anchors. `class` is
 * kept for the highlighter's spans and is filtered by prefix in the hook below.
 */
const ALLOWED_ATTR = [
  'href',
  'src',
  'alt',
  'title',
  'class',
  'colspan',
  'rowspan',
  'align',
  'type',
  'checked',
  'disabled',
  'rel',
  'target',
  'lang',
  'dir',
  'data-language',
  'data-external-image',
] as const;

/** URL schemes a link may use. `javascript:`, `data:` and `vbscript:` are not here. */
const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

/**
 * The same rule, in the shape DOMPurify wants: either one of the three schemes, or a value
 * that cannot be a scheme at all — which is how a relative link or a fragment passes.
 *
 * It follows the structure of DOMPurify's own default pattern rather than inventing one,
 * narrowed from its list (which also permits ftp, tel, sms and callto) to the three this
 * viewer is willing to render. Note that DOMPurify applies this pattern to attributes it
 * treats as URI-bearing, so a pattern requiring an absolute scheme would also strip
 * relative links — and, less obviously, `target`, `rel`, `colspan` and `type`.
 */
const ALLOWED_URI_PATTERN = /^(?:(?:https?|mailto):|[^a-z+.-]|[a-z+.-]+(?:[^a-z+.:-]|$))/i;

/**
 * Class names the renderer emits: the highlighter's `hljs`/`hljs-*`, this renderer's own
 * `md-*`, and `language-*`, which names the fence's language for the stylesheet. Anything
 * else a document invents is dropped, so a document cannot borrow the viewer's styling.
 */
const ALLOWED_CLASS_PREFIXES = ['hljs', 'md-', 'language-'];

let configured = false;

function configure(): void {
  if (configured) return;
  configured = true;

  DOMPurify.addHook('uponSanitizeElement', (node, data) => {
    // A checkbox is allowed only as the disabled marker of a GFM task list item.
    if (data.tagName === 'input') {
      const element = node as Element;
      const isTaskCheckbox =
        element.getAttribute('type') === 'checkbox' && element.hasAttribute('disabled');
      if (!isTaskCheckbox) element.remove();
    }
  });

  DOMPurify.addHook('afterSanitizeAttributes', (element) => {
    if (element.hasAttribute('class')) {
      const kept = (element.getAttribute('class') ?? '')
        .split(/\s+/)
        .filter((name) => ALLOWED_CLASS_PREFIXES.some((prefix) => name.startsWith(prefix)));
      if (kept.length > 0) element.setAttribute('class', kept.join(' '));
      else element.removeAttribute('class');
    }

    // Every link that opens elsewhere gets the full set: a document must not be able to
    // reach back into this window through `window.opener`.
    if (element.tagName === 'A' && element.hasAttribute('target')) {
      element.setAttribute('rel', 'noopener noreferrer nofollow');
    }
  });
}

export interface SanitizeOptions {
  /** When false, `img` is dropped entirely rather than left for the renderer to placehold. */
  readonly allowImages?: boolean;
}

/**
 * Reduces HTML to the allowlist. The result is safe to insert into the viewer's page.
 *
 * `SAFE_FOR_TEMPLATES` is not used: the output goes into a plain document, not a template
 * engine. `RETURN_DOM` is not used either, because the caller wants a string.
 */
export function sanitizeHtml(html: string, options: SanitizeOptions = {}): string {
  configure();

  const tags =
    options.allowImages === false ? ALLOWED_TAGS.filter((t) => t !== 'img') : ALLOWED_TAGS;

  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [...tags],
    ALLOWED_ATTR: [...ALLOWED_ATTR],
    ALLOWED_URI_REGEXP: ALLOWED_URI_PATTERN,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: true,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    WHOLE_DOCUMENT: false,
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'base', 'link', 'meta'],
    FORBID_ATTR: ['style', 'id', 'srcset', 'sizes', 'ping', 'formaction', 'background'],
  });
}

/** Whether a URL is one the viewer will link to at all. */
export function isAllowedUrl(value: string): boolean {
  const trimmed = value.trim();
  // A bare fragment or a relative path never carries a scheme and is harmless.
  if (trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('./')) return true;
  try {
    return ALLOWED_SCHEMES.has(new URL(trimmed).protocol);
  } catch {
    // Not absolute: treat as relative, which the renderer resolves or leaves as text.
    return !/^[a-z][a-z0-9+.-]*:/i.test(trimmed);
  }
}

export { ALLOWED_TAGS, ALLOWED_ATTR };
