import { describe, expect, it } from 'vitest';
import { renderMarkdown, RenderRefused } from '../../src/markdown/render.ts';
import { isAllowedUrl, sanitizeHtml } from '../../src/markdown/sanitize.ts';
import { resolveLanguage, SUPPORTED_LANGUAGES } from '../../src/markdown/highlight.ts';
import { JSDOM } from 'jsdom';

function html(source: string, options = {}): string {
  return renderMarkdown(source, options).html;
}

describe('CommonMark essentials', () => {
  it('renders headings at every level', () => {
    const out = html('# Uno\n## Dos\n### Tres\n#### Cuatro\n##### Cinco\n###### Seis');
    for (let level = 1; level <= 6; level += 1) {
      expect(out).toContain(`<h${level}>`);
    }
  });

  it('renders paragraphs and emphasis', () => {
    const out = html('Texto con *énfasis*, **fuerte** y `código`.');
    expect(out).toContain('<em>énfasis</em>');
    expect(out).toContain('<strong>fuerte</strong>');
    expect(out).toContain('<code>código</code>');
  });

  it('renders ordered and unordered lists', () => {
    const out = html('- uno\n- dos\n\n1. primero\n2. segundo');
    expect(out).toContain('<ul>');
    expect(out).toContain('<ol>');
    expect(out).toContain('<li>uno</li>');
  });

  it('renders block quotes', () => {
    expect(html('> citado')).toContain('<blockquote>');
  });

  it('renders horizontal rules', () => {
    expect(html('uno\n\n---\n\ndos')).toContain('<hr>');
  });

  it('renders fenced code blocks', () => {
    const out = html('```\nplain text\n```');
    expect(out).toContain('<pre');
    expect(out).toContain('plain text');
  });

  it('keeps a single newline as a space, as CommonMark specifies', () => {
    expect(html('una\nlínea')).toContain('una\nlínea');
    expect(html('una\nlínea')).not.toContain('<br>');
  });

  it('preserves Spanish characters and other unicode', () => {
    const out = html('# Año académico — ñ, ü, ¿qué?, 日本語, 🙂');
    expect(out).toContain('Año académico');
    expect(out).toContain('¿qué?');
    expect(out).toContain('日本語');
    expect(out).toContain('🙂');
  });
});

describe('GitHub Flavored Markdown', () => {
  it('renders tables', () => {
    const out = html('| A | B |\n|---|---|\n| 1 | 2 |');
    expect(out).toContain('<table>');
    expect(out).toContain('<th>A</th>');
    expect(out).toContain('<td>1</td>');
  });

  it('renders strikethrough', () => {
    // markdown-it emits <s>, which is the element GFM's strikethrough maps to.
    expect(html('~~tachado~~')).toContain('<s>tachado</s>');
  });

  it('autolinks a bare URL', () => {
    expect(html('Visita https://example.edu/página hoy')).toContain(
      '<a href="https://example.edu/',
    );
  });

  it('renders task lists as disabled checkboxes', () => {
    const out = html('- [ ] pendiente\n- [x] hecho');
    expect(out).toContain('type="checkbox"');
    expect(out).toContain('disabled');
    expect(out).toContain('checked');
    expect(out).toContain('pendiente');
    expect(out).toContain('hecho');
  });

  it('does not leave the task marker in the text', () => {
    const out = html('- [x] hecho');
    expect(out).not.toContain('[x]');
  });

  it('leaves an ordinary bracketed list item alone', () => {
    const out = html('- [enlace](https://example.edu)');
    expect(out).not.toContain('type="checkbox"');
    expect(out).toContain('<a href="https://example.edu"');
  });
});

describe('code highlighting', () => {
  it('highlights a known language with classes, never inline styles', () => {
    const out = html('```js\nconst a = 1;\n```');
    expect(out).toContain('class="hljs');
    expect(out).toContain('hljs-keyword');
    expect(out).not.toContain('style=');
  });

  it('resolves common aliases', () => {
    expect(resolveLanguage('js')).toBe('javascript');
    expect(resolveLanguage('ts')).toBe('typescript');
    expect(resolveLanguage('sh')).toBe('bash');
    expect(resolveLanguage('html')).toBe('xml');
  });

  it('ignores extra words in the fence info string', () => {
    expect(resolveLanguage('js title="a.js"')).toBe('javascript');
  });

  it('falls back to plain text for an unknown language', () => {
    expect(resolveLanguage('brainfuck')).toBeUndefined();
    const out = html('```brainfuck\n+++\n```');
    expect(out).toContain('+++');
  });

  it('escapes code content rather than letting it become markup', () => {
    const out = html('```\n<script>alert(1)</script>\n```');
    expect(out).not.toContain('<script>');
    expect(out).toContain('&lt;script&gt;');
  });

  it('registers a useful set of languages', () => {
    expect(SUPPORTED_LANGUAGES).toContain('python');
    expect(SUPPORTED_LANGUAGES).toContain('sql');
    expect(SUPPORTED_LANGUAGES.length).toBeGreaterThan(10);
  });
});

/**
 * Dangerous output is asserted against the parsed DOM, not against the HTML text.
 *
 * A vector may legitimately survive as escaped *text* — that is the point of escaping, and
 * the reader still sees what the document said. A textual assertion cannot tell that apart
 * from a real attribute, and would also be fooled by a correctly escaped `title` whose
 * value happens to contain `onmouseover=`. Parsing removes the ambiguity.
 */
function inspect(htmlText: string): Element[] {
  const { window } = new JSDOM(`<!doctype html><body>${htmlText}</body>`);
  return [...window.document.body.querySelectorAll('*')];
}

function eventHandlerAttributes(htmlText: string): string[] {
  return inspect(htmlText).flatMap((element) =>
    element.getAttributeNames().filter((name) => name.toLowerCase().startsWith('on')),
  );
}

function styleAttributes(htmlText: string): string[] {
  return inspect(htmlText)
    .filter((element) => element.hasAttribute('style'))
    .map((element) => element.tagName);
}

function elementNames(htmlText: string): string[] {
  return inspect(htmlText).map((element) => element.tagName.toLowerCase());
}

function urlAttributes(htmlText: string): string[] {
  return inspect(htmlText).flatMap((element) =>
    ['href', 'src'].map((name) => element.getAttribute(name) ?? '').filter(Boolean),
  );
}

const EXECUTABLE_SCHEME = /^\s*(?:javascript|data|vbscript):/i;

describe('XSS — raw HTML in the document', () => {
  const vectors = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<iframe src="https://evil.example"></iframe>',
    '<object data="x"></object>',
    '<embed src="x">',
    '<form action="https://evil.example"><input name="a"></form>',
    '<a href="javascript:alert(1)">click</a>',
    '<div style="position:fixed;top:0">cover</div>',
    '<base href="https://evil.example/">',
    '<meta http-equiv="refresh" content="0;url=https://evil.example">',
    '<link rel="stylesheet" href="https://evil.example/x.css">',
    '<style>body{display:none}</style>',
    '<body onload=alert(1)>',
    '<math><mtext><script>alert(1)</script></mtext></math>',
    '<xss onafterscriptexecute=alert(1)>',
  ];

  for (const vector of vectors) {
    it(`neutralises ${vector.slice(0, 40)}`, () => {
      const out = html(`Antes\n\n${vector}\n\nDespués`);

      const names = elementNames(out);
      for (const tag of [
        'script',
        'iframe',
        'object',
        'embed',
        'form',
        'base',
        'meta',
        'link',
        'style',
      ]) {
        expect(names).not.toContain(tag);
      }
      expect(eventHandlerAttributes(out)).toEqual([]);
      expect(styleAttributes(out)).toEqual([]);
      expect(out).toContain('Antes');
      expect(out).toContain('Después');
    });
  }

  it('escapes raw HTML into visible text rather than dropping it silently', () => {
    const out = html('<b>negrita</b>');
    expect(out).toContain('&lt;b&gt;');
  });
});

describe('XSS — through Markdown syntax', () => {
  it('refuses a javascript: link, leaving the text visible', () => {
    const out = html('[pulsa](javascript:alert(1))');
    expect(urlAttributes(out).filter((u) => EXECUTABLE_SCHEME.test(u))).toEqual([]);
    expect(out).toContain('pulsa');
  });

  it('refuses a javascript: link with mixed case and whitespace', () => {
    const out = html('[x](  JaVaScRiPt:alert(1))');
    expect(urlAttributes(out).filter((u) => EXECUTABLE_SCHEME.test(u))).toEqual([]);
  });

  it('refuses a data: URL', () => {
    const out = html('[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)');
    expect(urlAttributes(out).filter((u) => EXECUTABLE_SCHEME.test(u))).toEqual([]);
  });

  it('refuses a vbscript: link', () => {
    const out = html('[x](vbscript:msgbox(1))');
    expect(urlAttributes(out).filter((u) => EXECUTABLE_SCHEME.test(u))).toEqual([]);
  });

  it('refuses a javascript: image source', () => {
    const out = html('![alt](javascript:alert(1))');
    expect(urlAttributes(out).filter((u) => EXECUTABLE_SCHEME.test(u))).toEqual([]);
  });

  it('keeps an ordinary https link and marks it as external', () => {
    const out = html('[Canvas](https://canvas.example.edu/page)');
    expect(out).toContain('href="https://canvas.example.edu/page"');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
    expect(out).toContain('target="_blank"');
  });

  it('keeps a mailto link', () => {
    expect(html('[correo](mailto:alguien@example.edu)')).toContain('mailto:alguien@example.edu');
  });

  it('keeps a relative link without marking it external', () => {
    const out = html('[interno](./otra-pagina.md)');
    expect(out).toContain('href="./otra-pagina.md"');
    expect(out).not.toContain('target="_blank"');
  });

  it('does not let a title attribute break out of the tag', () => {
    const out = html('[x](https://example.edu "a\\" onmouseover=\\"alert(1)")');
    // The payload survives as the *value* of a correctly escaped title attribute, which is
    // inert. What matters is that no element gained an event handler.
    expect(eventHandlerAttributes(out)).toEqual([]);
    expect(out).toContain('&quot;');
  });
});

describe('external images', () => {
  it('blocks a remote image by default and says so', () => {
    const result = renderMarkdown('![Diagrama](https://tracker.example/pixel.png)');
    expect(result.html).not.toContain('tracker.example');
    expect(result.html).toContain('Diagrama');
    expect(result.warnings).toContain('external_image_blocked');
  });

  it('never requests the remote host, because the URL is not emitted at all', () => {
    expect(html('![x](https://tracker.example/pixel.png)')).not.toContain('<img');
  });

  it('renders a remote image when the operator has allowed it', () => {
    const out = html('![Diagrama](https://cdn.example.edu/d.png)', { allowExternalImages: true });
    expect(out).toContain('<img');
    expect(out).toContain('cdn.example.edu');
  });

  it('reports no warning for a document without external images', () => {
    expect(renderMarkdown('# solo texto').warnings).toEqual([]);
  });
});

describe('complexity limits', () => {
  it('refuses a document with too many tokens', () => {
    const source = Array.from({ length: 500 }, (_, i) => `párrafo ${i}`).join('\n\n');
    expect(() => renderMarkdown(source, { maxTokens: 50 })).toThrow(RenderRefused);
    expect(() => renderMarkdown(source, { maxTokens: 50 })).toThrow(/too_many_tokens/);
  });

  it('refuses a deeply nested document', () => {
    const nested = Array.from({ length: 60 }, (_, i) => `${'  '.repeat(i)}- nivel ${i}`).join('\n');
    expect(() => renderMarkdown(nested, { maxNestingDepth: 10 })).toThrow(/too_deeply_nested/);
  });

  it('refuses a document that took too long', () => {
    expect(() => renderMarkdown('# hola', { maxRenderMs: -1 })).toThrow(/too_slow/);
  });

  it('renders an ordinary document well inside the limits', () => {
    const result = renderMarkdown('# Título\n\nTexto normal.\n\n- uno\n- dos');
    expect(result.stats.tokens).toBeLessThan(100);
    expect(result.stats.maxDepth).toBeLessThan(10);
  });

  it('survives a long line without blowing up', () => {
    expect(() => renderMarkdown('a'.repeat(200_000))).not.toThrow();
  });

  it('survives pathological emphasis nesting', () => {
    expect(() => renderMarkdown('*'.repeat(2_000))).not.toThrow();
  });
});

describe('sanitizeHtml directly', () => {
  it('drops a script even when handed to it outside the renderer', () => {
    expect(sanitizeHtml('<p>ok</p><script>alert(1)</script>')).toBe('<p>ok</p>');
  });

  it('drops an id attribute so a document cannot collide with the viewer', () => {
    expect(sanitizeHtml('<p id="main">x</p>')).not.toContain('id=');
  });

  it('drops a style attribute', () => {
    expect(sanitizeHtml('<p style="color:red">x</p>')).not.toContain('style');
  });

  it('keeps only the class names the renderer and highlighter emit', () => {
    const out = sanitizeHtml('<span class="hljs-keyword evil-class md-task">x</span>');
    expect(out).toContain('hljs-keyword');
    expect(out).toContain('md-task');
    expect(out).not.toContain('evil-class');
  });

  it('keeps a disabled task checkbox and drops any other input', () => {
    expect(sanitizeHtml('<input type="checkbox" disabled>')).toContain('checkbox');
    expect(sanitizeHtml('<input type="text" name="password">')).not.toContain('<input');
  });

  it('adds noopener to any link that targets another window', () => {
    const out = sanitizeHtml('<a href="https://example.edu" target="_blank">x</a>');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
  });

  it('keeps table markup intact', () => {
    const out = sanitizeHtml('<table><tr><td colspan="2">x</td></tr></table>');
    expect(out).toContain('colspan="2"');
  });
});

describe('isAllowedUrl', () => {
  it('accepts the schemes the viewer follows', () => {
    expect(isAllowedUrl('https://example.edu')).toBe(true);
    expect(isAllowedUrl('http://example.edu')).toBe(true);
    expect(isAllowedUrl('mailto:a@example.edu')).toBe(true);
  });

  it('accepts relative targets and fragments', () => {
    expect(isAllowedUrl('./a.md')).toBe(true);
    expect(isAllowedUrl('/a.md')).toBe(true);
    expect(isAllowedUrl('#seccion')).toBe(true);
    expect(isAllowedUrl('otra.md')).toBe(true);
  });

  it('refuses executable and embedding schemes', () => {
    for (const url of [
      'javascript:alert(1)',
      'JAVASCRIPT:alert(1)',
      'data:text/html,<script>',
      'vbscript:x',
      'file:///etc/passwd',
    ]) {
      expect(isAllowedUrl(url)).toBe(false);
    }
  });
});
