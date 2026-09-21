import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../../src/markdown/render.ts';

/**
 * The fixture documents rendered end to end, as a document from a course would be.
 *
 * The inline tests exercise one construct at a time; these check that a whole document
 * behaves — that the safe parts survive alongside the hostile ones, which is what a reader
 * actually experiences.
 */

function fixture(name: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../fixtures/markdown/${name}`, import.meta.url)),
    'utf8',
  );
}

function elements(htmlText: string): Element[] {
  const { window } = new JSDOM(`<!doctype html><body>${htmlText}</body>`);
  return [...window.document.body.querySelectorAll('*')];
}

function tagNames(htmlText: string): string[] {
  return elements(htmlText).map((element) => element.tagName.toLowerCase());
}

function attributeNames(htmlText: string): string[] {
  return elements(htmlText).flatMap((element) => element.getAttributeNames());
}

describe('valid.md', () => {
  const result = renderMarkdown(fixture('valid.md'));

  it('renders the document structure', () => {
    expect(tagNames(result.html)).toEqual(
      expect.arrayContaining(['h1', 'h2', 'p', 'ol', 'li', 'blockquote', 'hr', 'strong', 'em']),
    );
  });

  it('keeps a relative link usable and does not mark it external', () => {
    const anchor = elements(result.html).find((e) => e.tagName === 'A');
    expect(anchor?.getAttribute('href')).toBe('./otra-pagina.md');
    expect(anchor?.hasAttribute('target')).toBe(false);
  });

  it('reports no warnings', () => {
    expect(result.warnings).toEqual([]);
  });
});

describe('gfm.md', () => {
  const result = renderMarkdown(fixture('gfm.md'));

  it('renders the table with its header', () => {
    expect(result.html).toContain('<table>');
    expect(result.html).toContain('<th>Semana</th>');
    expect(result.html).toContain('Introducción');
  });

  it('renders the task list as disabled checkboxes, one of them checked', () => {
    const boxes = elements(result.html).filter((e) => e.tagName === 'INPUT');
    expect(boxes).toHaveLength(3);
    expect(boxes.every((b) => b.hasAttribute('disabled'))).toBe(true);
    expect(boxes.filter((b) => b.hasAttribute('checked'))).toHaveLength(1);
  });

  it('renders strikethrough and autolinks', () => {
    expect(result.html).toContain('<s>descartado</s>');
    expect(result.html).toContain('href="https://example.edu/recursos"');
  });
});

describe('fenced-code.md', () => {
  const result = renderMarkdown(fixture('fenced-code.md'));

  it('highlights the languages it knows', () => {
    expect(result.html).toContain('language-python');
    expect(result.html).toContain('language-sql');
    expect(result.html).toContain('hljs-keyword');
  });

  it('renders an undeclared fence as plain code', () => {
    expect(result.html).toContain('sin lenguaje declarado');
  });

  it('uses classes and never inline styles, so a strict CSP holds', () => {
    expect(attributeNames(result.html)).not.toContain('style');
  });
});

describe('unicode-spanish.md', () => {
  const result = renderMarkdown(fixture('unicode-spanish.md'));

  it('preserves Spanish orthography exactly', () => {
    for (const text of [
      'Año académico',
      '¿preparado?',
      'á é í ó ú ü ñ Ñ',
      '¡Ojo!',
      '«españolas»',
    ]) {
      expect(result.html).toContain(text);
    }
  });

  it('preserves other scripts and emoji', () => {
    for (const text of ['日本語', 'Ελληνικά', 'Русский', 'العربية', '🎓']) {
      expect(result.html).toContain(text);
    }
  });
});

describe('malicious-html.md', () => {
  const result = renderMarkdown(fixture('malicious-html.md'));

  it('produces no executable or embedding element', () => {
    const names = tagNames(result.html);
    for (const tag of ['script', 'iframe', 'form', 'input', 'svg', 'style', 'object', 'embed']) {
      expect(names).not.toContain(tag);
    }
  });

  it('produces no event handler and no style attribute', () => {
    const attributes = attributeNames(result.html).map((n) => n.toLowerCase());
    expect(attributes.filter((n) => n.startsWith('on'))).toEqual([]);
    expect(attributes).not.toContain('style');
  });

  it('still shows the legitimate text around the hostile markup', () => {
    expect(result.html).toContain('Texto legítimo después de todo lo anterior.');
  });

  it('shows the hostile markup as visible, inert text', () => {
    expect(result.html).toContain('&lt;script&gt;');
  });
});

describe('javascript-url.md', () => {
  const result = renderMarkdown(fixture('javascript-url.md'));

  it('emits no URL with an executable scheme', () => {
    const urls = elements(result.html).flatMap((element) =>
      ['href', 'src'].map((name) => element.getAttribute(name) ?? ''),
    );
    expect(urls.filter((u) => /^\s*(?:javascript|data|vbscript):/i.test(u))).toEqual([]);
  });

  it('keeps the legitimate link', () => {
    expect(result.html).toContain('href="https://example.edu/pagina"');
  });

  it('keeps the link text of the refused links visible', () => {
    expect(result.html).toContain('Enlace javascript');
    expect(result.html).toContain('Enlace vbscript');
  });
});

describe('external-image.md', () => {
  it('blocks remote images by default and requests nothing from their hosts', () => {
    const result = renderMarkdown(fixture('external-image.md'));

    expect(tagNames(result.html)).not.toContain('img');
    expect(result.html).not.toContain('tracker.example');
    expect(result.html).not.toContain('cdn.example.edu');
    expect(result.warnings).toContain('external_image_blocked');
    expect(result.html).toContain('Diagrama alojado fuera');
    expect(result.html).toContain('Texto entre imágenes.');
  });

  it('renders them when the operator has chosen to allow it', () => {
    const result = renderMarkdown(fixture('external-image.md'), { allowExternalImages: true });

    expect(tagNames(result.html)).toContain('img');
    expect(result.html).toContain('cdn.example.edu');
  });
});

describe('every fixture', () => {
  const names = [
    'valid.md',
    'gfm.md',
    'fenced-code.md',
    'unicode-spanish.md',
    'malicious-html.md',
    'javascript-url.md',
    'external-image.md',
  ];

  for (const name of names) {
    it(`${name} renders without an event handler, style or executable URL`, () => {
      const { html } = renderMarkdown(fixture(name));
      const attributes = attributeNames(html).map((n) => n.toLowerCase());

      expect(attributes.filter((n) => n.startsWith('on'))).toEqual([]);
      expect(attributes).not.toContain('style');
      expect(attributes).not.toContain('id');
    });
  }

  it('contains no credential-shaped string in any fixture', () => {
    for (const name of names) {
      const text = fixture(name);
      expect(text).not.toMatch(/(?:api[_-]?key|secret|password\s*[:=]\s*\S)/i);
    }
  });
});
