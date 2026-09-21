import hljs from 'highlight.js/lib/core';
import bash from 'highlight.js/lib/languages/bash';
import css from 'highlight.js/lib/languages/css';
import diff from 'highlight.js/lib/languages/diff';
import go from 'highlight.js/lib/languages/go';
import java from 'highlight.js/lib/languages/java';
import javascript from 'highlight.js/lib/languages/javascript';
import json from 'highlight.js/lib/languages/json';
import markdown from 'highlight.js/lib/languages/markdown';
import php from 'highlight.js/lib/languages/php';
import plaintext from 'highlight.js/lib/languages/plaintext';
import python from 'highlight.js/lib/languages/python';
import ruby from 'highlight.js/lib/languages/ruby';
import rust from 'highlight.js/lib/languages/rust';
import shell from 'highlight.js/lib/languages/shell';
import sql from 'highlight.js/lib/languages/sql';
import typescript from 'highlight.js/lib/languages/typescript';
import xml from 'highlight.js/lib/languages/xml';
import yaml from 'highlight.js/lib/languages/yaml';

/**
 * Syntax highlighting, restricted to an explicit set of languages.
 *
 * highlight.js is used rather than a themed renderer because its output is **class-based**:
 * `<span class="hljs-keyword">`, never a `style` attribute. That is what lets the viewer
 * run under a Content-Security-Policy with `style-src 'self'` and no `'unsafe-inline'`.
 *
 * Languages are registered one by one rather than importing the whole bundle: it keeps the
 * image small and the parsing surface to what a course's documents plausibly contain.
 */

const LANGUAGES: Record<string, Parameters<typeof hljs.registerLanguage>[1]> = {
  bash,
  css,
  diff,
  go,
  java,
  javascript,
  json,
  markdown,
  php,
  plaintext,
  python,
  ruby,
  rust,
  shell,
  sql,
  typescript,
  xml,
  yaml,
};

for (const [name, language] of Object.entries(LANGUAGES)) {
  hljs.registerLanguage(name, language);
}

/** Aliases people actually write in fences, mapped to a registered language. */
const ALIASES: Record<string, string> = {
  js: 'javascript',
  jsx: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  rb: 'ruby',
  sh: 'bash',
  zsh: 'bash',
  console: 'shell',
  html: 'xml',
  svg: 'xml',
  yml: 'yaml',
  text: 'plaintext',
  txt: 'plaintext',
  md: 'markdown',
  patch: 'diff',
};

export function resolveLanguage(info: string | undefined): string | undefined {
  if (!info) return undefined;
  // A fence's info string may carry more than the language, e.g. ```js title="a.js"
  const first = info.trim().split(/\s+/)[0]?.toLowerCase();
  if (!first) return undefined;
  const resolved = ALIASES[first] ?? first;
  return hljs.getLanguage(resolved) ? resolved : undefined;
}

export interface HighlightResult {
  readonly html: string;
  readonly language: string | undefined;
}

/**
 * Highlights a fenced block. An unknown language, or a failure inside highlight.js, falls
 * back to plain escaped text rather than to raw output.
 */
export function highlightCode(code: string, info: string | undefined): HighlightResult {
  const language = resolveLanguage(info);
  if (!language) return { html: escapeCode(code), language: undefined };

  try {
    const { value } = hljs.highlight(code, { language, ignoreIllegals: true });
    return { html: value, language };
  } catch {
    return { html: escapeCode(code), language: undefined };
  }
}

function escapeCode(code: string): string {
  return code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export const SUPPORTED_LANGUAGES = Object.keys(LANGUAGES).sort();
