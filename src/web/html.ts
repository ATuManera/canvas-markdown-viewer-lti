/**
 * HTML and script escaping.
 *
 * The viewer's own document content goes through the Markdown pipeline and DOMPurify; this
 * module covers everything else the tool renders — file names, course titles, error
 * messages, values it hands to inline script.
 */

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Escapes text for an HTML element or a double-quoted attribute.
 *
 * `'` is escaped as well as `"`, so the result is also safe inside a single-quoted
 * attribute — a caller should not have to know which quoting style the template used.
 */
export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);
}

/**
 * Serialises a value for embedding inside a `<script>` element.
 *
 * `JSON.stringify` alone is not enough: the HTML parser ends a script element at the first
 * `</script`, whatever the Javascript syntax says, so `<` and `>` are escaped as unicode
 * sequences — which JSON and Javascript both read back as the original characters.
 * U+2028 and U+2029 are escaped because they are line terminators in Javascript but not in
 * JSON, and `&` so the value cannot start an HTML entity in an attribute context.
 */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value ?? null)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/** Escapes a value for use inside a URL path segment or query parameter. */
export function escapeUrlComponent(value: string): string {
  return encodeURIComponent(value);
}
