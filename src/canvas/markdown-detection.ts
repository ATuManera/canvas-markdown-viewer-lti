/**
 * Deciding whether a Canvas file is Markdown.
 *
 * No single signal is trustworthy:
 *
 *  - **`accept_media_types` is advisory.** Canvas applies it in the browser only
 *    (`ui/features/files_v2/utils/fileUtils.ts`); nothing enforces it server-side, so a
 *    launch can arrive for any file at all.
 *  - **The MIME type is whatever the uploader's browser claimed.** Canvas only falls back
 *    to its own table when the client sends nothing usable (`app/models/attachment.rb:547`),
 *    so the same `.md` file can be stored as `text/markdown`, `text/plain` or
 *    `application/octet-stream` depending on the machine it was uploaded from.
 *  - **The extension is a hint** that a user chooses freely.
 *
 * So all three are checked — name, declared type, and the bytes themselves — and the
 * answer is only "yes" when nothing contradicts it.
 */

/** Extensions treated as Markdown. `.mdx` is deliberately absent: it is Javascript. */
const MARKDOWN_EXTENSIONS = new Set([
  '.md',
  '.markdown',
  '.mdown',
  '.mkd',
  '.mkdn',
  '.mdtext',
  '.mdtxt',
  '.text',
]);

/**
 * MIME types accepted for a file whose name already looks like Markdown. The generic ones
 * are here because Canvas genuinely stores `.md` files under them; they are never enough on
 * their own.
 */
const ACCEPTED_MIME_TYPES = new Set([
  'text/markdown',
  'text/x-markdown',
  'text/plain',
  'application/markdown',
  'application/x-markdown',
  'application/octet-stream',
  'binary/octet-stream',
  '',
]);

/** Types this tool declares it can accept, for the `accept_media_types` placement setting. */
export const ACCEPT_MEDIA_TYPES = [
  'text/markdown',
  'text/x-markdown',
  'text/plain',
  'application/octet-stream',
] as const;

export function fileExtension(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? name;
  const dot = base.lastIndexOf('.');
  return dot <= 0 ? '' : base.slice(dot).toLowerCase();
}

export function hasMarkdownExtension(name: string): boolean {
  return MARKDOWN_EXTENSIONS.has(fileExtension(name));
}

/** Strips the `; charset=…` Canvas may append before comparing. */
export function normaliseMime(contentType: string | undefined | null): string {
  return (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
}

export function isAcceptableMime(contentType: string | undefined | null): boolean {
  return ACCEPTED_MIME_TYPES.has(normaliseMime(contentType));
}

/** Both the name and the declared type must be consistent with Markdown. */
export function looksLikeMarkdown(name: string, contentType: string | undefined | null): boolean {
  return hasMarkdownExtension(name) && isAcceptableMime(contentType);
}

export type ContentVerdict =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: 'binary' | 'invalid_encoding' | 'empty' };

/**
 * The final check, on the bytes themselves.
 *
 * A UTF-8 BOM is stripped, a NUL byte means the file is not text whatever it was called,
 * and the decode must round-trip: `TextDecoder` with `fatal` rejects malformed sequences
 * rather than quietly substituting replacement characters, so a mislabelled binary cannot
 * reach the renderer as mojibake.
 */
export function decodeMarkdown(body: Buffer): ContentVerdict {
  if (body.length === 0) return { ok: false, reason: 'empty' };

  const withoutBom =
    body.length >= 3 && body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf
      ? body.subarray(3)
      : body;

  if (withoutBom.includes(0x00)) return { ok: false, reason: 'binary' };

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(withoutBom);
    return { ok: true, text };
  } catch {
    return { ok: false, reason: 'invalid_encoding' };
  }
}
