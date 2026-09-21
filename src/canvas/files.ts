import type { Platform } from '../config/platforms.ts';
import { decodeMarkdown, looksLikeMarkdown, normaliseMime } from './markdown-detection.ts';
import { SafeFetcher, redactUrl, type SafeFetchOptions } from './safe-fetch.ts';

/**
 * Reading Canvas files on behalf of the launching user.
 *
 * Every request carries that user's access token, so Canvas re-evaluates their permissions
 * each time and this tool never has to reimplement them. The course always comes from the
 * validated launch, never from user input, and a file is only fetched through the
 * course-scoped route — Canvas then refuses a file that belongs elsewhere, which is the
 * membership check rather than something this code has to infer.
 *
 * Endpoints (Canvas `app/controllers/files_controller.rb`):
 *   GET /api/v1/courses/:course_id/files        "List files"
 *   GET /api/v1/courses/:course_id/files/:id    "Get file"
 *
 * The content itself is fetched through the `url` the File object carries. The web download
 * route `/courses/:course_id/files/:id/download` is **not** used: the physical test showed
 * that Canvas publishes scopes only for `/api/v1` and `/api/sis` routes, so no developer key
 * can be granted access to it. See `docs/architecture/ADR-002-canvas-file-access.md`.
 *
 * That URL is an ephemeral bearer credential — it carries a `verifier` that grants access to
 * the file on its own — and is treated as one throughout: never stored, never returned to a
 * browser, never logged, never placed in an error, and consumed immediately after the
 * membership, type and size checks have passed.
 */

export type FileErrorCode =
  | 'not_found'
  | 'forbidden'
  | 'not_markdown'
  | 'too_large'
  | 'unreadable'
  | 'no_download_url'
  | 'upstream_error';

export class FileError extends Error {
  override readonly name = 'FileError';

  constructor(
    readonly code: FileErrorCode,
    readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

export interface CanvasFile {
  readonly id: string;
  readonly displayName: string;
  readonly contentType: string;
  readonly size: number;
  readonly updatedAt: string | undefined;
  readonly folderId: string | undefined;
  /** Whether name and declared type are both consistent with Markdown. */
  readonly isMarkdown: boolean;
}

/**
 * A file's metadata together with the ephemeral URL Canvas issued for its content.
 *
 * Deliberately **not exported**: the URL must not reach the picker, a template, a log line
 * or a response. It exists only between the metadata call and the download.
 */
interface FileWithDownloadUrl {
  readonly file: CanvasFile;
  readonly downloadUrl: string;
}

export interface MarkdownDocument {
  readonly file: CanvasFile;
  readonly text: string;
  /** Hops the download went through, query strings removed. For diagnostics only. */
  readonly via: readonly string[];
}

export interface FilesClientOptions {
  readonly fetchOptions: Omit<SafeFetchOptions, 'originHosts' | 'redirectHosts'>;
  /** Upper bound on the Markdown this tool will fetch and render. */
  readonly maxFileBytes: number;
  /** How many pages of the file listing to walk before stopping. */
  readonly maxPages?: number;
  readonly pageSize?: number;
}

const DEFAULT_MAX_PAGES = 10;
const DEFAULT_PAGE_SIZE = 100;

/** Listing responses are JSON, and far smaller than a document. */
const LISTING_MAX_BYTES = 2_000_000;

export class CanvasFilesClient {
  constructor(private readonly options: FilesClientOptions) {}

  /**
   * Lists the course's files, marking which are Markdown.
   *
   * `content_types[]` is not used to filter: Canvas stores `.md` under several types
   * depending on the uploader's browser, so filtering server-side would silently hide
   * legitimate files. The listing is fetched whole and classified here.
   */
  async listFiles(
    platform: Platform,
    courseId: string,
    accessToken: string,
    options: { search?: string } = {},
  ): Promise<CanvasFile[]> {
    const files: CanvasFile[] = [];
    const maxPages = this.options.maxPages ?? DEFAULT_MAX_PAGES;

    let url: string | undefined = this.listingUrl(platform, courseId, options.search);

    for (let page = 0; page < maxPages && url; page += 1) {
      const response = await this.api(platform).fetch(url, {
        bearerToken: accessToken,
        readErrorBody: true,
      });

      if (response.status >= 400) throw this.statusError(response.status);

      const parsed: unknown = parseJson(response.body.toString('utf8'));
      if (!Array.isArray(parsed)) {
        throw new FileError('upstream_error', 'file listing was not an array');
      }

      for (const entry of parsed) {
        const file = toCanvasFile(entry);
        if (file) files.push(file);
      }

      url = nextPageUrl(response.headers['link'], platform);
    }

    return files;
  }

  /**
   * Fetches a file's metadata through the course-scoped route.
   *
   * Using `/courses/:course_id/files/:id` rather than `/files/:id` is deliberate: Canvas
   * itself then refuses a file that does not belong to this course, so cross-course access
   * is prevented by the platform rather than by a check this tool could get wrong.
   */
  async getFile(
    platform: Platform,
    courseId: string,
    fileId: string,
    accessToken: string,
  ): Promise<CanvasFile> {
    assertCanvasId(courseId, 'course');
    assertCanvasId(fileId, 'file');

    const url = new URL(
      `/api/v1/courses/${courseId}/files/${fileId}`,
      platform.apiBaseUrl,
    ).toString();

    const response = await this.api(platform).fetch(url, {
      bearerToken: accessToken,
      readErrorBody: true,
    });
    if (response.status >= 400) throw this.statusError(response.status);

    const raw = parseJson(response.body.toString('utf8'));
    const file = toCanvasFile(raw);
    if (!file) throw new FileError('upstream_error', 'file metadata was not an object');
    return file;
  }

  /**
   * The same course-scoped request, keeping the ephemeral download URL alongside the
   * metadata. Private, so no caller can obtain the URL for any other purpose.
   */
  private async getFileWithDownloadUrl(
    platform: Platform,
    courseId: string,
    fileId: string,
    accessToken: string,
  ): Promise<FileWithDownloadUrl> {
    assertCanvasId(courseId, 'course');
    assertCanvasId(fileId, 'file');

    const url = new URL(
      `/api/v1/courses/${courseId}/files/${fileId}`,
      platform.apiBaseUrl,
    ).toString();

    const response = await this.api(platform).fetch(url, {
      bearerToken: accessToken,
      readErrorBody: true,
    });
    if (response.status >= 400) throw this.statusError(response.status);

    const raw = parseJson(response.body.toString('utf8'));
    const file = toCanvasFile(raw);
    if (!file) throw new FileError('upstream_error', 'file metadata was not an object');

    return { file, downloadUrl: extractDownloadUrl(raw) };
  }

  /**
   * Downloads a file and returns it as text.
   *
   * Order matters and is part of the security argument:
   *
   *  1. The metadata is fetched through the **course-scoped** route, so Canvas itself
   *     refuses a file belonging to another course and a file this user may not read.
   *  2. Type and size are refused before any content is requested.
   *  3. Only then is the ephemeral URL used, and it is used once.
   *
   * No `Authorization` header is sent with the download. The URL is self-authenticating,
   * and attaching the user's token would hand it to whatever host Canvas points at.
   */
  async fetchMarkdown(
    platform: Platform,
    courseId: string,
    fileId: string,
    accessToken: string,
  ): Promise<MarkdownDocument> {
    const { file, downloadUrl } = await this.getFileWithDownloadUrl(
      platform,
      courseId,
      fileId,
      accessToken,
    );

    if (!file.isMarkdown) {
      throw new FileError('not_markdown', file.contentType || 'no declared type');
    }
    if (file.size > this.options.maxFileBytes) {
      throw new FileError('too_large', `${file.size} bytes`);
    }

    // Canvas leaves `url` empty for a file the user may not download, and a missing or
    // unusable value is reported rather than worked around: constructing a path of our own
    // would be guessing at an interface this Canvas does not offer.
    if (downloadUrl === '') {
      throw new FileError('no_download_url', 'the File object carried no usable url');
    }

    const response = await this.downloadFetcher(platform).fetch(downloadUrl, {
      // No bearer token: the URL authenticates itself, and the storage host must never see
      // the user's Canvas credential.
      readErrorBody: true,
    });
    if (response.status >= 400) throw this.statusError(response.status);

    const verdict = decodeMarkdown(response.body);
    if (!verdict.ok) throw new FileError('unreadable', verdict.reason);

    // `response.redirects` and `response.finalUrl` are already redacted by the fetcher.
    return { file, text: verdict.text, via: response.redirects };
  }

  private listingUrl(platform: Platform, courseId: string, search?: string): string {
    assertCanvasId(courseId, 'course');
    const url = new URL(`/api/v1/courses/${courseId}/files`, platform.apiBaseUrl);
    url.searchParams.set('per_page', String(this.options.pageSize ?? DEFAULT_PAGE_SIZE));
    url.searchParams.set('sort', 'updated_at');
    url.searchParams.set('order', 'desc');
    if (search && search.trim() !== '') url.searchParams.set('search_term', search.trim());
    return url.toString();
  }

  /** API calls stay on the Canvas host: no redirect off it is expected or permitted. */
  private api(platform: Platform): SafeFetcher {
    return new SafeFetcher({
      ...this.options.fetchOptions,
      originHosts: [new URL(platform.apiBaseUrl).hostname],
      maxBytes: LISTING_MAX_BYTES,
    });
  }

  /**
   * Fetcher for the content itself.
   *
   * The URL comes from Canvas, never from a user, and may already point at a separate files
   * domain — so the authorized Canvas host **and** the operator's download allowlist are
   * accepted as the initial host. Redirects beyond that are confined to the same allowlist.
   * Every other defence stays: https, per-hop address checks, connection pinning, a bounded
   * number of hops, no downgrade to http, a timeout, and a size limit applied while the
   * body streams.
   */
  private downloadFetcher(platform: Platform): SafeFetcher {
    const canvasHost = new URL(platform.apiBaseUrl).hostname;
    return new SafeFetcher({
      ...this.options.fetchOptions,
      originHosts: [canvasHost, ...platform.downloadHostAllowlist],
      redirectHosts: platform.downloadHostAllowlist,
      maxBytes: this.options.maxFileBytes,
    });
  }

  private statusError(status: number): FileError {
    if (status === 401 || status === 403) return new FileError('forbidden', `status ${status}`);
    if (status === 404) return new FileError('not_found', `status ${status}`);
    return new FileError('upstream_error', `status ${status}`);
  }
}

function assertCanvasId(value: string, what: string): void {
  if (!/^[0-9]+$/.test(value)) {
    throw new FileError('not_found', `${what} id is not a Canvas id`);
  }
}

/**
 * Reads the `url` field of a File object.
 *
 * Canvas sets it to `""` for a file the user may not download
 * (`lib/api/v1/attachment.rb`). Anything that is not a non-empty string is treated as
 * absent; an unusable value is reported by the caller rather than repaired here.
 *
 * The value is returned and never retained: it is a credential with a short life.
 */
function extractDownloadUrl(value: unknown): string {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return '';
  const url = (value as Record<string, unknown>)['url'];
  return typeof url === 'string' ? url.trim() : '';
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new FileError('upstream_error', 'response was not JSON');
  }
}

function toCanvasFile(value: unknown): CanvasFile | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const row = value as Record<string, unknown>;

  const id = row['id'];
  const displayName = row['display_name'] ?? row['filename'];
  if ((typeof id !== 'number' && typeof id !== 'string') || typeof displayName !== 'string') {
    return undefined;
  }

  const contentType = normaliseMime(
    typeof row['content-type'] === 'string'
      ? row['content-type']
      : typeof row['content_type'] === 'string'
        ? row['content_type']
        : '',
  );

  return {
    id: String(id),
    displayName,
    contentType,
    size: typeof row['size'] === 'number' ? row['size'] : 0,
    updatedAt: typeof row['updated_at'] === 'string' ? row['updated_at'] : undefined,
    folderId:
      typeof row['folder_id'] === 'number' || typeof row['folder_id'] === 'string'
        ? String(row['folder_id'])
        : undefined,
    isMarkdown: looksLikeMarkdown(displayName, contentType),
  };
}

/**
 * Follows Canvas's `Link` header pagination, and only within the Canvas host: a `next`
 * pointing somewhere else is ignored rather than followed.
 */
export function nextPageUrl(
  header: string | string[] | undefined,
  platform: Platform,
): string | undefined {
  const value = Array.isArray(header) ? header.join(',') : header;
  if (!value) return undefined;

  for (const part of value.split(',')) {
    const match = /^\s*<([^>]+)>\s*;\s*rel="?next"?/i.exec(part);
    const target = match?.[1];
    if (!target) continue;
    try {
      const url = new URL(target);
      if (url.hostname !== new URL(platform.apiBaseUrl).hostname) return undefined;
      return url.toString();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export { redactUrl };
