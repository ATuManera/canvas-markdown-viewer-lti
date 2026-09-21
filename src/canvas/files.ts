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
 *   GET /courses/:course_id/files/:id/download  "Download file"
 */

export type FileErrorCode =
  'not_found' | 'forbidden' | 'not_markdown' | 'too_large' | 'unreadable' | 'upstream_error';

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

    const file = toCanvasFile(parseJson(response.body.toString('utf8')));
    if (!file) throw new FileError('upstream_error', 'file metadata was not an object');
    return file;
  }

  /**
   * Downloads a file and returns it as text.
   *
   * The metadata is fetched first, so the size and type can be refused before a single byte
   * of content is requested, and so the file's membership of the course is confirmed.
   */
  async fetchMarkdown(
    platform: Platform,
    courseId: string,
    fileId: string,
    accessToken: string,
  ): Promise<MarkdownDocument> {
    const file = await this.getFile(platform, courseId, fileId, accessToken);

    if (!file.isMarkdown) {
      throw new FileError('not_markdown', file.contentType || 'no declared type');
    }
    if (file.size > this.options.maxFileBytes) {
      throw new FileError('too_large', `${file.size} bytes`);
    }

    // The course-scoped download route, with the user's token. The File object's `url`
    // field is deliberately not used: it carries a `verifier` that grants access without
    // authentication, and this tool never holds such a URL. See ADR-002 §9.6.
    const url = new URL(
      `/courses/${courseId}/files/${fileId}/download?download_frd=1`,
      platform.apiBaseUrl,
    ).toString();

    const response = await this.download(platform).fetch(url, {
      bearerToken: accessToken,
      readErrorBody: true,
    });
    if (response.status >= 400) throw this.statusError(response.status);

    const verdict = decodeMarkdown(response.body);
    if (!verdict.ok) throw new FileError('unreadable', verdict.reason);

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
   * Downloads may legitimately redirect to a files domain or to object storage, so those
   * hosts are allowed as redirect targets only. The bearer credential is dropped by the
   * fetcher the moment the origin changes.
   */
  private download(platform: Platform): SafeFetcher {
    return new SafeFetcher({
      ...this.options.fetchOptions,
      originHosts: [new URL(platform.apiBaseUrl).hostname],
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
