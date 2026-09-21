import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';
import { promisify } from 'node:util';
import { classifyAddress, hostAllowed } from './ip-guard.ts';

/**
 * HTTP client hardened for fetching Canvas files.
 *
 * Canvas answers a download in one of three ways (`app/helpers/attachment_helper.rb`,
 * `render_or_redirect_to_stored_file`): 200 with the body, 302 to a separate files domain,
 * or 302 to external object storage. The tool must follow redirects, so every hop is
 * validated independently:
 *
 *  - the scheme must be https (http only where explicitly permitted, for local development);
 *  - the host must be on the allowlist;
 *  - every address the host resolves to must be publicly routable;
 *  - the socket is pinned to an address that was checked, closing the DNS-rebinding window
 *    between validation and connection;
 *  - credentials embedded in the URL are refused;
 *  - the body size limit is applied while the response streams, not after.
 *
 * `node:https` is used rather than `fetch` because only the former lets us supply the
 * `lookup` function that pins the connection.
 */

const resolveHost = promisify(dnsLookup);

export type FetchDenialReason =
  | 'insecure_scheme'
  | 'host_not_allowed'
  | 'private_address'
  | 'dns_failure'
  | 'credentials_in_url'
  | 'too_many_redirects'
  | 'redirect_without_location'
  | 'response_too_large'
  | 'timeout'
  | 'network_error'
  | 'http_error';

export class FetchDenied extends Error {
  override readonly name = 'FetchDenied';

  constructor(
    readonly reason: FetchDenialReason,
    /** Operator-facing detail. Never shown to a user. */
    readonly detail: string,
    readonly status?: number,
  ) {
    super(`${reason}: ${detail}`);
  }
}

export interface SafeFetchOptions {
  /** Hostnames, optionally `*.`-prefixed, that may be contacted. */
  readonly allowedHosts: readonly string[];
  readonly maxRedirects: number;
  readonly timeoutMs: number;
  readonly maxBytes: number;
  /**
   * Permits plain http. Off in production; used by local development against a Canvas
   * running on http, and by tests that need a real server without TLS.
   */
  readonly allowInsecureScheme?: boolean;
  /**
   * Permits non-routable destinations. Off in production. Kept separate from
   * {@link allowInsecureScheme} so a test can use http and still prove that private
   * addresses are refused.
   */
  readonly allowPrivateAddresses?: boolean;
}

export interface SafeResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Buffer;
  /** The URL the body was finally read from, after any redirects. */
  readonly finalUrl: string;
  readonly redirects: readonly string[];
}

export interface SafeRequestInit {
  readonly headers?: Readonly<Record<string, string>>;
  readonly method?: 'GET' | 'HEAD';
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export class SafeFetcher {
  constructor(private readonly options: SafeFetchOptions) {}

  async fetch(url: string, init: SafeRequestInit = {}): Promise<SafeResponse> {
    const redirects: string[] = [];
    let current = url;

    for (let hop = 0; hop <= this.options.maxRedirects; hop += 1) {
      const target = this.validateUrl(current);
      const addresses = await this.resolveAndCheck(target.hostname);
      const response = await this.send(target, addresses, init);

      const location = response.headers.location;
      if (REDIRECT_STATUSES.has(response.statusCode ?? 0)) {
        response.resume(); // discard the redirect body
        if (!location) {
          throw new FetchDenied(
            'redirect_without_location',
            `status ${response.statusCode ?? 0} carried no Location`,
          );
        }
        redirects.push(current);
        current = new URL(location, target).toString();
        continue;
      }

      const status = response.statusCode ?? 0;
      if (status >= 400) {
        response.resume();
        throw new FetchDenied('http_error', `upstream responded ${status}`, status);
      }

      const body = await this.readBounded(response);
      return {
        status,
        headers: response.headers,
        body,
        finalUrl: target.toString(),
        redirects,
      };
    }

    throw new FetchDenied('too_many_redirects', `exceeded ${this.options.maxRedirects} redirects`);
  }

  private validateUrl(raw: string): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new FetchDenied('network_error', 'malformed URL');
    }

    if (url.username !== '' || url.password !== '') {
      throw new FetchDenied('credentials_in_url', 'URL carries embedded credentials');
    }

    const httpsOnly = !this.options.allowInsecureScheme;
    if (url.protocol !== 'https:' && (httpsOnly || url.protocol !== 'http:')) {
      throw new FetchDenied('insecure_scheme', `scheme ${url.protocol} is not permitted`);
    }

    if (!hostAllowed(url.hostname, this.options.allowedHosts)) {
      throw new FetchDenied('host_not_allowed', `host ${url.hostname} is not on the allowlist`);
    }

    return url;
  }

  private async resolveAndCheck(hostname: string): Promise<LookupAddress[]> {
    let addresses: LookupAddress[];
    try {
      addresses = await resolveHost(hostname, { all: true });
    } catch {
      throw new FetchDenied('dns_failure', `could not resolve ${hostname}`);
    }
    if (addresses.length === 0) {
      throw new FetchDenied('dns_failure', `${hostname} resolved to no addresses`);
    }

    // Every answer must be acceptable. Allowing the connection because *one* address is
    // public would let a host that also resolves to a private address win the race.
    for (const entry of addresses) {
      const verdict = classifyAddress(entry.address);
      if (!verdict.allowed && !this.options.allowPrivateAddresses) {
        throw new FetchDenied(
          'private_address',
          `${hostname} resolves to a non-routable address: ${verdict.reason}`,
        );
      }
    }

    return addresses;
  }

  private send(
    url: URL,
    addresses: readonly LookupAddress[],
    init: SafeRequestInit,
  ): Promise<IncomingMessage> {
    const send = url.protocol === 'https:' ? httpsRequest : httpRequest;

    return new Promise<IncomingMessage>((resolve, reject) => {
      const req = send(
        url,
        {
          method: init.method ?? 'GET',
          headers: { ...init.headers, host: url.host },
          // The socket connects only to addresses that were just validated, so a second
          // DNS answer cannot be substituted between the check and the connection.
          // `net` asks for either one address or the whole list, depending on `opts.all`.
          lookup: pinnedLookup(addresses),
          servername: url.hostname,
          timeout: this.options.timeoutMs,
        },
        resolve,
      );

      req.on('timeout', () => {
        req.destroy(new FetchDenied('timeout', `no response within ${this.options.timeoutMs}ms`));
      });
      req.on('error', (error: unknown) => {
        reject(
          error instanceof FetchDenied
            ? error
            : new FetchDenied('network_error', describeError(error)),
        );
      });
      req.end();
    });
  }

  /**
   * Reads the body, aborting as soon as the limit is passed. Content-Length is only a hint:
   * a hostile or misconfigured server can understate it, so the running total decides.
   */
  private readBounded(response: IncomingMessage): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const declared = Number(response.headers['content-length'] ?? Number.NaN);
      if (Number.isFinite(declared) && declared > this.options.maxBytes) {
        response.destroy();
        reject(
          new FetchDenied(
            'response_too_large',
            `declared ${declared} bytes, limit is ${this.options.maxBytes}`,
          ),
        );
        return;
      }

      const chunks: Buffer[] = [];
      let total = 0;

      response.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > this.options.maxBytes) {
          response.destroy();
          reject(
            new FetchDenied('response_too_large', `body exceeded ${this.options.maxBytes} bytes`),
          );
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', (error: unknown) => {
        reject(new FetchDenied('network_error', describeError(error)));
      });
      response.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
    });
  }
}

/**
 * Builds the `lookup` implementation handed to `net`. It ignores DNS entirely and returns
 * the addresses this request already validated.
 */
function pinnedLookup(addresses: readonly LookupAddress[]): LookupFunction {
  const [first] = addresses;
  if (!first) throw new FetchDenied('dns_failure', 'no validated address to connect to');
  return ((_hostname: string, options: { all?: boolean }, callback: unknown) => {
    if (options.all === true) {
      (callback as (err: null, result: LookupAddress[]) => void)(null, [...addresses]);
      return;
    }
    (callback as (err: null, address: string, family: number) => void)(
      null,
      first.address,
      first.family,
    );
  }) as unknown as LookupFunction;
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : error.message;
  }
  return 'unknown error';
}
