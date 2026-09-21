import { isIP } from 'node:net';

/**
 * Address classification for SSRF defence.
 *
 * A Canvas download can redirect to a files domain or to object storage, so the tool has to
 * follow redirects. Following them blindly would let anyone who can influence a redirect
 * target reach the private network the tool runs in — including cloud metadata endpoints.
 * Every hop is therefore resolved and every resolved address checked here.
 *
 * Ranges follow IANA's IPv4 and IPv6 special-purpose address registries.
 */

export type AddressVerdict =
  { readonly allowed: true } | { readonly allowed: false; readonly reason: string };

const ALLOWED: AddressVerdict = { allowed: true };

function denied(reason: string): AddressVerdict {
  return { allowed: false, reason };
}

/** Parses dotted-quad IPv4 into its four octets. Returns undefined if not IPv4. */
function ipv4Octets(address: string): [number, number, number, number] | undefined {
  if (isIP(address) !== 4) return undefined;
  const parts = address.split('.').map(Number);
  const [a, b, c, d] = parts;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return undefined;
  return [a, b, c, d];
}

function checkIpv4(address: string): AddressVerdict {
  const octets = ipv4Octets(address);
  if (!octets) return denied('not a valid IPv4 address');
  const [a, b, c, d] = octets;

  if (a === 0) return denied('"this network" (0.0.0.0/8)');
  if (a === 10) return denied('private (10.0.0.0/8)');
  if (a === 127) return denied('loopback (127.0.0.0/8)');
  if (a === 169 && b === 254) return denied('link-local (169.254.0.0/16)');
  if (a === 172 && b >= 16 && b <= 31) return denied('private (172.16.0.0/12)');
  if (a === 192 && b === 0 && c === 0) return denied('IETF protocol assignments (192.0.0.0/24)');
  if (a === 192 && b === 0 && c === 2) return denied('documentation (192.0.2.0/24)');
  if (a === 192 && b === 168) return denied('private (192.168.0.0/16)');
  if (a === 100 && b >= 64 && b <= 127) return denied('carrier-grade NAT (100.64.0.0/10)');
  if (a === 198 && (b === 18 || b === 19)) return denied('benchmarking (198.18.0.0/15)');
  if (a === 198 && b === 51 && c === 100) return denied('documentation (198.51.100.0/24)');
  if (a === 203 && b === 0 && c === 113) return denied('documentation (203.0.113.0/24)');
  if (a >= 224 && a <= 239) return denied('multicast (224.0.0.0/4)');
  if (a >= 240) return denied('reserved (240.0.0.0/4)');
  if (a === 255 && b === 255 && c === 255 && d === 255) return denied('broadcast');

  return ALLOWED;
}

/** Expands an IPv6 address to its eight 16-bit groups. */
function ipv6Groups(address: string): number[] | undefined {
  if (isIP(address) !== 6) return undefined;
  const zoneless = address.split('%')[0] ?? address;

  // An IPv4-mapped or IPv4-compatible tail is handled by the caller.
  const [head, tail] = zoneless.split('::');
  const parse = (part: string | undefined): number[] =>
    part && part.length > 0 ? part.split(':').map((g) => parseInt(g, 16)) : [];

  const left = parse(head);
  if (tail === undefined) return left.length === 8 ? left : undefined;
  const right = parse(tail);
  const fill = 8 - left.length - right.length;
  if (fill < 0) return undefined;
  return [...left, ...Array<number>(fill).fill(0), ...right];
}

/** Pulls the embedded IPv4 out of `::ffff:a.b.c.d` and `::ffff:7f00:1` style addresses. */
function embeddedIpv4(address: string): string | undefined {
  const zoneless = (address.split('%')[0] ?? address).toLowerCase();
  const dotted = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(zoneless);
  if (dotted?.[1] && (zoneless.startsWith('::ffff:') || zoneless.startsWith('::'))) {
    return dotted[1];
  }
  const groups = ipv6Groups(address);
  if (!groups) return undefined;
  const isMapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
  const isCompatible = groups.slice(0, 6).every((g) => g === 0);
  if (!isMapped && !isCompatible) return undefined;
  const high = groups[6];
  const low = groups[7];
  if (high === undefined || low === undefined) return undefined;
  if (isCompatible && high === 0 && low <= 1) return undefined; // :: and ::1 handled elsewhere
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function checkIpv6(address: string): AddressVerdict {
  const groups = ipv6Groups(address);
  if (!groups) return denied('not a valid IPv6 address');

  const mapped = embeddedIpv4(address);
  if (mapped) {
    const verdict = checkIpv4(mapped);
    return verdict.allowed ? verdict : denied(`IPv4-mapped ${verdict.reason}`);
  }

  if (groups.every((g) => g === 0)) return denied('unspecified (::)');
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return denied('loopback (::1)');

  const first = groups[0] ?? 0;
  if ((first & 0xfe00) === 0xfc00) return denied('unique local (fc00::/7)');
  if ((first & 0xffc0) === 0xfe80) return denied('link-local (fe80::/10)');
  if ((first & 0xff00) === 0xff00) return denied('multicast (ff00::/8)');
  if (first === 0x0100 && groups[1] === 0) return denied('discard-only (100::/64)');
  if (first === 0x2001 && (groups[1] ?? 0) <= 0x01ff) return denied('IETF protocol assignments');
  if (first === 0x2001 && groups[1] === 0x0db8) return denied('documentation (2001:db8::/32)');

  return ALLOWED;
}

/**
 * Decides whether a literal IP address may be connected to.
 *
 * Note that a public address is not automatically safe: the host allowlist is the other
 * half of the check, and both must pass.
 */
export function classifyAddress(address: string): AddressVerdict {
  const family = isIP(address);
  if (family === 4) return checkIpv4(address);
  if (family === 6) return checkIpv6(address);
  return denied('not an IP address');
}

export function isPublicAddress(address: string): boolean {
  return classifyAddress(address).allowed;
}

/**
 * Matches a hostname against an allowlist entry. An entry may be an exact hostname or a
 * `*.example.edu` wildcard, which matches one or more leading labels but never the bare
 * domain — a wildcard is a delegation, not a shorthand for "and also the parent".
 */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // keeps the leading dot
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

export function hostAllowed(host: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => hostMatches(host, pattern));
}
