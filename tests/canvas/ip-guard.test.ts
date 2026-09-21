import { describe, expect, it } from 'vitest';
import {
  classifyAddress,
  hostAllowed,
  hostMatches,
  isPublicAddress,
} from '../../src/canvas/ip-guard.ts';

describe('classifyAddress — IPv4 denied ranges', () => {
  const denied = [
    ['0.0.0.0', 'this network'],
    ['10.0.0.1', 'private'],
    ['10.255.255.255', 'private'],
    ['127.0.0.1', 'loopback'],
    ['127.1.2.3', 'loopback'],
    ['169.254.169.254', 'cloud metadata endpoint'],
    ['172.16.0.1', 'private'],
    ['172.31.255.254', 'private'],
    ['192.168.1.1', 'private'],
    ['192.0.0.1', 'protocol assignments'],
    ['192.0.2.5', 'documentation'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['198.18.0.1', 'benchmarking'],
    ['198.51.100.7', 'documentation'],
    ['203.0.113.7', 'documentation'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.250', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'broadcast'],
  ] as const;

  for (const [address, why] of denied) {
    it(`refuses ${address} (${why})`, () => {
      expect(isPublicAddress(address)).toBe(false);
    });
  }
});

describe('classifyAddress — IPv4 allowed', () => {
  for (const address of ['1.1.1.1', '8.8.8.8', '172.15.255.255', '172.32.0.1', '192.167.0.1']) {
    it(`allows ${address}`, () => {
      expect(isPublicAddress(address)).toBe(true);
    });
  }
});

describe('classifyAddress — IPv6', () => {
  const denied = [
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fc00::1', 'unique local'],
    ['fd12:3456::1', 'unique local'],
    ['fe80::1', 'link-local'],
    ['ff02::1', 'multicast'],
    ['2001:db8::1', 'documentation'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['::ffff:169.254.169.254', 'IPv4-mapped metadata endpoint'],
    ['::ffff:10.0.0.1', 'IPv4-mapped private'],
  ] as const;

  for (const [address, why] of denied) {
    it(`refuses ${address} (${why})`, () => {
      expect(isPublicAddress(address)).toBe(false);
    });
  }

  it('allows a routable IPv6 address', () => {
    expect(isPublicAddress('2606:4700:4700::1111')).toBe(true);
  });

  it('refuses something that is not an IP address at all', () => {
    expect(isPublicAddress('canvas.example.edu')).toBe(false);
    expect(classifyAddress('not-an-ip')).toMatchObject({ allowed: false });
  });
});

describe('hostMatches', () => {
  it('matches an exact host, ignoring case and a trailing dot', () => {
    expect(hostMatches('canvas.example.edu', 'canvas.example.edu')).toBe(true);
    expect(hostMatches('CANVAS.example.edu', 'canvas.example.edu')).toBe(true);
    expect(hostMatches('canvas.example.edu.', 'canvas.example.edu')).toBe(true);
  });

  it('does not match a different host', () => {
    expect(hostMatches('evil.example', 'canvas.example.edu')).toBe(false);
  });

  it('is not fooled by a suffix that is not a label boundary', () => {
    expect(hostMatches('evilcanvas.example.edu', 'canvas.example.edu')).toBe(false);
    expect(hostMatches('canvas.example.edu.evil.test', 'canvas.example.edu')).toBe(false);
  });

  it('matches subdomains under a wildcard', () => {
    expect(hostMatches('files.example.edu', '*.example.edu')).toBe(true);
    expect(hostMatches('a.b.example.edu', '*.example.edu')).toBe(true);
  });

  it('does not let a wildcard match the bare domain', () => {
    expect(hostMatches('example.edu', '*.example.edu')).toBe(false);
  });

  it('does not let a wildcard escape its parent', () => {
    expect(hostMatches('example.edu.evil.test', '*.example.edu')).toBe(false);
  });
});

describe('hostAllowed', () => {
  it('accepts a host present on the allowlist', () => {
    expect(hostAllowed('files.example.edu', ['canvas.example.edu', '*.example.edu'])).toBe(true);
  });

  it('refuses everything when the allowlist is empty', () => {
    expect(hostAllowed('canvas.example.edu', [])).toBe(false);
  });
});
