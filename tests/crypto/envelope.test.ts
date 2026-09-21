import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  KeyRing,
  open,
  rewrap,
  safeEquals,
  seal,
  sealedKeyVersion,
  type SecretBinding,
} from '../../src/crypto/envelope.ts';

const BINDING: SecretBinding = {
  issuer: 'https://canvas.test.edu',
  deploymentId: '1:deployment-abc',
  subject: 'lti-user-subject-1',
};

const SECRET = 'refresh-token-value-that-must-never-leak';

function ring(...versions: string[]): KeyRing {
  const entries = (versions.length > 0 ? versions : ['1']).map((version) => ({
    version,
    key: randomBytes(32),
  }));
  return new KeyRing(entries);
}

describe('KeyRing', () => {
  it('refuses a key that is not 32 bytes', () => {
    expect(() => new KeyRing([{ version: '1', key: randomBytes(16) }])).toThrow(/32 bytes/);
  });

  it('refuses an empty ring', () => {
    expect(() => new KeyRing([])).toThrow(/at least one key/);
  });

  it('refuses duplicate versions', () => {
    expect(
      () =>
        new KeyRing([
          { version: '1', key: randomBytes(32) },
          { version: '1', key: randomBytes(32) },
        ]),
    ).toThrow(/duplicate key version/);
  });

  it('defaults the active key to the last entry', () => {
    expect(ring('1', '2').activeVersion).toBe('2');
  });

  it('honours an explicit active version', () => {
    const keys = [
      { version: '1', key: randomBytes(32) },
      { version: '2', key: randomBytes(32) },
    ];
    expect(new KeyRing(keys, '1').activeVersion).toBe('1');
  });

  it('refuses an active version that is not in the ring', () => {
    expect(() => new KeyRing([{ version: '1', key: randomBytes(32) }], '9')).toThrow(
      /not in the key ring/,
    );
  });
});

describe('seal and open', () => {
  it('round-trips a secret', () => {
    const keyRing = ring();
    expect(open(seal(SECRET, BINDING, keyRing), BINDING, keyRing)).toBe(SECRET);
  });

  it('round-trips unicode and an empty string', () => {
    const keyRing = ring();
    for (const value of ['ñandú — 日本語 🙂', '']) {
      expect(open(seal(value, BINDING, keyRing), BINDING, keyRing)).toBe(value);
    }
  });

  it('never repeats a ciphertext for the same input', () => {
    const keyRing = ring();
    const a = seal(SECRET, BINDING, keyRing);
    const b = seal(SECRET, BINDING, keyRing);
    expect(a).not.toBe(b);
    expect(open(a, BINDING, keyRing)).toBe(open(b, BINDING, keyRing));
  });

  it('uses a fresh IV every time', () => {
    const keyRing = ring();
    const ivs = new Set(
      Array.from({ length: 50 }, () => seal(SECRET, BINDING, keyRing).split('.')[2]),
    );
    expect(ivs.size).toBe(50);
  });

  it('does not leave the plaintext visible in the sealed value', () => {
    const sealed = seal(SECRET, BINDING, ring());
    expect(sealed).not.toContain(SECRET);
    expect(Buffer.from(sealed).toString('utf8')).not.toContain('refresh-token');
  });

  it('records the key version it used', () => {
    const keyRing = ring('7');
    expect(sealedKeyVersion(seal(SECRET, BINDING, keyRing))).toBe('7');
  });
});

describe('open — tampering', () => {
  it('refuses an edited ciphertext', () => {
    const keyRing = ring();
    const parts = seal(SECRET, BINDING, keyRing).split('.');
    const ciphertext = Buffer.from(parts[4]!, 'base64url');
    ciphertext.writeUInt8(ciphertext.readUInt8(0) ^ 0x01, 0);
    parts[4] = ciphertext.toString('base64url');

    expect(() => open(parts.join('.'), BINDING, keyRing)).toThrow(DecryptionError);
    expect(() => open(parts.join('.'), BINDING, keyRing)).toThrow(/authentication_failed/);
  });

  it('refuses an edited authentication tag', () => {
    const keyRing = ring();
    const parts = seal(SECRET, BINDING, keyRing).split('.');
    const tag = Buffer.from(parts[3]!, 'base64url');
    tag.writeUInt8(tag.readUInt8(0) ^ 0x01, 0);
    parts[3] = tag.toString('base64url');

    expect(() => open(parts.join('.'), BINDING, keyRing)).toThrow(/authentication_failed/);
  });

  it('refuses a substituted IV', () => {
    const keyRing = ring();
    const parts: string[] = seal(SECRET, BINDING, keyRing).split('.');
    parts[2] = randomBytes(12).toString('base64url');

    expect(() => open(parts.join('.'), BINDING, keyRing)).toThrow(/authentication_failed/);
  });

  it('refuses an IV of the wrong length', () => {
    const keyRing = ring();
    const parts: string[] = seal(SECRET, BINDING, keyRing).split('.');
    parts[2] = randomBytes(8).toString('base64url');

    expect(() => open(parts.join('.'), BINDING, keyRing)).toThrow(/malformed/);
  });

  it('refuses a value with the wrong number of segments', () => {
    expect(() => open('v1.1.aaa', BINDING, ring())).toThrow(/malformed/);
  });

  it('refuses an unknown envelope format', () => {
    const parts = seal(SECRET, BINDING, ring()).split('.');
    parts[0] = 'v9';
    expect(() => open(parts.join('.'), BINDING, ring())).toThrow(/malformed/);
  });
});

describe('open — wrong key', () => {
  it('refuses a ciphertext sealed under a different key of the same version', () => {
    const sealed = seal(SECRET, BINDING, ring('1'));
    const otherRing = ring('1');
    expect(() => open(sealed, BINDING, otherRing)).toThrow(/authentication_failed/);
  });

  it('reports a key version the ring does not hold', () => {
    const sealed = seal(SECRET, BINDING, ring('2'));
    expect(() => open(sealed, BINDING, ring('1'))).toThrow(/unknown_key_version/);
  });
});

describe('open — binding', () => {
  it('refuses a ciphertext moved to another user', () => {
    const keyRing = ring();
    const sealed = seal(SECRET, BINDING, keyRing);

    expect(() => open(sealed, { ...BINDING, subject: 'somebody-else' }, keyRing)).toThrow(
      /authentication_failed/,
    );
  });

  it('refuses a ciphertext moved to another deployment', () => {
    const keyRing = ring();
    const sealed = seal(SECRET, BINDING, keyRing);

    expect(() => open(sealed, { ...BINDING, deploymentId: '2:elsewhere' }, keyRing)).toThrow(
      /authentication_failed/,
    );
  });

  it('refuses a ciphertext moved to another issuer', () => {
    const keyRing = ring();
    const sealed = seal(SECRET, BINDING, keyRing);

    expect(() => open(sealed, { ...BINDING, issuer: 'https://evil.example' }, keyRing)).toThrow(
      /authentication_failed/,
    );
  });

  it('cannot be fooled by shifting a separator between binding fields', () => {
    const keyRing = ring();
    const sealed = seal(SECRET, { issuer: 'a', deploymentId: 'b', subject: 'c' }, keyRing);

    expect(() =>
      open(sealed, { issuer: 'a\u0000b', deploymentId: '', subject: 'c' }, keyRing),
    ).toThrow(/authentication_failed/);
  });
});

describe('rotation', () => {
  it('still opens a value sealed under an older key', () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };

    const sealedOld = seal(SECRET, BINDING, new KeyRing([oldKey]));
    const rotated = new KeyRing([oldKey, newKey], '2');

    expect(open(sealedOld, BINDING, rotated)).toBe(SECRET);
  });

  it('seals new values under the active key', () => {
    const rotated = new KeyRing(
      [
        { version: '1', key: randomBytes(32) },
        { version: '2', key: randomBytes(32) },
      ],
      '2',
    );
    expect(sealedKeyVersion(seal(SECRET, BINDING, rotated))).toBe('2');
  });

  it('re-wraps a stale value under the active key, preserving the plaintext', () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const sealedOld = seal(SECRET, BINDING, new KeyRing([oldKey]));
    const rotated = new KeyRing([oldKey, newKey], '2');

    const rewrapped = rewrap(sealedOld, BINDING, rotated);

    expect(rewrapped).toBeDefined();
    expect(sealedKeyVersion(rewrapped!)).toBe('2');
    expect(open(rewrapped!, BINDING, rotated)).toBe(SECRET);
  });

  it('does not re-wrap a value that is already current', () => {
    const keyRing = ring('1');
    expect(rewrap(seal(SECRET, BINDING, keyRing), BINDING, keyRing)).toBeUndefined();
  });

  it('makes old ciphertexts unreadable once the old key is dropped', () => {
    const oldKey = { version: '1', key: randomBytes(32) };
    const newKey = { version: '2', key: randomBytes(32) };
    const sealedOld = seal(SECRET, BINDING, new KeyRing([oldKey]));

    expect(() => open(sealedOld, BINDING, new KeyRing([newKey]))).toThrow(/unknown_key_version/);
  });
});

describe('safeEquals', () => {
  it('matches identical strings', () => {
    expect(safeEquals('abc123', 'abc123')).toBe(true);
  });

  it('rejects different strings of the same length', () => {
    expect(safeEquals('abc123', 'abc124')).toBe(false);
  });

  it('rejects strings of different lengths without throwing', () => {
    expect(safeEquals('abc', 'abcdef')).toBe(false);
  });
});
