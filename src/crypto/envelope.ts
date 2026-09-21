import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Authenticated encryption for the refresh tokens held in PostgreSQL.
 *
 * AES-256-GCM through Node's own `crypto`, which is OpenSSL underneath: no cryptography is
 * implemented here, only the envelope around it.
 *
 * Three properties matter beyond confidentiality:
 *
 *  1. **Authentication.** GCM's tag is verified on every decryption, so a ciphertext edited
 *     in the database fails to open rather than yielding altered plaintext.
 *  2. **Binding.** The owner of the secret — issuer, deployment and subject — is fed in as
 *     additional authenticated data. A row copied onto another user's record will not
 *     decrypt, so the association is enforced by the cipher and not only by a foreign key.
 *  3. **Rotation.** Every ciphertext names the key version that produced it, so a new key
 *     can be introduced while old rows stay readable, and rows can be re-wrapped lazily.
 *
 * The key is 32 random bytes supplied by the operator. It is never derived from a
 * passphrase: a human-chosen string would not have 256 bits of entropy.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12; // 96 bits, the size GCM is specified for
const TAG_BYTES = 16;
const FORMAT_VERSION = 'v1';

export class DecryptionError extends Error {
  override readonly name = 'DecryptionError';

  constructor(
    readonly reason:
      'malformed' | 'unknown_key_version' | 'authentication_failed' | 'binding_mismatch',
    detail?: string,
  ) {
    super(detail ? `${reason}: ${detail}` : reason);
  }
}

export interface KeyRingEntry {
  /** Operator-chosen label, e.g. `1`, `2024-06`. Stored in the ciphertext. */
  readonly version: string;
  readonly key: Buffer;
}

/**
 * The set of keys this process can decrypt with, and the one it encrypts with.
 * Rotation is therefore: add a key, make it active, re-wrap at leisure, drop the old key.
 */
export class KeyRing {
  readonly #keys = new Map<string, Buffer>();
  readonly #activeVersion: string;

  constructor(entries: readonly KeyRingEntry[], activeVersion?: string) {
    if (entries.length === 0) throw new Error('key ring must hold at least one key');
    for (const entry of entries) {
      if (entry.key.length !== 32) {
        throw new Error(`key "${entry.version}" must be 32 bytes, got ${entry.key.length}`);
      }
      if (this.#keys.has(entry.version)) {
        throw new Error(`duplicate key version "${entry.version}"`);
      }
      this.#keys.set(entry.version, entry.key);
    }

    const last = entries[entries.length - 1];
    const active = activeVersion ?? last?.version;
    if (active === undefined || !this.#keys.has(active)) {
      throw new Error(`active key version "${active ?? '(none)'}" is not in the key ring`);
    }
    this.#activeVersion = active;
  }

  get activeVersion(): string {
    return this.#activeVersion;
  }

  get versions(): readonly string[] {
    return [...this.#keys.keys()];
  }

  active(): { version: string; key: Buffer } {
    const key = this.#keys.get(this.#activeVersion);
    // The constructor rejects an active version outside the ring, so this cannot happen.
    if (!key) throw new Error('key ring is inconsistent');
    return { version: this.#activeVersion, key };
  }

  get(version: string): Buffer | undefined {
    return this.#keys.get(version);
  }
}

/**
 * Identifies whose secret this is. Fed to the cipher as additional authenticated data, so
 * that a ciphertext is only openable in the context it was sealed for.
 */
export interface SecretBinding {
  readonly issuer: string;
  readonly deploymentId: string;
  readonly subject: string;
}

function bindingBytes(binding: SecretBinding): Buffer {
  // NUL-separated: none of the three fields may contain a NUL byte, so the encoding is
  // unambiguous and one field cannot be shifted into another.
  return Buffer.from(
    `${FORMAT_VERSION}\u0000${binding.issuer}\u0000${binding.deploymentId}\u0000${binding.subject}`,
    'utf8',
  );
}

/**
 * Seals `plaintext`, returning `v1.<keyVersion>.<iv>.<tag>.<ciphertext>` in base64url.
 * A fresh random IV is generated for every call; GCM's security collapses if one repeats
 * under the same key.
 */
export function seal(plaintext: string, binding: SecretBinding, keyRing: KeyRing): string {
  const { version, key } = keyRing.active();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(bindingBytes(binding));

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    FORMAT_VERSION,
    version,
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

/** Opens a sealed value, or throws {@link DecryptionError}. Never returns partial output. */
export function open(sealed: string, binding: SecretBinding, keyRing: KeyRing): string {
  const parts = sealed.split('.');
  if (parts.length !== 5) {
    throw new DecryptionError('malformed', `expected 5 segments, got ${parts.length}`);
  }
  const [format, keyVersion, ivPart, tagPart, ciphertextPart] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];
  if (format !== FORMAT_VERSION) {
    throw new DecryptionError('malformed', `unknown envelope format "${format}"`);
  }

  const key = keyRing.get(keyVersion);
  if (!key) {
    throw new DecryptionError('unknown_key_version', keyVersion);
  }

  const iv = Buffer.from(ivPart, 'base64url');
  const tag = Buffer.from(tagPart, 'base64url');
  const ciphertext = Buffer.from(ciphertextPart, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new DecryptionError('malformed', 'iv or tag has the wrong length');
  }

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(bindingBytes(binding));
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    // GCM cannot distinguish "edited ciphertext" from "wrong key" from "wrong binding":
    // all three fail the same tag check. The caller gets one reason, deliberately.
    throw new DecryptionError('authentication_failed');
  }
}

/** The key version a sealed value was produced with, for deciding whether to re-wrap. */
export function sealedKeyVersion(sealed: string): string | undefined {
  const parts = sealed.split('.');
  return parts.length === 5 && parts[0] === FORMAT_VERSION ? parts[1] : undefined;
}

/** Re-seals under the active key. Returns undefined when the value is already current. */
export function rewrap(
  sealed: string,
  binding: SecretBinding,
  keyRing: KeyRing,
): string | undefined {
  if (sealedKeyVersion(sealed) === keyRing.activeVersion) return undefined;
  return seal(open(sealed, binding, keyRing), binding, keyRing);
}

/** Constant-time comparison, for opaque tokens that are compared rather than decrypted. */
export function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
