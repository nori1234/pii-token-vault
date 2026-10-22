// 鍵を使う暗号の処理のすべて。keysvc で node:crypto を import するのは、このファイルだけ（不変条件9、ADR 0012）。
// 使う方式は許可リストのものだけ：保存は AES-256-GCM（IV は96ビットの乱数）、MAC は HMAC-SHA-256、署名は ES256。

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  sign,
} from 'node:crypto';

export const AES_KEY_BYTES = 32;
export const GCM_IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;
export const HMAC_BYTES = 32;
export const ES256_SIGNATURE_BYTES = 64;

/** 復号の失敗。理由（鍵、IV、タグ、AAD、本文）を区別しない。 */
export class CryptoOpenError extends Error {
  constructor() {
    super('復号できなかった');
    this.name = 'CryptoOpenError';
  }
}

function assertLength(bytes: Uint8Array, length: number): void {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
    throw new RangeError('長さが違う');
  }
}

export function newSymmetricKey(): Uint8Array {
  return new Uint8Array(randomBytes(AES_KEY_BYTES));
}

export function randomId(bytes: number): Uint8Array {
  return new Uint8Array(randomBytes(bytes));
}

/** IV は中で毎回 randomBytes(12) で作る。呼び出し側は IV を渡せない。 */
export function aes256GcmSeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
  assertLength(key, AES_KEY_BYTES);
  const iv = new Uint8Array(randomBytes(GCM_IV_BYTES));
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
  cipher.setAAD(aad);
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
  const tag = new Uint8Array(cipher.getAuthTag());
  return { iv, ciphertext, tag };
}

/** タグは16バイトだけを受け付ける（短いタグによる偽造を防ぐ）。 */
export function aes256GcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  try {
    assertLength(key, AES_KEY_BYTES);
    assertLength(iv, GCM_IV_BYTES);
    assertLength(tag, GCM_TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    throw new CryptoOpenError();
  }
}

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.byteLength < HMAC_BYTES) {
    throw new RangeError('長さが違う');
  }
  return new Uint8Array(createHmac('sha256', key).update(message).digest());
}

export interface Es256KeyPair {
  readonly privateKey: KeyObject;
  readonly publicJwk: { readonly x: string; readonly y: string };
}

export function generateEs256KeyPair(): Es256KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('公開鍵を書き出せなかった');
  }
  return { privateKey, publicJwk: { x: jwk.x, y: jwk.y } };
}

/** JWS の ES256 の形（r‖s の64バイト）で署名する。 */
export function signEs256(privateKey: KeyObject, message: Uint8Array): Uint8Array {
  return new Uint8Array(sign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
}
