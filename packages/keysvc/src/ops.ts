// 操作の本体（ADR 0012）。権限の検査（acl.ts）を通った後に呼ぶ。入力の形を厳しく確かめ、値を例外に入れない。
//
// 暗号文の形：0x01（形式の版）‖ 鍵の番号（1バイト）‖ 鍵の版（u32 BE）‖ IV（12）‖ 暗号文 ‖ タグ（16）。
// AAD は「頭の6バイト ‖ lengthPrefixed(キーで並べた [キー, 値, キー, 値, …])」。暗号文は文脈（利用者 ID など）に
// 結び付くので、DB の行を入れ替えても、別の利用者の文脈では復号できない。

import {
  concatBytes,
  fromBase64Url,
  isUuid,
  lengthPrefixed,
  toBase32Lower,
  toBase64Url,
  u32be,
  uuidBytes,
} from '@pii-token-vault/warifu-core';
import {
  type EncryptionKeyId,
  type KeysvcOp,
  LIMITS,
  MAX_ALIAS_GENERATION,
  type MacPurpose,
  type SigningKeyId,
} from '@pii-token-vault/warifu-core/keys/protocol';
import {
  aes256GcmOpen,
  aes256GcmSeal,
  CryptoOpenError,
  GCM_IV_BYTES,
  GCM_TAG_BYTES,
  hmacSha256,
  signEs256,
} from './crypto.ts';
import { ENCRYPTION_KEY_NUMBER, type Keyring } from './keyring.ts';

/** 入力の形が違う（400 invalid_request）。 */
export class InvalidRequestError extends Error {
  constructor() {
    super('要求の形が違う');
    this.name = 'InvalidRequestError';
  }
}

/** 復号できない（400 decrypt_failed）。 */
export class DecryptFailedError extends Error {
  constructor() {
    super('復号できなかった');
    this.name = 'DecryptFailedError';
  }
}

const FORMAT_VERSION = 0x01;
const HEADER_BYTES = 6;
/** 別名のローカル部に使う HMAC の先頭のバイト数（80ビット。ADR 0005 の下限）。 */
const ALIAS_BYTES = 10;

function exactKeys(body: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(body);
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(body, key))) {
    throw new InvalidRequestError();
  }
}

function bytesField(value: unknown, min: number, max: number): Uint8Array {
  if (typeof value !== 'string') throw new InvalidRequestError();
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch {
    throw new InvalidRequestError();
  }
  if (bytes.byteLength < min || bytes.byteLength > max) throw new InvalidRequestError();
  return bytes;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** 文脈の形を確かめ、キーで並べた [キー, 値, …] を返す。 */
function contextEntries(keyId: EncryptionKeyId, context: unknown): string[] {
  if (!isPlainObject(context)) throw new InvalidRequestError();
  if (keyId === 'contact') {
    exactKeys(context, ['field', 'user_id']);
    if (context.field !== 'email' || !isUuid(context.user_id)) throw new InvalidRequestError();
  } else {
    exactKeys(context, ['queue_item_id']);
    if (!isUuid(context.queue_item_id)) throw new InvalidRequestError();
  }
  return Object.keys(context)
    .sort()
    .flatMap((key) => [key, context[key] as string]);
}

function header(keyId: EncryptionKeyId, version: number): Uint8Array {
  return concatBytes([
    new Uint8Array([FORMAT_VERSION, ENCRYPTION_KEY_NUMBER[keyId]]),
    u32be(version),
  ]);
}

function encrypt(body: Record<string, unknown>, keyring: Keyring): { ciphertext: string } {
  exactKeys(body, ['keyId', 'plaintext', 'context']);
  const keyId = body.keyId as EncryptionKeyId;
  const plaintext = bytesField(body.plaintext, 1, LIMITS.plaintextBytes);
  const entries = contextEntries(keyId, body.context);
  const key = keyring.primary(keyId);
  const head = header(keyId, key.version);
  const sealed = aes256GcmSeal(key.key, plaintext, concatBytes([head, lengthPrefixed(entries)]));
  return {
    ciphertext: toBase64Url(concatBytes([head, sealed.iv, sealed.ciphertext, sealed.tag])),
  };
}

function decrypt(body: Record<string, unknown>, keyring: Keyring): { plaintext: string } {
  exactKeys(body, ['keyId', 'ciphertext', 'context']);
  const keyId = body.keyId as EncryptionKeyId;
  const blob = bytesField(
    body.ciphertext,
    1,
    HEADER_BYTES + GCM_IV_BYTES + LIMITS.plaintextBytes + GCM_TAG_BYTES,
  );
  const entries = contextEntries(keyId, body.context);
  if (blob.byteLength < HEADER_BYTES + GCM_IV_BYTES + 1 + GCM_TAG_BYTES) {
    throw new DecryptFailedError();
  }
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (blob[0] !== FORMAT_VERSION || blob[1] !== ENCRYPTION_KEY_NUMBER[keyId]) {
    throw new DecryptFailedError();
  }
  const key = keyring.byVersion(keyId, view.getUint32(2));
  if (key === undefined) throw new DecryptFailedError();
  const head = blob.subarray(0, HEADER_BYTES);
  const iv = blob.subarray(HEADER_BYTES, HEADER_BYTES + GCM_IV_BYTES);
  const tag = blob.subarray(blob.byteLength - GCM_TAG_BYTES);
  const ciphertext = blob.subarray(HEADER_BYTES + GCM_IV_BYTES, blob.byteLength - GCM_TAG_BYTES);
  try {
    const plaintext = aes256GcmOpen(
      key.key,
      iv,
      ciphertext,
      tag,
      concatBytes([head, lengthPrefixed(entries)]),
    );
    return { plaintext: toBase64Url(plaintext) };
  } catch (error) {
    if (error instanceof CryptoOpenError) throw new DecryptFailedError();
    throw error;
  }
}

function mac(body: Record<string, unknown>, keyring: Keyring): { mac: string } {
  exactKeys(body, ['purpose', 'message']);
  const message = bytesField(body.message, 1, LIMITS.macMessageBytes);
  return { mac: toBase64Url(hmacSha256(keyring.macKey(body.purpose as MacPurpose), message)) };
}

function deriveAlias(body: Record<string, unknown>, keyring: Keyring): { localPart: string } {
  exactKeys(body, ['tenantId', 'userId', 'generation']);
  const { tenantId, userId, generation } = body;
  if (!isUuid(tenantId) || !isUuid(userId)) throw new InvalidRequestError();
  if (
    typeof generation !== 'number' ||
    !Number.isSafeInteger(generation) ||
    generation < 1 ||
    generation > MAX_ALIAS_GENERATION
  ) {
    throw new InvalidRequestError();
  }
  const digest = hmacSha256(
    keyring.aliasDeriveKey(),
    lengthPrefixed(['warifu/alias/v1', uuidBytes(tenantId), uuidBytes(userId), u32be(generation)]),
  );
  return { localPart: toBase32Lower(digest.subarray(0, ALIAS_BYTES)) };
}

function sign(body: Record<string, unknown>, keyring: Keyring): { kid: string; signature: string } {
  exactKeys(body, ['keyId', 'message']);
  const message = bytesField(body.message, 1, LIMITS.signMessageBytes);
  const key = keyring.signingKey(body.keyId as SigningKeyId);
  return { kid: key.kid, signature: toBase64Url(signEs256(key.privateKey, message)) };
}

function publicKeys(body: Record<string, unknown>, keyring: Keyring): { keys: readonly object[] } {
  exactKeys(body, ['keyId']);
  return { keys: keyring.publicKeys(body.keyId as SigningKeyId) };
}

/** 操作の対象（acl.ts の第3列）を本文から取り出す。形が違えば undefined（403 にする）。 */
export function targetOf(op: KeysvcOp, body: Record<string, unknown>): unknown {
  switch (op) {
    case 'encrypt':
    case 'decrypt':
    case 'sign':
    case 'public_keys':
      return body.keyId;
    case 'mac':
      return body.purpose;
    case 'derive_alias':
      return 'alias_derive';
  }
}

export function runOp(op: KeysvcOp, body: Record<string, unknown>, keyring: Keyring): object {
  switch (op) {
    case 'encrypt':
      return encrypt(body, keyring);
    case 'decrypt':
      return decrypt(body, keyring);
    case 'mac':
      return mac(body, keyring);
    case 'derive_alias':
      return deriveAlias(body, keyring);
    case 'sign':
      return sign(body, keyring);
    case 'public_keys':
      return publicKeys(body, keyring);
  }
}
