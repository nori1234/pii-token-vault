// 符号化（暗号は使わない）。MAC にかける入力は、すべて lengthPrefixed で作る（区切りの曖昧さをなくすため）。

/** 符号化の誤り。メッセージに値を入れない（不変条件4）。 */
export class EncodingError extends Error {
  constructor() {
    super('符号化の形が違う');
    this.name = 'EncodingError';
  }
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/** パディングなしの base64url だけを受け付ける。同じバイト列の書き方は1つだけにする（余りのビットが0）。 */
export function fromBase64Url(text: string): Uint8Array {
  if (typeof text !== 'string' || !BASE64URL_PATTERN.test(text) || text.length % 4 === 1) {
    throw new EncodingError();
  }
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.toString('base64url') !== text) throw new EncodingError();
  return new Uint8Array(bytes);
}

// RFC 4648 の base32 の字母を小文字にしたもの。
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** RFC 4648 の base32 を小文字にしたもの。パディングは付けない。 */
export function toBase32Lower(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET.charAt((buffer >>> bits) & 31);
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 31);
  return out;
}

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** 32ビットの符号なし整数（ビッグエンディアン）。 */
export function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) throw new EncodingError();
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

/** 64ビットの符号なし整数（ビッグエンディアン）。 */
export function u64be(value: bigint): Uint8Array {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new EncodingError();
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value);
  return out;
}

/** 各部分の前に、u32 のビッグエンディアンで長さを付けて連結する。文字列は UTF-8 にする。 */
export function lengthPrefixed(parts: readonly (Uint8Array | string)[]): Uint8Array {
  const encoded = parts.map((part) => (typeof part === 'string' ? utf8(part) : part));
  const total = encoded.reduce((sum, part) => sum + 4 + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of encoded) {
    out.set(u32be(part.byteLength), offset);
    out.set(part, offset + 4);
    offset += 4 + part.byteLength;
  }
  return out;
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** キーを並べ替えた JSON。値は、文字列、安全な整数、真偽値だけを受け付ける。 */
export function canonicalJson(value: Readonly<Record<string, string | number | boolean>>): string {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new EncodingError();
  const keys = Object.keys(value).sort();
  const body = keys.map((key) => {
    const item = value[key];
    if (typeof item === 'number' && !Number.isSafeInteger(item)) throw new EncodingError();
    if (typeof item !== 'string' && typeof item !== 'number' && typeof item !== 'boolean') {
      throw new EncodingError();
    }
    return `${JSON.stringify(key)}:${JSON.stringify(item)}`;
  });
  return `{${body.join(',')}}`;
}
