// 乱数と定数時間の比較。warifu-core で node:crypto を import するのは、このファイルだけ（不変条件9）。
// 鍵を使う処理（暗号化、MAC、署名）は、ここには置かない。すべて鍵サービス（packages/keysvc）の中で行う。

import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

export function randomBytesOf(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1 || length > 1024) {
    throw new RangeError('乱数の長さが範囲の外');
  }
  return new Uint8Array(randomBytes(length));
}

/** RFC 9562 の version 4 の UUID（小文字）。 */
export function randomUuid(): string {
  return randomUUID();
}

/** 長さが違えば false を返す（node:crypto の timingSafeEqual は、長さが違うと例外を投げるため）。 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return timingSafeEqual(a, b);
}
