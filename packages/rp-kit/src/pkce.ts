// PKCE（RFC 7636）の S256 と、state・nonce の乱数（ADR 0029 の O-110）。
// node:crypto を import してよいのは、rp-kit ではこのファイルだけ。使うのは randomBytes と createHash('sha256') だけ
// （不変条件9 の、プロトコルで決まる例外。test/leak/t08-crypto-allowlist で固定する）。

import { createHash, randomBytes } from 'node:crypto';

/** 32バイトの乱数の base64url（43文字。RFC 7636 の verifier の長さの範囲）。 */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export interface Pkce {
  readonly verifier: string;
  readonly challenge: string;
  readonly method: 'S256';
}

export function newPkce(): Pkce {
  const verifier = randomToken(32);
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return { verifier, challenge, method: 'S256' };
}
