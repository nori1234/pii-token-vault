// company-api の JWS（不変条件9、ADR 0022）。方式は ES256 だけ。
// - 署名：秘密鍵は鍵サービスの外に出さない。ヘッダーの kid は鍵サービスの公開鍵から入れ、署名の応答の kid と
//   食い違えば（入れ替わっていたら）止める（idp の ID トークンと同じ。ADR 0014）。
// - 検証：jose の jwtVerify に、algorithms: ['ES256'] と、手元の鍵（createLocalJWKSet）だけを渡す。
//   外から鍵を取りに行く createRemoteJWKSet は使わない（不変条件7。lint でも禁じる）。

import { toBase64Url, utf8 } from '@pii-token-vault/warifu-core';
import type {
  CompanyApiKeyClient,
  CompanyApiSigningKeyId,
} from '@pii-token-vault/warifu-core/keys/company-api';
import type { Es256PublicJwk } from '@pii-token-vault/warifu-core/keys/protocol';
import { createLocalJWKSet, type JWTPayload, type JWTVerifyOptions, jwtVerify } from 'jose';

/** JWS に使う方式。ここ以外の値を、検証にも署名にも渡さない。 */
export const JWS_ALGORITHMS: readonly ['ES256'] = Object.freeze(['ES256'] as ['ES256']);

const KEY_CACHE_MS = 60_000;
/** 引き直しの間隔の下限（知らない kid のトークンで、鍵サービスを叩かせない）。 */
const KEY_REFRESH_MIN_MS = 10_000;

export class KeyRotatedError extends Error {
  override name = 'KeyRotatedError';
}

/** 鍵サービスの公開鍵を短い間だけ覚える（署名のたびに引かない）。 */
export class PublicKeyCache {
  readonly #keys: CompanyApiKeyClient;
  readonly #now: () => number;
  readonly #cache = new Map<
    CompanyApiSigningKeyId,
    { at: number; keys: readonly Es256PublicJwk[] }
  >();

  constructor(keys: CompanyApiKeyClient, now: () => number) {
    this.#keys = keys;
    this.#now = now;
  }

  async get(keyId: CompanyApiSigningKeyId, refresh = false): Promise<readonly Es256PublicJwk[]> {
    const hit = this.#cache.get(keyId);
    if (hit !== undefined) {
      const age = this.#now() - hit.at;
      if (refresh ? age < KEY_REFRESH_MIN_MS : age < KEY_CACHE_MS) return hit.keys;
    }
    const keys = await this.#keys.publicKeys(keyId);
    this.#cache.set(keyId, { at: this.#now(), keys });
    return keys;
  }
}

/** compact の JWS を作る。署名は鍵サービスの ES256（r‖s の64バイト）。 */
export async function signJwt(
  keys: CompanyApiKeyClient,
  cache: PublicKeyCache,
  keyId: CompanyApiSigningKeyId,
  typ: 'at+jwt' | 'secevent+jwt',
  payload: Readonly<Record<string, unknown>>,
): Promise<string> {
  const [current] = await cache.get(keyId);
  if (current === undefined) throw new KeyRotatedError();
  const header = { alg: 'ES256', typ, kid: current.kid };
  const input = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
  const { kid, signature } = await keys.sign(keyId, utf8(input));
  if (kid !== current.kid) {
    await cache.get(keyId, true);
    throw new KeyRotatedError();
  }
  return `${input}.${toBase64Url(signature)}`;
}

/** 手元の鍵で検証する。方式は ES256 だけ。失敗したら undefined（理由を区別しない）。 */
export async function verifyJwt(
  token: string,
  keys: readonly Es256PublicJwk[] | readonly object[],
  options: Omit<JWTVerifyOptions, 'algorithms'>,
): Promise<JWTPayload | undefined> {
  if (typeof token !== 'string' || token.length > 8192) return undefined;
  try {
    const jwks = createLocalJWKSet({ keys: [...keys] as never });
    const { payload } = await jwtVerify(token, jwks, {
      ...options,
      algorithms: [...JWS_ALGORITHMS],
    });
    return payload;
  } catch {
    return undefined;
  }
}
