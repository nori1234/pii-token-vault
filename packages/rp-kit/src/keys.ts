// 割符の公開鍵を取る（ADR 0029 の O-108）。URL は、設定のオリジンの下に SDK が組み立てる（応答の中の jwks_uri に従わない）。
// 5分だけ覚え、kid が見つからなければ1回だけ取り直す（鍵の入れ替えに追いつくため）。
// 取り直しは、前に取りに行ってから30秒たつまでは行わない（知らない kid の JWT を受け口に送り続けて、企業のサーバーに
// 割符へ鍵を取りに行かせ続けることを防ぐ）。

import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { RpKitError } from './errors.ts';
import { failureOf, type HttpRequest, type HttpResponse, jsonOf } from './transport.ts';

const CACHE_MS = 5 * 60_000;
/** 取り直しの間隔の下限（ミリ秒）。 */
export const JWKS_REFRESH_COOLDOWN_MS = 30_000;

export function jwksFetcher(
  send: (request: HttpRequest) => Promise<HttpResponse>,
  url: string,
  now: () => number,
): (refresh: boolean) => Promise<JWTVerifyGetKey> {
  let cached: { readonly at: number; readonly keys: JWTVerifyGetKey } | undefined;
  return async (refresh) => {
    if (cached !== undefined) {
      const age = now() - cached.at;
      if (age >= 0 && age < (refresh ? JWKS_REFRESH_COOLDOWN_MS : CACHE_MS)) return cached.keys;
    }
    const response = await send({ method: 'GET', url, headers: { accept: 'application/json' } });
    if (response.status !== 200) throw failureOf(response);
    const body = jsonOf(response);
    if (!Array.isArray(body.keys)) throw new RpKitError('invalid_response');
    const keys = createLocalJWKSet({ keys: body.keys } as JSONWebKeySet);
    cached = { at: now(), keys };
    return keys;
  };
}
