// 割符の公開鍵を取る（ADR 0029 の O-108）。URL は、設定のオリジンの下に SDK が組み立てる（応答の中の jwks_uri に従わない）。
// 5分だけ覚え、kid が見つからなければ取り直す（鍵の入れ替えに追いつくため）。
// 割符へ取りに行く回数を、受け口に届く要求の数で増やさせない（知らない kid の JWT を受け口に送り続けて、企業のサーバーに
// 割符へ鍵を取りに行かせ続けることを防ぐ）。
// - 取りに行っている途中の要求は、同時の呼び出しで共有する（同時に何件来ても、取りに行くのは1回）。
// - 前に取りに行き始めてから30秒の間は、取りに行かない。成功しても失敗しても、取りに行き始めた時刻から数える
//   （失敗の後に、続けて取りに行かない）。その間は、覚えている鍵が新しければそれを使い、なければ unavailable にする。

import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { RpKitError } from './errors.ts';
import { failureOf, type HttpRequest, type HttpResponse, jsonOf } from './transport.ts';

const CACHE_MS = 5 * 60_000;
/** 取りに行く間隔の下限（ミリ秒）。 */
export const JWKS_REFRESH_COOLDOWN_MS = 30_000;

export function jwksFetcher(
  send: (request: HttpRequest) => Promise<HttpResponse>,
  url: string,
  now: () => number,
): (refresh: boolean) => Promise<JWTVerifyGetKey> {
  let cached: { readonly at: number; readonly keys: JWTVerifyGetKey } | undefined;
  /** 取りに行っている途中の要求（同時の呼び出しは、これを待つ）。 */
  let inflight: Promise<JWTVerifyGetKey> | undefined;
  /** 最後に取りに行き始めた時刻（成功しても失敗しても）。 */
  let attemptedAt: number | undefined;

  async function fetchKeys(): Promise<JWTVerifyGetKey> {
    const response = await send({ method: 'GET', url, headers: { accept: 'application/json' } });
    if (response.status !== 200) throw failureOf(response);
    const body = jsonOf(response);
    if (!Array.isArray(body.keys)) throw new RpKitError('invalid_response');
    return createLocalJWKSet({ keys: body.keys } as JSONWebKeySet);
  }

  return async (refresh) => {
    if (inflight !== undefined) return inflight;
    const at = now();
    const current = cached;
    const fresh =
      current !== undefined && at - current.at >= 0 && at - current.at < CACHE_MS
        ? current.keys
        : undefined;
    if (fresh !== undefined && !refresh) return fresh;
    const since = attemptedAt === undefined ? undefined : at - attemptedAt;
    if (since !== undefined && since >= 0 && since < JWKS_REFRESH_COOLDOWN_MS) {
      if (fresh !== undefined) return fresh;
      throw new RpKitError('unavailable');
    }
    attemptedAt = at;
    // 共有する要求は、呼び出しの間に await を挟まずに置く（同時の呼び出しが、必ずこれを見る）。
    inflight = fetchKeys()
      .then((keys) => {
        cached = { at: now(), keys };
        return keys;
      })
      .finally(() => {
        inflight = undefined;
      });
    return inflight;
  };
}
