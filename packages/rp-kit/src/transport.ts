// 通信の関数（ADR 0029 の O-108）。企業が書くのは、1つの要求を送って1つの応答を返す、この関数だけ。
// SDK は、送る前に宛先が設定した割符のオリジンかを確かめ、応答が 3xx なら失敗にする（リダイレクトに進まない）。

import { RpKitError } from './errors.ts';

export interface HttpRequest {
  readonly method: 'GET' | 'POST';
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
}

export interface HttpResponse {
  readonly status: number;
  /** content-type だけを見る（小文字の名前）。 */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** 企業が渡す関数。リダイレクトには従わない作りにする（fetch なら redirect: 'manual'）。 */
export type Send = (request: HttpRequest) => Promise<HttpResponse>;

/** 応答の本文の上限（大きすぎる応答で、企業のサーバーのメモリを使わせない）。 */
export const MAX_RESPONSE_BYTES = 256 * 1024;

/** オリジン（scheme://host[:port]）の形。パス、クエリ、利用者情報を持たない。 */
export function parseOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RpKitError('invalid_config');
  }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== '' ||
    value.replace(/\/$/, '') !== url.origin
  ) {
    throw new RpKitError('invalid_config');
  }
  return url.origin;
}

/** 設定したオリジンの下にだけ送る通信。宛先は SDK が組み立てた URL だけにする。 */
export function guardedSend(
  send: Send,
  origins: readonly string[],
): (request: HttpRequest) => Promise<HttpResponse> {
  const allowed = new Set(origins);
  return async (request) => {
    let target: URL;
    try {
      target = new URL(request.url);
    } catch {
      throw new RpKitError('forbidden_destination');
    }
    if (!allowed.has(target.origin) || target.username !== '' || target.password !== '') {
      throw new RpKitError('forbidden_destination');
    }
    let response: HttpResponse;
    try {
      response = await send(request);
    } catch {
      throw new RpKitError('unavailable');
    }
    if (
      typeof response?.status !== 'number' ||
      typeof response.body !== 'string' ||
      response.body.length > MAX_RESPONSE_BYTES ||
      (response.status >= 300 && response.status < 400)
    ) {
      throw new RpKitError('unavailable');
    }
    return response;
  };
}

/** JSON の応答を読む。オブジェクトでなければ invalid_response。 */
export function jsonOf(response: HttpResponse): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.body);
  } catch {
    throw new RpKitError('invalid_response');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new RpKitError('invalid_response');
  }
  return parsed as Record<string, unknown>;
}

/** 4xx は rejected（割符の error の値だけを reason に）、5xx は unavailable。 */
export function failureOf(response: HttpResponse): RpKitError {
  if (response.status >= 400 && response.status < 500) {
    let reason: string | undefined;
    try {
      const error = (JSON.parse(response.body) as { error?: unknown }).error;
      reason = typeof error === 'string' ? error : undefined;
    } catch {
      reason = undefined;
    }
    return new RpKitError('rejected', reason);
  }
  return new RpKitError('unavailable');
}
