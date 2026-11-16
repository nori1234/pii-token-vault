// demo-rp が割符につなぐ、ただ1つのファイル（ADR 0029 の O-109）。lint の fetch の制限は、このファイルだけ外している。
// - 送る先は、設定で固定したオリジン（割符の idp と company-api、または模擬 OP）の完全一致だけ。利用者や画面から渡された
//   URL にはつながない。
// - リダイレクトには従わない（redirect: 'manual'。3xx は、rp-kit が失敗として扱う）。
// - https だけにつなぐ。http は、ループバック（手元の開発とテスト）に限る。
// - 応答は、大きさの上限までしか読まない（上限を超えたら、読むのをやめて失敗にする）。時間切れは5秒。

import type { HttpRequest, HttpResponse, Send } from '@pii-token-vault/rp-kit';

const TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

export class TransportError extends Error {
  override name = 'TransportError';
}

/** 本文を、上限のバイト数まで読む。超えたら、残りを読まずに失敗にする。 */
async function readLimited(response: Response): Promise<string> {
  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new TransportError('応答が大きすぎる');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** 設定のオリジンにだけ送る通信の関数を作る。オリジンは、起動のときに決めて、後から足せない。 */
export function createTransport(allowedOrigins: readonly string[]): Send {
  const allowed: ReadonlySet<string> = new Set(
    allowedOrigins.map((origin) => {
      const url = new URL(origin);
      if (
        url.origin !== origin.replace(/\/$/, '') ||
        (url.protocol !== 'https:' && url.protocol !== 'http:') ||
        (url.protocol === 'http:' && !LOOPBACK_HOSTS.has(url.hostname))
      ) {
        throw new TransportError('オリジンの形が違う');
      }
      return url.origin;
    }),
  );
  return async (request: HttpRequest): Promise<HttpResponse> => {
    const target = new URL(request.url);
    if (!allowed.has(target.origin) || target.username !== '' || target.password !== '') {
      throw new TransportError('設定していない宛先');
    }
    const response = await fetch(target, {
      method: request.method,
      headers: request.headers,
      ...(request.body === undefined ? {} : { body: request.body }),
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const body = await readLimited(response);
    return {
      status: response.status,
      headers: { 'content-type': response.headers.get('content-type') ?? '' },
      body,
    };
  };
}
