// SET の Webhook（RFC 8935 の push）への送信（plan 2章、CAP-22、RP-51、ADR 0022）。
//
// - URL は https、ポート 443、ホストは名前だけ（names.ts）。
// - 名前の A と AAAA がすべて公開のアドレスのときだけ送る（resolve.ts）。接続は、確かめたアドレスに直接つなぎ、
//   TLS の SNI と証明書の検査はホスト名で行う（DNS rebinding 対策）。
//   node:https の request に agent: false を渡すと、Node が自前のエージェントを作り、createConnection を使わずに
//   ホスト名を名前解決してしまう。そこで、接続を作る関数を差し替えたエージェントを要求ごとに作り、さらに lookup も
//   確かめたアドレスだけを返すものにする（どちらの経路でも、ほかのアドレスにつながない）。
// - リダイレクトに従わない（3xx は失敗）。応答の本文は 16 KiB まで読む。400 の JSON の本文から、RFC 8935 の err と、
//   割符の補足の warifu_reason（SET の時刻の失敗。ADR 0026）が決まった値かどうかだけを読み、ほかは捨てる。
//   description も、知らない値も、呼び出し元に返さない。全体の時間切れは10秒。
// - テストでは、最後の接続（TLS のソケット）だけを差し替えられる。宛先の検査は差し替えられない。

import { Agent, request } from 'node:https';
import type { LookupFunction } from 'node:net';
import { isIP } from 'node:net';
import { connect, type TLSSocket } from 'node:tls';
import {
  SET_TIME_ERRORS,
  type SenderRejectReason,
  type SetTimeError,
} from '@pii-token-vault/warifu-core/sender/protocol';
import { parseWebhookUrl } from './names.ts';
import { type DnsResolver, ResolveError, resolvePublicAddresses } from './resolve.ts';

export const WEBHOOK_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 16_384;
const MAX_ATTEMPTS = 2;
const SET_CONTENT_TYPE = 'application/secevent+jwt';

/** 確かめたアドレスへの TLS の接続を作る。既定は node:tls。 */
export type TlsConnector = (input: {
  readonly address: string;
  readonly port: number;
  readonly servername: string;
}) => TLSSocket;

export const defaultTlsConnector: TlsConnector = ({ address, port, servername }) =>
  connect({ host: address, port, servername, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2' });

export interface WebhookDeps {
  readonly resolver: DnsResolver;
  readonly connectTls: TlsConnector;
}

export type WebhookOutcome =
  | { readonly ok: true; readonly status: number }
  | {
      readonly ok: false;
      readonly reason: SenderRejectReason;
      /** 受け口が応答したときの HTTP のステータス。 */
      readonly status?: number;
      /** 400 の本文が、SET の時刻だけの失敗を示したとき。 */
      readonly setError?: SetTimeError;
    };

/** 400 の本文から、SET の時刻だけの失敗を読む。決まった形でなければ undefined。 */
export function setTimeErrorOf(contentType: unknown, body: Buffer): SetTimeError | undefined {
  if (typeof contentType !== 'string' || !/^application\/json(\s*;|$)/i.test(contentType)) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const { err, warifu_reason: reason } = parsed as Record<string, unknown>;
  if (err !== 'invalid_request' || typeof reason !== 'string') return undefined;
  return (SET_TIME_ERRORS as readonly string[]).includes(reason)
    ? (reason as SetTimeError)
    : undefined;
}

function postOnce(
  deps: WebhookDeps,
  target: { readonly host: string; readonly path: string },
  address: string,
  body: Buffer,
): Promise<WebhookOutcome> {
  return new Promise((resolvePost) => {
    let settled = false;
    const finish = (outcome: WebhookOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      req.destroy();
      agent.destroy();
      resolvePost(outcome);
    };
    const headers: Record<string, string> = {
      host: target.host,
      'content-type': SET_CONTENT_TYPE,
      accept: 'application/json',
      'content-length': String(body.byteLength),
      'user-agent': 'warifu-sender',
    };
    const agent = new Agent({ keepAlive: false, maxSockets: 1 });
    Object.defineProperty(agent, 'createConnection', {
      value: () => deps.connectTls({ address, port: 443, servername: target.host }),
    });
    const pinned: LookupFunction = (_hostname, options, callback) => {
      const family = isIP(address);
      if ((options as { all?: boolean }).all === true) {
        (callback as (e: null, a: { address: string; family: number }[]) => void)(null, [
          { address, family },
        ]);
      } else {
        callback(null, address, family);
      }
    };
    const req = request(
      {
        host: target.host,
        port: 443,
        path: target.path,
        method: 'POST',
        headers,
        agent,
        lookup: pinned,
        servername: target.host,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.byteLength;
          if (total > MAX_RESPONSE_BYTES) {
            finish(classify(status, undefined));
            return;
          }
          if (status === 400) chunks.push(chunk);
        });
        res.on('end', () =>
          finish(
            classify(
              status,
              status === 400
                ? setTimeErrorOf(res.headers['content-type'], Buffer.concat(chunks))
                : undefined,
            ),
          ),
        );
        res.on('error', () => finish(classify(status, undefined)));
      },
    );
    const deadline = setTimeout(() => finish({ ok: false, reason: 'timeout' }), WEBHOOK_TIMEOUT_MS);
    req.on('error', () => finish({ ok: false, reason: 'connect_failed' }));
    req.end(body);
  });
}

function classify(status: number, setError: SetTimeError | undefined): WebhookOutcome {
  if (status >= 200 && status < 300) return { ok: true, status };
  if (status >= 300 && status < 400) return { ok: false, reason: 'redirect', status };
  if (status < 100 || status > 599) return { ok: false, reason: 'http_status' };
  return {
    ok: false,
    reason: 'http_status',
    status,
    ...(setError === undefined ? {} : { setError }),
  };
}

/** SET を Webhook に送る。宛先が検査に通らなければ、つながずに断る。 */
export async function postWebhook(
  deps: WebhookDeps,
  input: { readonly url: string; readonly set: string },
): Promise<WebhookOutcome> {
  const target = parseWebhookUrl(input.url);
  if (target === undefined) return { ok: false, reason: 'invalid_destination' };
  let addresses: readonly string[];
  try {
    addresses = await resolvePublicAddresses(deps.resolver, target.host);
  } catch (error) {
    if (error instanceof ResolveError) return { ok: false, reason: error.reason };
    throw error;
  }
  const body = Buffer.from(input.set, 'ascii');
  let outcome: WebhookOutcome = { ok: false, reason: 'connect_failed' };
  for (const address of addresses.slice(0, MAX_ATTEMPTS)) {
    outcome = await postOnce(deps, target, address, body);
    // つながらなかったときだけ、次のアドレスを試す（応答があったものは、そのまま返す）。
    if (outcome.ok || outcome.reason !== 'connect_failed') return outcome;
  }
  return outcome;
}
