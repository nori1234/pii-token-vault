// 送信サービス（不変条件7、CAP-20〜27・38、ADR 0022）。外向きの通信（HTTP(S)、SMTP、名前解決）の唯一の出口。
//
// - 内部 API は Unix ドメインソケットの HTTP（TCP では待ち受けない）。資格情報は呼び出し元ごとの
//   `Bearer <呼び出し元>.<32バイトの base64url>`。形が違う、知らない呼び出し元、長さが違うときも、ダミーと
//   比べてから失敗にする（所要時間をそろえる。鍵サービスと同じ。ADR 0013）。
// - 口は POST /v1/webhook（company-api）、POST /v1/mail と POST /v1/dns（relay）だけ。呼び出し元に許していない
//   口は 401、ほかのパスとメソッドは 404。本文は口ごとの上限まで。
// - 応答は、送れたか、送れなかった理由の種類だけ。URL、宛先、IP をログにも応答にも出さない（不変条件4）。
// - 鍵サービスの資格情報と DB を持たない（CAP-21、spec 04 の 3章）。

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { constantTimeEqual, randomBytesOf } from '@pii-token-vault/warifu-core';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import {
  DNS_TYPES,
  type DnsType,
  SENDER_ACL,
  SENDER_CALLERS,
  SENDER_ERROR_BODY,
  SENDER_LIMITS,
  SENDER_PATHS,
  type SenderCaller,
  type SenderOp,
} from '@pii-token-vault/warifu-core/sender/protocol';
import { lookupDns } from './dns.ts';
import { defaultTcpConnector, deliverMail, type TcpConnector } from './mail.ts';
import { type DnsResolver, systemResolver } from './resolve.ts';
import { defaultTlsConnector, postWebhook, type TlsConnector } from './webhook.ts';

const SECRET_BYTES = 32;
const BEARER_PATTERN = /^Bearer (relay|company-api)\.([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

export interface SenderOptions {
  readonly socketPath: string;
  readonly credentials: Readonly<Partial<Record<SenderCaller, Uint8Array>>>;
  readonly log: Logger;
  /** EHLO で名乗る名前。 */
  readonly heloName: string;
  /** 既定は OS の設定のリゾルバ。テストでは模擬のものを渡す。 */
  readonly resolver?: DnsResolver;
  /** 確かめたアドレスへの最後の接続。テストだけが差し替える（宛先の検査は差し替えられない）。 */
  readonly connectTls?: TlsConnector;
  readonly connectTcp?: TcpConnector;
}

export interface SenderHandle {
  readonly socketPath: string;
  close(): Promise<void>;
}

function reply(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
  });
  res.end(body);
}

function opOf(method: string | undefined, url: string | undefined): SenderOp | undefined {
  if (method !== 'POST') return undefined;
  for (const op of Object.keys(SENDER_PATHS) as SenderOp[]) {
    if (SENDER_PATHS[op] === url) return op;
  }
  return undefined;
}

function callerOf(
  header: string | undefined,
  credentials: SenderOptions['credentials'],
  dummy: Uint8Array,
): SenderCaller | undefined {
  const match = typeof header === 'string' ? BEARER_PATTERN.exec(header) : null;
  const caller = match?.[1] as SenderCaller | undefined;
  const presented =
    match === null ? undefined : new Uint8Array(Buffer.from(match[2] ?? '', 'base64url'));
  const expected = caller === undefined ? undefined : credentials[caller];
  if (presented === undefined || presented.byteLength !== SECRET_BYTES || expected === undefined) {
    constantTimeEqual(dummy, dummy);
    return undefined;
  }
  return constantTimeEqual(presented, expected) ? caller : undefined;
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).byteLength;
    if (total > limit) return undefined;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function objectWithKeys(raw: Buffer, keys: readonly string[]): Record<string, unknown> | undefined {
  let value: unknown;
  try {
    value = JSON.parse(raw.toString('utf8'));
  } catch {
    return undefined;
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== [...keys].sort().join(',')) return undefined;
  if (!keys.every((key) => typeof record[key] === 'string')) return undefined;
  return record;
}

export async function startSender(options: SenderOptions): Promise<SenderHandle> {
  for (const [caller, secret] of Object.entries(options.credentials)) {
    if (!(SENDER_CALLERS as readonly string[]).includes(caller)) {
      throw new RangeError('知らない呼び出し元の資格情報がある');
    }
    if (!(secret instanceof Uint8Array) || secret.byteLength !== SECRET_BYTES) {
      throw new RangeError('資格情報の長さが違う');
    }
  }
  const resolver = options.resolver ?? systemResolver();
  const webhookDeps = { resolver, connectTls: options.connectTls ?? defaultTlsConnector };
  const mailDeps = {
    resolver,
    connectTcp: options.connectTcp ?? defaultTcpConnector,
    heloName: options.heloName,
  };
  const { log } = options;
  const dummy = randomBytesOf(SECRET_BYTES);

  const handle = async (op: SenderOp, raw: Buffer): Promise<object | undefined> => {
    switch (op) {
      case 'webhook': {
        const body = objectWithKeys(raw, ['url', 'set']);
        if (body === undefined) return undefined;
        const set = body.set as string;
        if (set.length > SENDER_LIMITS.setBytes || !/^[A-Za-z0-9_.-]+$/.test(set)) return undefined;
        const outcome = await postWebhook(webhookDeps, { url: body.url as string, set });
        if (outcome.ok) {
          log.info({ event: 'sender.webhook_delivered', status: outcome.status });
          return { ok: true };
        }
        log.warn({ event: 'sender.webhook_rejected', reason: outcome.reason });
        return { ok: false, reason: outcome.reason };
      }
      case 'mail': {
        const body = objectWithKeys(raw, ['mailFrom', 'rcptTo', 'raw']);
        if (body === undefined || !BASE64_PATTERN.test(body.raw as string)) return undefined;
        const message = Buffer.from(body.raw as string, 'base64');
        if (message.byteLength === 0 || message.byteLength > SENDER_LIMITS.rawMessageBytes) {
          return undefined;
        }
        const outcome = await deliverMail(mailDeps, {
          mailFrom: body.mailFrom as string,
          rcptTo: body.rcptTo as string,
          raw: message,
        });
        if (outcome.ok) {
          log.info({ event: 'sender.mail_delivered' });
          return { ok: true };
        }
        log.warn({ event: 'sender.mail_rejected', reason: outcome.reason });
        return { ok: false, reason: outcome.reason };
      }
      case 'dns': {
        const body = objectWithKeys(raw, ['name', 'type']);
        if (body === undefined || !DNS_TYPES.includes(body.type as DnsType)) return undefined;
        const outcome = await lookupDns(resolver, {
          name: body.name as string,
          type: body.type as DnsType,
        });
        return outcome.ok
          ? { ok: true, records: outcome.records }
          : { ok: false, code: outcome.code };
      }
    }
  };

  const server = createServer((req, res) => {
    (async () => {
      const op = opOf(req.method, req.url);
      if (op === undefined) {
        reply(res, 404, SENDER_ERROR_BODY.not_found);
        return;
      }
      const caller = callerOf(req.headers.authorization, options.credentials, dummy);
      if (caller === undefined || !SENDER_ACL[caller].includes(op)) {
        reply(res, 401, SENDER_ERROR_BODY.forbidden);
        return;
      }
      const raw = await readBody(req, SENDER_LIMITS.requestBodyBytes[op]);
      const result = raw === undefined ? undefined : await handle(op, raw);
      if (result === undefined) {
        reply(res, 400, SENDER_ERROR_BODY.invalid_request);
        return;
      }
      reply(res, 200, JSON.stringify(result));
    })().catch((err: unknown) => {
      log.error({ event: 'sender.internal_api_failed', err });
      if (!res.headersSent) reply(res, 503, SENDER_ERROR_BODY.unavailable);
    });
  });
  server.requestTimeout = 150_000;
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(options.socketPath, () => resolveListen());
  });
  return Object.freeze({
    socketPath: options.socketPath,
    close: () => new Promise<void>((resolveClose) => server.close(() => resolveClose())),
  });
}
