// relay の内部配送 API（不変条件3、CAP-38、ADR 0021）。Unix ドメインソケットの HTTP で、idp だけが呼べる。
// idp は利用者 ID と種類（と、宛先確認のときだけ確認コード）を渡し、relay が本物のアドレスを読んで送る。
//
// - 資格情報は `Authorization: Bearer idp.<32バイトの base64url>`。形が違う、知らない呼び出し元、長さが違うときも、
//   ダミーと比べてから失敗にする（所要時間をそろえる。鍵サービスと同じ。ADR 0013）。
// - POST /v1/deliver だけ。JSON の本文は 1KB まで。ほかはすべて 404。
// - 応答は 202 か、固定の本文のエラーだけ。利用者がいるか、アドレスがあるかで応答を変えない。
// - ソケットの親のディレクトリは、このプロセスの利用者だけが読める（uds-client の検査と同じ前提）。

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  constantTimeEqual,
  isUuid,
  randomBytesOf,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import {
  DELIVERY_ERROR_BODY,
  DELIVERY_LIMITS,
  type DeliveryRequest,
  RELAY_DELIVER_PATH,
  VERIFY_CODE_PATTERN,
} from '@pii-token-vault/warifu-core/relay/protocol';

const SECRET_BYTES = 32;
const BEARER_PATTERN = /^Bearer (idp)\.([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/;

export interface InternalApi {
  close(): Promise<void>;
}

export interface InternalApiOptions {
  readonly socketPath: string;
  readonly credentials: Readonly<Record<'idp', Uint8Array>>;
  readonly log: Logger;
  deliver(request: DeliveryRequest): Promise<void>;
}

function reply(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
  });
  res.end(body);
}

function authenticate(
  header: string | undefined,
  credentials: Readonly<Record<'idp', Uint8Array>>,
  dummy: Uint8Array,
): boolean {
  const match = typeof header === 'string' ? BEARER_PATTERN.exec(header) : null;
  const presented =
    match === null ? undefined : new Uint8Array(Buffer.from(match[2] ?? '', 'base64url'));
  if (presented === undefined || presented.byteLength !== SECRET_BYTES) {
    constantTimeEqual(dummy, dummy);
    return false;
  }
  return constantTimeEqual(presented, credentials.idp);
}

function parseRequest(body: unknown): DeliveryRequest | undefined {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const value = body as Record<string, unknown>;
  const keys = Object.keys(value).sort().join(',');
  if (!isUuid(value.userId)) return undefined;
  const userId = value.userId as WarifuUserId;
  if (value.kind === 'email_verification' && keys === 'code,kind,userId') {
    if (typeof value.code !== 'string' || !VERIFY_CODE_PATTERN.test(value.code)) return undefined;
    return { kind: 'email_verification', userId, code: value.code };
  }
  if (value.kind === 'email_changed_notice' && keys === 'kind,userId') {
    return { kind: 'email_changed_notice', userId };
  }
  return undefined;
}

async function readBody(req: IncomingMessage): Promise<Buffer | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).byteLength;
    if (total > DELIVERY_LIMITS.requestBodyBytes) return undefined;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function startInternalApi(options: InternalApiOptions): Promise<InternalApi> {
  for (const secret of Object.values(options.credentials)) {
    if (!(secret instanceof Uint8Array) || secret.byteLength !== SECRET_BYTES) {
      throw new RangeError('資格情報の長さが違う');
    }
  }
  const dummy = randomBytesOf(SECRET_BYTES);
  const server: Server = createServer((req, res) => {
    (async () => {
      if (req.method !== 'POST' || req.url !== RELAY_DELIVER_PATH) {
        reply(res, 404, DELIVERY_ERROR_BODY.not_found);
        return;
      }
      if (!authenticate(req.headers.authorization, options.credentials, dummy)) {
        reply(res, 401, DELIVERY_ERROR_BODY.forbidden);
        return;
      }
      const raw = await readBody(req);
      let request: DeliveryRequest | undefined;
      try {
        request = raw === undefined ? undefined : parseRequest(JSON.parse(raw.toString('utf8')));
      } catch {
        request = undefined;
      }
      if (request === undefined) {
        reply(res, 400, DELIVERY_ERROR_BODY.invalid_request);
        return;
      }
      try {
        await options.deliver(request);
      } catch (err) {
        options.log.warn({ event: 'relay.internal_deliver_failed', err });
        reply(res, 503, DELIVERY_ERROR_BODY.unavailable);
        return;
      }
      reply(res, 202, '{"ok":true}');
    })().catch((err: unknown) => {
      options.log.error({ event: 'relay.internal_api_failed', err });
      if (!res.headersSent) reply(res, 503, DELIVERY_ERROR_BODY.unavailable);
    });
  });
  server.requestTimeout = 10_000;
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(options.socketPath, () => resolveListen());
  });
  return Object.freeze({
    close: () => new Promise<void>((resolveClose) => server.close(() => resolveClose())),
  });
}
