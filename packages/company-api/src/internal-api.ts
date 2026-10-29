// company-api の窓口の内部 API（ADR 0026 の O-63）。Unix ドメインソケットの HTTP で、idp だけが呼べる。
// idp は、承認した作成の記録、利用者の項目の状態、取消の受理を頼む。逆向き（company-api から idp）の API はない。
//
// - 資格情報は `Authorization: Bearer idp.<32バイトの base64url>`。形が違う、知らない呼び出し元、長さが違うときも、
//   ダミーと比べてから失敗にする（所要時間をそろえる。relay の内部配送 API と同じ。ADR 0021）。
// - POST /v1/desk_approve、/v1/desk_status、/v1/desk_cancel だけ。JSON の本文は 8KB まで。ほかはすべて 404。
// - テナントは、company-api の登録簿にあるものだけ。利用者 ID は idp が自分の認証から渡す。company-api は、
//   行の利用者が頼んだ利用者と同じかも確かめる（BOLA の二重の守り。D-41）。
// - 応答の本文に、受け取った値（申請ID など）を入れない。ログは固定の事象の名前だけ（不変条件4）。
// - ソケットの親のディレクトリは、このプロセスの利用者だけが読める（uds-client の検査と同じ前提）。

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  constantTimeEqual,
  isUuid,
  randomBytesOf,
  type TenantId,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import {
  DESK_ERROR_BODY,
  DESK_LIMITS,
  DESK_PATHS,
  DESK_REQUEST_ID_PATTERN,
  type DeskOp,
  type DeskStatusItem,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import type { CompanyApiConfig } from './config.ts';
import { acceptCancel, type DeskDeps, recordApproval, statusOf } from './desk.ts';

const SECRET_BYTES = 32;
const BEARER_PATTERN = /^Bearer (idp)\.([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/;

export interface DeskInternalApi {
  close(): Promise<void>;
}

export interface DeskInternalApiOptions {
  readonly socketPath: string;
  readonly credentials: Readonly<Record<'idp', Uint8Array>>;
  readonly config: CompanyApiConfig;
  readonly deps: DeskDeps;
  readonly log: Logger;
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

async function readBody(req: IncomingMessage): Promise<Buffer | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).byteLength;
    if (total > DESK_LIMITS.requestBodyBytes) return undefined;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function objectWithKeys(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== [...keys].sort().join(',')) return undefined;
  return record;
}

function opOf(method: string | undefined, url: string | undefined): DeskOp | undefined {
  if (method !== 'POST') return undefined;
  for (const [op, path] of Object.entries(DESK_PATHS)) if (path === url) return op as DeskOp;
  return undefined;
}

export async function startDeskInternalApi(
  options: DeskInternalApiOptions,
): Promise<DeskInternalApi> {
  if (
    !(options.credentials.idp instanceof Uint8Array) ||
    options.credentials.idp.byteLength !== SECRET_BYTES
  ) {
    throw new RangeError('資格情報の長さが違う');
  }
  const { config, deps, log } = options;
  const dummy = randomBytesOf(SECRET_BYTES);

  /** 応答（ステータスと本文）。形が違えば undefined（400）。 */
  async function handle(op: DeskOp, value: unknown): Promise<[number, string] | undefined> {
    switch (op) {
      case 'approve': {
        const body = objectWithKeys(value, [
          'tenantId',
          'userId',
          'changeRef',
          'requestId',
          'action',
        ]);
        if (
          body === undefined ||
          !isUuid(body.tenantId) ||
          !isUuid(body.userId) ||
          !isUuid(body.changeRef) ||
          typeof body.requestId !== 'string' ||
          !DESK_REQUEST_ID_PATTERN.test(body.requestId) ||
          body.action !== 'desk.case.create'
        ) {
          return undefined;
        }
        const tenant = config.tenants.get(body.tenantId as TenantId);
        if (tenant === undefined) return [404, DESK_ERROR_BODY.not_found];
        const result = await recordApproval(deps, tenant, {
          userId: body.userId as WarifuUserId,
          changeRef: body.changeRef,
          requestId: body.requestId,
        });
        if (result.ok) {
          log.info({ event: 'company_api.desk_change_recorded' });
          return [200, JSON.stringify({ changeId: result.changeId })];
        }
        return result.reason === 'conflict'
          ? [409, DESK_ERROR_BODY.conflict]
          : [404, DESK_ERROR_BODY.not_found];
      }
      case 'status': {
        const body = objectWithKeys(value, ['userId', 'items']);
        if (
          body === undefined ||
          !isUuid(body.userId) ||
          !Array.isArray(body.items) ||
          body.items.length > DESK_LIMITS.statusItems
        ) {
          return undefined;
        }
        const items: { tenantId: TenantId; changeRef: string }[] = [];
        for (const raw of body.items) {
          const item = objectWithKeys(raw, ['tenantId', 'changeRef']);
          if (item === undefined || !isUuid(item.tenantId) || !isUuid(item.changeRef))
            return undefined;
          items.push({ tenantId: item.tenantId as TenantId, changeRef: item.changeRef });
        }
        const found = new Map<string, DeskStatusItem>();
        const byTenant = new Map<TenantId, string[]>();
        for (const item of items) {
          if (!config.tenants.has(item.tenantId)) continue;
          byTenant.set(item.tenantId, [...(byTenant.get(item.tenantId) ?? []), item.changeRef]);
        }
        for (const [tenantId, refs] of byTenant) {
          for (const [ref, status] of await statusOf(
            deps,
            tenantId,
            body.userId as WarifuUserId,
            refs,
          )) {
            found.set(`${tenantId}\u0000${ref}`, status);
          }
        }
        return [
          200,
          JSON.stringify({
            items: items.map(
              (item) =>
                found.get(`${item.tenantId}\u0000${item.changeRef}`) ?? {
                  changeRef: item.changeRef,
                  state: 'unknown',
                  cancelDeadline: null,
                },
            ),
          }),
        ];
      }
      case 'cancel': {
        const body = objectWithKeys(value, ['tenantId', 'userId', 'changeRef']);
        if (
          body === undefined ||
          !isUuid(body.tenantId) ||
          !isUuid(body.userId) ||
          !isUuid(body.changeRef)
        ) {
          return undefined;
        }
        const tenant = config.tenants.get(body.tenantId as TenantId);
        if (tenant === undefined) return [404, DESK_ERROR_BODY.not_found];
        const result = await acceptCancel(deps, tenant, {
          userId: body.userId as WarifuUserId,
          changeRef: body.changeRef,
        });
        if (result.ok) {
          log.info({ event: 'company_api.desk_cancel_accepted' });
          return [200, JSON.stringify({ state: result.state })];
        }
        return result.reason === 'closed'
          ? [409, DESK_ERROR_BODY.closed]
          : [404, DESK_ERROR_BODY.not_found];
      }
    }
  }

  const server: Server = createServer((req, res) => {
    (async () => {
      const op = opOf(req.method, req.url);
      if (op === undefined) {
        reply(res, 404, DESK_ERROR_BODY.not_found);
        return;
      }
      if (!authenticate(req.headers.authorization, options.credentials, dummy)) {
        reply(res, 401, DESK_ERROR_BODY.forbidden);
        return;
      }
      const raw = await readBody(req);
      let value: unknown;
      try {
        value = raw === undefined ? undefined : JSON.parse(raw.toString('utf8'));
      } catch {
        value = undefined;
      }
      const result = value === undefined ? undefined : await handle(op, value);
      if (result === undefined) {
        reply(res, 400, DESK_ERROR_BODY.invalid_request);
        return;
      }
      reply(res, result[0], result[1]);
    })().catch((err: unknown) => {
      log.error({ event: 'company_api.desk_internal_failed', err });
      if (!res.headersSent) reply(res, 503, DESK_ERROR_BODY.unavailable);
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
