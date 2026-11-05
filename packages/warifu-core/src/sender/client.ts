// 送信サービスの内部 API のクライアント（不変条件7、ADR 0022）。
// - company-api は Webhook の口だけ、relay は配送と名前解決の口だけを持つ（型にほかの口のメソッドがない）。
// - 資格情報は `<呼び出し元>.<32バイトの base64url>`。工場関数は、呼び出し元の部分が自分と一致することを確かめる。
// - 再試行はしない（呼び出し元が決める）。応答の本文を例外に入れない（不変条件4）。

import { UdsError, udsPost } from '../internal/uds-client.ts';
import {
  DNS_ERROR_CODES,
  DNS_TYPES,
  type DnsErrorCode,
  type DnsRecords,
  type DnsType,
  type MailRequest,
  SENDER_LIMITS,
  SENDER_PATHS,
  SENDER_REJECT_REASONS,
  SET_TIME_ERRORS,
  type SenderCaller,
  type SenderOp,
  type SenderRejectReason,
  type SetTimeError,
} from './protocol.ts';

export type SenderClientErrorCode = 'invalid_request' | 'forbidden' | 'unavailable';

export class SenderClientError extends Error {
  readonly code: SenderClientErrorCode;

  constructor(code: SenderClientErrorCode) {
    super('送信サービスの内部 API の呼び出しが失敗した');
    this.name = 'SenderClientError';
    this.code = code;
  }
}

export interface SenderConnection {
  readonly socketPath: string;
  /** `<呼び出し元>.<32バイトの base64url>`。 */
  readonly credential: string;
}

export type SendResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: SenderRejectReason };

/** Webhook の結果。受け口が応答したときは、そのステータス（と、400 の SET の時刻の失敗）も返す（ADR 0026）。 */
export type WebhookResult =
  | { readonly ok: true; readonly status: number }
  | {
      readonly ok: false;
      readonly reason: SenderRejectReason;
      readonly status?: number;
      readonly setError?: SetTimeError;
    };

export type DnsResult =
  | { readonly ok: true; readonly records: DnsRecords }
  | { readonly ok: false; readonly code: DnsErrorCode };

export interface SenderWebhookClient {
  /** SET を Webhook に送る。宛先の検査は sender が行う。 */
  postSet(input: { readonly url: string; readonly set: string }): Promise<WebhookResult>;
}

export interface SenderMailClient {
  sendMail(input: MailRequest): Promise<SendResult>;
  resolveDns(name: string, type: DnsType): Promise<DnsResult>;
}

const encoder = new TextEncoder();

function transport(connection: SenderConnection, caller: SenderCaller) {
  const credential = connection?.credential;
  const pattern = new RegExp(`^${caller.replace('-', '\\-')}\\.[A-Za-z0-9_-]{43}$`);
  if (typeof credential !== 'string' || !pattern.test(credential)) {
    throw new SenderClientError('forbidden');
  }
  const socketPath = connection.socketPath;
  return async (op: SenderOp, body: Record<string, string>): Promise<Record<string, unknown>> => {
    let response: { status: number; body: Uint8Array };
    try {
      response = await udsPost({
        socketPath,
        path: SENDER_PATHS[op],
        headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' },
        body: encoder.encode(JSON.stringify(body)),
        timeoutMs: SENDER_LIMITS.clientTimeoutMs[op],
        maxResponseBytes: SENDER_LIMITS.responseBodyBytes,
      });
    } catch (error) {
      if (error instanceof UdsError) throw new SenderClientError('unavailable');
      throw error;
    }
    if (response.status === 400) throw new SenderClientError('invalid_request');
    if (response.status === 401 || response.status === 403)
      throw new SenderClientError('forbidden');
    if (response.status !== 200) throw new SenderClientError('unavailable');
    try {
      const parsed: unknown = JSON.parse(Buffer.from(response.body).toString('utf8'));
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // 下で unavailable にする。
    }
    throw new SenderClientError('unavailable');
  };
}

function sendResultOf(value: Record<string, unknown>): SendResult {
  if (value.ok === true) return { ok: true };
  if (
    value.ok === false &&
    typeof value.reason === 'string' &&
    (SENDER_REJECT_REASONS as readonly string[]).includes(value.reason)
  ) {
    return { ok: false, reason: value.reason as SenderRejectReason };
  }
  throw new SenderClientError('unavailable');
}

function isHttpStatus(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599;
}

function webhookResultOf(value: Record<string, unknown>): WebhookResult {
  if (value.ok === true && isHttpStatus(value.status) && value.status < 300) {
    return { ok: true, status: value.status };
  }
  const base = sendResultOf(value);
  if (base.ok) throw new SenderClientError('unavailable');
  if (value.status !== undefined && !isHttpStatus(value.status)) {
    throw new SenderClientError('unavailable');
  }
  if (
    value.setError !== undefined &&
    !(
      typeof value.setError === 'string' && SET_TIME_ERRORS.includes(value.setError as SetTimeError)
    )
  ) {
    throw new SenderClientError('unavailable');
  }
  return {
    ok: false,
    reason: base.reason,
    ...(value.status === undefined ? {} : { status: value.status as number }),
    ...(value.setError === undefined ? {} : { setError: value.setError as SetTimeError }),
  };
}

export function createSenderWebhookClient(connection: SenderConnection): SenderWebhookClient {
  const call = transport(connection, 'company-api');
  return Object.freeze({
    async postSet(input: { readonly url: string; readonly set: string }): Promise<WebhookResult> {
      if (typeof input?.url !== 'string' || typeof input.set !== 'string') {
        throw new SenderClientError('invalid_request');
      }
      return webhookResultOf(await call('webhook', { url: input.url, set: input.set }));
    },
  });
}

export function createSenderMailClient(connection: SenderConnection): SenderMailClient {
  const call = transport(connection, 'relay');
  return Object.freeze({
    async sendMail(input: MailRequest): Promise<SendResult> {
      if (
        typeof input?.mailFrom !== 'string' ||
        typeof input.rcptTo !== 'string' ||
        typeof input.raw !== 'string'
      ) {
        throw new SenderClientError('invalid_request');
      }
      return sendResultOf(
        await call('mail', { mailFrom: input.mailFrom, rcptTo: input.rcptTo, raw: input.raw }),
      );
    },
    async resolveDns(name: string, type: DnsType): Promise<DnsResult> {
      if (typeof name !== 'string' || !DNS_TYPES.includes(type)) {
        throw new SenderClientError('invalid_request');
      }
      const value = await call('dns', { name, type });
      if (value.ok === true && Array.isArray(value.records)) {
        return { ok: true, records: value.records as DnsRecords };
      }
      if (
        value.ok === false &&
        typeof value.code === 'string' &&
        (DNS_ERROR_CODES as readonly string[]).includes(value.code)
      ) {
        return { ok: false, code: value.code as DnsErrorCode };
      }
      throw new SenderClientError('unavailable');
    },
  });
}
