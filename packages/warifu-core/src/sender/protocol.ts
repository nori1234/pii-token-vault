// 送信サービス（packages/sender）の内部 API の約束（不変条件7、CAP-20〜26・38、ADR 0022）。
// 呼び出し元（relay、company-api）と sender が共有する。
//
// - Unix ドメインソケットの HTTP。資格情報は `Authorization: Bearer <呼び出し元>.<32バイトの base64url>`。
// - 呼び出し元ごとに呼べる口を決める（SENDER_ACL）。relay は配送と名前解決、company-api は Webhook だけ。
// - 宛先の検査（https、443、公開の IP、固定した IP への接続、リダイレクトに従わない、上限）は sender の中で行い、
//   呼び出し元から外せない。

/** sender の内部 API のソケットのファイル名。 */
export const SENDER_SOCKET_NAME = 'sender.sock';

export type SenderOp = 'webhook' | 'mail' | 'dns';
export const SENDER_PATHS: Readonly<Record<SenderOp, string>> = Object.freeze({
  webhook: '/v1/webhook',
  mail: '/v1/mail',
  dns: '/v1/dns',
});

/** sender を呼べるサービス。idp、keysvc は呼べない（CAP-38）。 */
export type SenderCaller = 'relay' | 'company-api';
export const SENDER_CALLERS: readonly SenderCaller[] = Object.freeze(['relay', 'company-api']);

/** 呼び出し元ごとに呼べる口。この1か所に書く（ADR 0022）。 */
export const SENDER_ACL: Readonly<Record<SenderCaller, readonly SenderOp[]>> = Object.freeze({
  relay: Object.freeze(['mail', 'dns'] as const),
  'company-api': Object.freeze(['webhook'] as const),
});

/** SET を企業の Webhook に送る（RFC 8935 の push）。本文は compact の JWS で、content-type は固定。 */
export interface WebhookRequest {
  readonly url: string;
  readonly set: string;
}

/**
 * 受け口が 400 で返した、SET の時刻だけの失敗（割符の受信の規則の補足。RFC 8935 の err は invalid_request。
 * ADR 0026 の O-67）。sender は本文の err と warifu_reason だけを読み、description は読まない。
 */
export type SetTimeError = 'set_too_old' | 'iat_in_future';
export const SET_TIME_ERRORS: readonly SetTimeError[] = Object.freeze([
  'set_too_old',
  'iat_in_future',
]);

/** 署名と封印を付けたメッセージを、宛先のドメインの MX に送る。raw は base64。 */
export interface MailRequest {
  readonly mailFrom: string;
  readonly rcptTo: string;
  readonly raw: string;
}

/** relay の返信の DMARC の判定に使う名前解決（mailauth の resolver の形）。 */
export type DnsType = 'TXT' | 'MX' | 'A' | 'AAAA';
export const DNS_TYPES: readonly DnsType[] = Object.freeze(['TXT', 'MX', 'A', 'AAAA']);
export interface DnsRequest {
  readonly name: string;
  readonly type: DnsType;
}
export type DnsRecords = readonly (readonly string[])[] | readonly string[] | readonly MxRecord[];
export interface MxRecord {
  readonly exchange: string;
  readonly priority: number;
}

/** 送れなかった理由。値（URL、宛先、IP）は入れない。 */
export type SenderRejectReason =
  | 'invalid_destination'
  | 'blocked_address'
  | 'no_address'
  | 'dns_failed'
  | 'connect_failed'
  | 'timeout'
  | 'redirect'
  | 'http_status'
  | 'too_large'
  | 'null_mx'
  | 'smtp_rejected'
  | 'smtp_failed';
export const SENDER_REJECT_REASONS: readonly SenderRejectReason[] = Object.freeze([
  'invalid_destination',
  'blocked_address',
  'no_address',
  'dns_failed',
  'connect_failed',
  'timeout',
  'redirect',
  'http_status',
  'too_large',
  'null_mx',
  'smtp_rejected',
  'smtp_failed',
]);

/** 名前解決の失敗の種類（node:dns と mailauth が使う code）。 */
export type DnsErrorCode = 'ENOTFOUND' | 'ENODATA' | 'ETIMEOUT' | 'ESERVFAIL' | 'EBADNAME';
export const DNS_ERROR_CODES: readonly DnsErrorCode[] = Object.freeze([
  'ENOTFOUND',
  'ENODATA',
  'ETIMEOUT',
  'ESERVFAIL',
  'EBADNAME',
]);

export const SENDER_LIMITS = Object.freeze({
  /** 要求の本文。mail は 10 MiB のメッセージの base64 と封筒が入る大きさ。 */
  requestBodyBytes: Object.freeze({ webhook: 16_384, mail: 14_680_064, dns: 1024 }),
  /** SET の compact の JWS。 */
  setBytes: 8192,
  /** 配送するメッセージ（relay の SMTP の受け口と同じ 10 MiB）。 */
  rawMessageBytes: 10 * 1024 * 1024,
  responseBodyBytes: 65_536,
  clientTimeoutMs: Object.freeze({ webhook: 20_000, mail: 120_000, dns: 8000 }),
} as const);

/** エラーの本文。理由によらず、同じ種類のエラーはバイト単位で同じ本文にする。 */
export const SENDER_ERROR_BODY = Object.freeze({
  forbidden: '{"error":"forbidden"}',
  invalid_request: '{"error":"invalid_request"}',
  unavailable: '{"error":"unavailable"}',
  not_found: '{"error":"not_found"}',
} as const);
