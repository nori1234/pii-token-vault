// 割符の内部の ID の型。テナント ID と利用者 ID は、小文字の UUID だけを受け付ける。
// 入力をそのまま境界の値に使う誤り（SQL インジェクションなど）を、DB に届く前に止める。

import { randomUuid } from './random.ts';

export type ServiceName = 'idp' | 'relay' | 'company-api';
export type Component = ServiceName | 'keysvc' | 'sender';

/** サービスごとの DB のログインロール（ADR 0014）。 */
export const SERVICE_ROLE: Readonly<Record<ServiceName, string>> = Object.freeze({
  idp: 'warifu_idp',
  relay: 'warifu_relay',
  'company-api': 'warifu_company_api',
});

export type TenantId = string & { readonly __brand: 'TenantId' };
export type WarifuUserId = string & { readonly __brand: 'WarifuUserId' };

// RFC 9562 の形（version 1〜8、variant 10xx）。大文字は受け付けない（同じ値の書き方を1つにする）。
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** ID の形が違うときの例外。メッセージに値を入れない（不変条件4）。 */
export class InvalidIdError extends Error {
  constructor() {
    super('ID の形が違う');
    this.name = 'InvalidIdError';
  }
}

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function parseTenantId(value: string): TenantId {
  if (!isUuid(value)) throw new InvalidIdError();
  return value as TenantId;
}

export function parseWarifuUserId(value: string): WarifuUserId {
  if (!isUuid(value)) throw new InvalidIdError();
  return value as WarifuUserId;
}

export function newTenantId(): TenantId {
  return parseTenantId(randomUuid());
}

export function newWarifuUserId(): WarifuUserId {
  return parseWarifuUserId(randomUuid());
}

/** UUID の16バイト。MAC にかける入力を、文字列の書き方によらず同じにするために使う。 */
export function uuidBytes(value: string): Uint8Array {
  if (!isUuid(value)) throw new InvalidIdError();
  return new Uint8Array(Buffer.from(value.replaceAll('-', ''), 'hex'));
}
