// 静的な登録簿（M3）。テナントとクライアントを設定で受け取り、起動の時点で検査する（ADR 0018）。
// company-api の登録も静的な設定にした（ADR 0022）。1つの登録簿にまとめるかは M9 で決める。
//
// - 不変条件7：割符から外へ取りに行く項目（jwks_uri、sector_identifier_uri、request_uris など）は、肯定リストで止める。
//   oidc-provider 9.12.2 は、認識した項目をそのまま受け入れる（lib/helpers/client_schema.js）。
// - 不変条件9：企業のクライアント認証と ID トークンの署名は ES256 だけ。企業の鍵は jwks で受け取り、P-256 の公開鍵に限る。
// - 不変条件5：sub はテナント単位の pairwise。sector_identifier_uri を使わないので、redirect_uris のホストは1つに限る
//   （oidc-provider は、ホストが複数の pairwise のクライアントに sector_identifier_uri を求めるため）。
// - DESIGN.md 原則2：画面に出す企業名は、この登録簿の値（displayName）だけ。企業が送る client_name などは使わない。
// - 窓口の操作は、クライアントごとに許す（deskActions。既定は空で、窓口の申請を受け付けない。ADR 0026 の O-60）。

import { parseTenantId, type TenantId } from '@pii-token-vault/warifu-core';
import { DESK_ACTIONS, type DeskAction } from '@pii-token-vault/warifu-core/desk/protocol';

export interface TenantEntry {
  readonly tenantId: TenantId;
  /** 画面に出す企業名。テキストとしてだけ描画する。 */
  readonly displayName: string;
  /** relay がこのテナントの別名を受け取るドメイン（別名の右側）。テナントごとに分ける（不変条件5）。 */
  readonly relayDomain: string;
}

export interface PublicEcJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly kid?: string;
  readonly alg?: 'ES256';
  readonly use?: 'sig';
}

/** 別名を、email クレーム（email_verified は常に false）と独自クレーム contact_alias のどちらで渡すか。 */
export type AliasClaim = 'email' | 'contact_alias';

export interface ClientEntry {
  readonly clientId: string;
  readonly tenantId: TenantId;
  readonly redirectUris: readonly string[];
  readonly jwks: { readonly keys: readonly PublicEcJwk[] };
  readonly aliasClaim: AliasClaim;
  /** このクライアントに許す窓口の操作（DESIGN.md 3章の3つから）。空なら、窓口の申請を受け付けない。 */
  readonly deskActions: readonly DeskAction[];
}

export interface Registry {
  readonly tenants: ReadonlyMap<TenantId, TenantEntry>;
  readonly clients: ReadonlyMap<string, ClientEntry>;
}

export class RegistryError extends Error {
  override name = 'RegistryError';
}

/** oidc-provider が外へ取りに行く（または外へ送る）クライアントの項目。provider.ts の validator でも拒否する。 */
export const OUTBOUND_CLIENT_METADATA: readonly string[] = Object.freeze([
  'jwks_uri',
  'sector_identifier_uri',
  'request_uris',
  'backchannel_client_notification_endpoint',
  'backchannel_logout_uri',
  'logo_uri',
  'policy_uri',
  'tos_uri',
  'client_uri',
  'initiate_login_uri',
]);

const TENANT_KEYS: ReadonlySet<string> = new Set(['tenantId', 'displayName', 'relayDomain']);
const CLIENT_KEYS: ReadonlySet<string> = new Set([
  'clientId',
  'tenantId',
  'redirectUris',
  'jwks',
  'aliasClaim',
  'deskActions',
]);
const JWK_MEMBERS: ReadonlySet<string> = new Set(['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use']);
const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
// 小文字の DNS 名（ラベルは63文字まで、全体で253文字まで）。
const DOMAIN_PATTERN =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
// 制御文字と、書式を変える文字（双方向の制御など）を含めない。
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function onlyKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  what: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new RegistryError(`${what}：許可していない項目がある（${key}）`);
  }
}

function parseTenant(input: unknown): TenantEntry {
  if (!isRecord(input)) throw new RegistryError('テナントがオブジェクトではない');
  onlyKeys(input, TENANT_KEYS, 'テナント');
  const tenantId = parseTenantId(String(input.tenantId));
  const displayName = input.displayName;
  if (
    typeof displayName !== 'string' ||
    displayName.trim() !== displayName ||
    displayName.length < 1 ||
    displayName.length > 64 ||
    UNSAFE_TEXT.test(displayName)
  ) {
    throw new RegistryError('テナントの表示名の形が違う');
  }
  if (typeof input.relayDomain !== 'string' || !DOMAIN_PATTERN.test(input.relayDomain)) {
    throw new RegistryError('テナントの relay ドメインの形が違う');
  }
  return Object.freeze({ tenantId, displayName, relayDomain: input.relayDomain });
}

function parseJwk(clientId: string, input: unknown): PublicEcJwk {
  if (!isRecord(input)) throw new RegistryError(`${clientId}：jwks の鍵がオブジェクトではない`);
  // d（秘密鍵）、x5u（外の URL）、x5c などは受け付けない。
  onlyKeys(input, JWK_MEMBERS, `${clientId}：jwks の鍵`);
  if (input.kty !== 'EC' || input.crv !== 'P-256') {
    throw new RegistryError(`${clientId}：jwks の鍵は EC の P-256 だけ`);
  }
  if (
    typeof input.x !== 'string' ||
    !COORDINATE_PATTERN.test(input.x) ||
    typeof input.y !== 'string' ||
    !COORDINATE_PATTERN.test(input.y)
  ) {
    throw new RegistryError(`${clientId}：jwks の鍵の x と y の形が違う`);
  }
  if (input.alg !== undefined && input.alg !== 'ES256') {
    throw new RegistryError(`${clientId}：jwks の鍵の alg は ES256 だけ`);
  }
  if (input.use !== undefined && input.use !== 'sig') {
    throw new RegistryError(`${clientId}：jwks の鍵の use は sig だけ`);
  }
  if (input.kid !== undefined && (typeof input.kid !== 'string' || !KID_PATTERN.test(input.kid))) {
    throw new RegistryError(`${clientId}：jwks の鍵の kid の形が違う`);
  }
  return Object.freeze({ ...input }) as unknown as PublicEcJwk;
}

/** https だけ。ただし開発用に http://localhost と http://127.0.0.1 を許す。フラグメント、資格情報、ワイルドカードは不可。 */
function parseRedirectUri(clientId: string, value: unknown): URL {
  if (typeof value !== 'string' || value.length > 512) {
    throw new RegistryError(`${clientId}：redirect_uris の形が違う`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RegistryError(`${clientId}：redirect_uris が URL ではない`);
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new RegistryError(`${clientId}：redirect_uris は https（開発では http://localhost）だけ`);
  }
  if (url.hash !== '' || url.username !== '' || url.password !== '' || value.includes('*')) {
    throw new RegistryError(
      `${clientId}：redirect_uris にフラグメント、資格情報、ワイルドカードを含めない`,
    );
  }
  if (url.href !== value) {
    throw new RegistryError(`${clientId}：redirect_uris は正規化した形で書く`);
  }
  return url;
}

function parseClient(input: unknown, tenants: ReadonlyMap<TenantId, TenantEntry>): ClientEntry {
  if (!isRecord(input)) throw new RegistryError('クライアントがオブジェクトではない');
  const clientId = typeof input.clientId === 'string' ? input.clientId : '';
  if (!CLIENT_ID_PATTERN.test(clientId)) throw new RegistryError('client_id の形が違う');
  for (const name of OUTBOUND_CLIENT_METADATA) {
    if (Object.hasOwn(input, name)) throw new RegistryError(`${clientId}：${name} は受け付けない`);
  }
  onlyKeys(input, CLIENT_KEYS, clientId);
  const tenantId = parseTenantId(String(input.tenantId));
  if (!tenants.has(tenantId)) throw new RegistryError(`${clientId}：テナントが登録簿にない`);

  if (
    !Array.isArray(input.redirectUris) ||
    input.redirectUris.length < 1 ||
    input.redirectUris.length > 8
  ) {
    throw new RegistryError(`${clientId}：redirect_uris は1〜8個`);
  }
  const urls = input.redirectUris.map((uri) => parseRedirectUri(clientId, uri));
  if (new Set(urls.map((url) => url.host)).size !== 1) {
    throw new RegistryError(
      `${clientId}：redirect_uris のホストは1つだけ（sector_identifier_uri を使わないため）`,
    );
  }

  if (!isRecord(input.jwks) || !Array.isArray(input.jwks.keys)) {
    throw new RegistryError(`${clientId}：jwks がない`);
  }
  onlyKeys(input.jwks, new Set(['keys']), `${clientId}：jwks`);
  if (input.jwks.keys.length < 1 || input.jwks.keys.length > 4) {
    throw new RegistryError(`${clientId}：jwks の鍵は1〜4個`);
  }
  const keys = input.jwks.keys.map((jwk) => parseJwk(clientId, jwk));

  const aliasClaim = input.aliasClaim ?? 'email';
  if (aliasClaim !== 'email' && aliasClaim !== 'contact_alias') {
    throw new RegistryError(`${clientId}：aliasClaim は email か contact_alias`);
  }
  const deskActions = input.deskActions ?? [];
  if (
    !Array.isArray(deskActions) ||
    !deskActions.every((action) => (DESK_ACTIONS as readonly unknown[]).includes(action)) ||
    new Set(deskActions).size !== deskActions.length
  ) {
    throw new RegistryError(`${clientId}：deskActions は窓口の操作の一覧から（重複なし）`);
  }
  return Object.freeze({
    clientId,
    tenantId,
    redirectUris: Object.freeze(urls.map((url) => url.href)),
    jwks: Object.freeze({ keys: Object.freeze(keys) }),
    aliasClaim,
    deskActions: Object.freeze([...deskActions] as DeskAction[]),
  });
}

/** 設定を検査して登録簿にする。1つでも違えば、起動させない。 */
export function parseRegistry(input: {
  readonly tenants: unknown;
  readonly clients: unknown;
}): Registry {
  if (!Array.isArray(input.tenants) || !Array.isArray(input.clients)) {
    throw new RegistryError('tenants と clients は配列');
  }
  const tenants = new Map<TenantId, TenantEntry>();
  const relayDomains = new Set<string>();
  for (const raw of input.tenants) {
    const tenant = parseTenant(raw);
    if (tenants.has(tenant.tenantId)) throw new RegistryError('テナント ID が重複している');
    // 別名のドメインは、テナントごとに独立させる（不変条件5。relay の送信元のサブドメインと同じ考え方）。
    if (relayDomains.has(tenant.relayDomain))
      throw new RegistryError('relay ドメインが重複している');
    tenants.set(tenant.tenantId, tenant);
    relayDomains.add(tenant.relayDomain);
  }
  const clients = new Map<string, ClientEntry>();
  for (const raw of input.clients) {
    const client = parseClient(raw, tenants);
    if (clients.has(client.clientId)) throw new RegistryError('client_id が重複している');
    clients.set(client.clientId, client);
  }
  return Object.freeze({ tenants, clients });
}
