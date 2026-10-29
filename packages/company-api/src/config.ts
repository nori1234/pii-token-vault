// company-api の登録簿（ADR 0010、ADR 0022）。配備のときの静的な設定で、起動の時点で検査する。
//
// - テナントの登録は DB に置かない。企業向けのルートからも、ほかのどのルートからも書き換えられない
//   （参加の状態を企業に書き換えさせない。ADR 0010、テスト6）。変えるのは、設定を直して配備し直すときだけ。
// - 参加の状態、移行中の期限、割符が確かめた入り口（と確かめた日）を、登録の形に持たせる（ADR 0010）。
//   M9 で利用者の画面に出せるようになるまでは、参加の状態は「完全な参加」（full）だけを受け付け、移行中の期限は
//   なし、確かめた入り口は空（すべて「まだ残っている入り口」）だけを受け付ける（ADR 0010、plan 10章 M5）。
// - 企業の鍵は jwks で受け取り、EC の P-256 の公開鍵に限る（不変条件7・9。jwks_uri は受け付けない）。
// - 緊急停止（suspended）は、トークンの発行、企業向け API、SET の送信を止める（plan 2章。ADR 0022）。
// - クライアントごとに、出してよいテナントの JWT の scope を決める（既定は company_api だけ。窓口の desk は
//   ADR 0026 の O-65）。

import { parseTenantId, type TenantId } from '@pii-token-vault/warifu-core';

export interface PublicEcJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly kid?: string;
  readonly alg?: 'ES256';
  readonly use?: 'sig';
}

/** テナントの JWT の scope。company_api：別名の入れ替えと検証の SET（ADR 0022）。desk：窓口（ADR 0026）。 */
export type TokenScope = 'company_api' | 'desk';
export const TOKEN_SCOPES: readonly TokenScope[] = Object.freeze(['company_api', 'desk']);

export interface ApiClient {
  readonly clientId: string;
  readonly jwks: { readonly keys: readonly PublicEcJwk[] };
  /** このクライアントに出してよい scope（1つ以上）。 */
  readonly scopes: readonly TokenScope[];
}

export interface CompanyTenant {
  readonly tenantId: TenantId;
  /** 別名の右側（relay がこのテナントの別名を受け取るドメイン）。テナントごとに分ける（不変条件5）。 */
  readonly relayDomain: string;
  /** 参加の状態。P0（M9 まで）は full だけ（ADR 0010）。 */
  readonly participation: 'full';
  /** 移行中の期限。M9 までは null だけ（ADR 0010）。 */
  readonly migrationDeadline: null;
  /** 割符が確かめた入り口と確かめた日。登録の時点では空。M9 までは空だけ（ADR 0010）。 */
  readonly verifiedEntries: readonly never[];
  /** 緊急停止。true なら、トークンを出さず、API を断り、SET を送らない。 */
  readonly suspended: boolean;
  readonly apiClients: readonly ApiClient[];
  /** SET の受け口（RFC 8935）。https、443。宛先の検査は sender が送るたびに行う（RP-51）。 */
  readonly webhookUrl?: string;
}

export interface CompanyApiConfig {
  /** company-api の発行者（トークンの iss と aud、client assertion の aud の元）。正規化した origin。 */
  readonly issuer: string;
  readonly tenants: ReadonlyMap<TenantId, CompanyTenant>;
  /** client_id → テナント。client_id は全テナントで一意。 */
  readonly clients: ReadonlyMap<
    string,
    { readonly tenant: CompanyTenant; readonly client: ApiClient }
  >;
}

export class CompanyApiConfigError extends Error {
  override name = 'CompanyApiConfigError';
}

const TENANT_KEYS: ReadonlySet<string> = new Set([
  'tenantId',
  'relayDomain',
  'participation',
  'migrationDeadline',
  'verifiedEntries',
  'suspended',
  'apiClients',
  'webhookUrl',
]);
const CLIENT_KEYS: ReadonlySet<string> = new Set(['clientId', 'jwks', 'scopes']);
const JWK_MEMBERS: ReadonlySet<string> = new Set(['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use']);
const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const DOMAIN_PATTERN =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>, what: string) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key))
      throw new CompanyApiConfigError(`${what}：許可していない項目がある（${key}）`);
  }
}

function parseJwk(clientId: string, input: unknown): PublicEcJwk {
  if (!isRecord(input))
    throw new CompanyApiConfigError(`${clientId}：jwks の鍵がオブジェクトではない`);
  onlyKeys(input, JWK_MEMBERS, `${clientId}：jwks の鍵`);
  if (
    input.kty !== 'EC' ||
    input.crv !== 'P-256' ||
    typeof input.x !== 'string' ||
    !COORDINATE_PATTERN.test(input.x) ||
    typeof input.y !== 'string' ||
    !COORDINATE_PATTERN.test(input.y) ||
    (input.alg !== undefined && input.alg !== 'ES256') ||
    (input.use !== undefined && input.use !== 'sig') ||
    (input.kid !== undefined && (typeof input.kid !== 'string' || !KID_PATTERN.test(input.kid)))
  ) {
    throw new CompanyApiConfigError(`${clientId}：jwks の鍵は ES256（EC の P-256）の公開鍵だけ`);
  }
  return Object.freeze({ ...input }) as unknown as PublicEcJwk;
}

function parseClient(input: unknown): ApiClient {
  if (!isRecord(input)) throw new CompanyApiConfigError('クライアントがオブジェクトではない');
  const clientId = typeof input.clientId === 'string' ? input.clientId : '';
  if (!CLIENT_ID_PATTERN.test(clientId)) throw new CompanyApiConfigError('client_id の形が違う');
  // jwks_uri など、割符から外へ取りに行く項目は、肯定リスト（CLIENT_KEYS）で止まる（不変条件7）。
  onlyKeys(input, CLIENT_KEYS, clientId);
  if (!isRecord(input.jwks) || !Array.isArray(input.jwks.keys)) {
    throw new CompanyApiConfigError(`${clientId}：jwks がない`);
  }
  onlyKeys(input.jwks, new Set(['keys']), `${clientId}：jwks`);
  if (input.jwks.keys.length < 1 || input.jwks.keys.length > 4) {
    throw new CompanyApiConfigError(`${clientId}：jwks の鍵は1〜4個`);
  }
  const keys = input.jwks.keys.map((jwk) => parseJwk(clientId, jwk));
  const scopes = input.scopes ?? ['company_api'];
  if (
    !Array.isArray(scopes) ||
    scopes.length < 1 ||
    !scopes.every((scope) => (TOKEN_SCOPES as readonly unknown[]).includes(scope)) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw new CompanyApiConfigError(
      `${clientId}：scopes は company_api と desk から1つ以上（重複なし）`,
    );
  }
  return Object.freeze({
    clientId,
    jwks: Object.freeze({ keys: Object.freeze(keys) }),
    scopes: Object.freeze([...scopes] as TokenScope[]),
  });
}

function parseWebhookUrl(tenantId: string, value: unknown): string {
  let url: URL;
  try {
    url = new URL(String(value));
  } catch {
    throw new CompanyApiConfigError(`${tenantId}：webhookUrl が URL ではない`);
  }
  if (
    url.protocol !== 'https:' ||
    (url.port !== '' && url.port !== '443') ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    url.href !== value ||
    url.href.length > 2048
  ) {
    throw new CompanyApiConfigError(
      `${tenantId}：webhookUrl は https で 443 番だけ（正規化した形、利用者情報とフラグメントなし）`,
    );
  }
  return url.href;
}

function parseTenant(input: unknown): CompanyTenant {
  if (!isRecord(input)) throw new CompanyApiConfigError('テナントがオブジェクトではない');
  onlyKeys(input, TENANT_KEYS, 'テナント');
  const tenantId = parseTenantId(String(input.tenantId));
  if (input.participation !== 'full') {
    throw new CompanyApiConfigError(
      '参加の状態は full だけ（移行中の参加は、M9 で表示ができるまで登録できない。ADR 0010）',
    );
  }
  if (input.migrationDeadline !== undefined && input.migrationDeadline !== null) {
    throw new CompanyApiConfigError(
      '移行中の期限は、M9 で表示ができるまで登録できない（ADR 0010）',
    );
  }
  if (
    input.verifiedEntries !== undefined &&
    !(Array.isArray(input.verifiedEntries) && input.verifiedEntries.length === 0)
  ) {
    throw new CompanyApiConfigError(
      '割符が確かめた入り口は、登録の時点では空（M9 で表示ができるまで。ADR 0010）',
    );
  }
  if (typeof input.relayDomain !== 'string' || !DOMAIN_PATTERN.test(input.relayDomain)) {
    throw new CompanyApiConfigError('テナントの relay ドメインの形が違う');
  }
  if (input.suspended !== undefined && typeof input.suspended !== 'boolean') {
    throw new CompanyApiConfigError('suspended は真偽値');
  }
  if (
    !Array.isArray(input.apiClients) ||
    input.apiClients.length < 1 ||
    input.apiClients.length > 4
  ) {
    throw new CompanyApiConfigError('apiClients は1〜4個');
  }
  const apiClients = Object.freeze(input.apiClients.map(parseClient));
  return Object.freeze({
    tenantId,
    relayDomain: input.relayDomain,
    participation: 'full',
    migrationDeadline: null,
    verifiedEntries: Object.freeze([]) as readonly never[],
    suspended: input.suspended === true,
    apiClients,
    ...(input.webhookUrl === undefined
      ? {}
      : { webhookUrl: parseWebhookUrl(tenantId, input.webhookUrl) }),
  });
}

/** 設定を検査して登録簿にする。1つでも違えば、起動させない。 */
export function parseCompanyApiConfig(input: {
  readonly issuer: unknown;
  readonly tenants: unknown;
}): CompanyApiConfig {
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(String(input.issuer));
  } catch {
    throw new CompanyApiConfigError('issuer が URL ではない');
  }
  const local = issuerUrl.hostname === 'localhost' || issuerUrl.hostname === '127.0.0.1';
  if (
    issuerUrl.origin !== input.issuer ||
    !(issuerUrl.protocol === 'https:' || (issuerUrl.protocol === 'http:' && local))
  ) {
    throw new CompanyApiConfigError(
      'issuer は正規化した https の origin（開発では http://localhost）',
    );
  }
  if (!Array.isArray(input.tenants)) throw new CompanyApiConfigError('tenants は配列');
  const tenants = new Map<TenantId, CompanyTenant>();
  const clients = new Map<string, { tenant: CompanyTenant; client: ApiClient }>();
  const relayDomains = new Set<string>();
  for (const raw of input.tenants) {
    const tenant = parseTenant(raw);
    if (tenants.has(tenant.tenantId)) throw new CompanyApiConfigError('テナント ID が重複している');
    if (relayDomains.has(tenant.relayDomain)) {
      throw new CompanyApiConfigError('relay ドメインが重複している');
    }
    tenants.set(tenant.tenantId, tenant);
    relayDomains.add(tenant.relayDomain);
    for (const client of tenant.apiClients) {
      if (clients.has(client.clientId)) throw new CompanyApiConfigError('client_id が重複している');
      clients.set(client.clientId, { tenant, client });
    }
  }
  return Object.freeze({ issuer: issuerUrl.origin, tenants, clients });
}
