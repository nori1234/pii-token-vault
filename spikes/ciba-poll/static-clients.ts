// 捨てスパイク2：テナントの登録簿と、静的なクライアントの設定の事前検査。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
//
// 不変条件7：割符から外へ取りに行く値（jwks_uri、sector_identifier_uri、request_uris など）は、
// oidc-provider に渡す前に拒否する。oidc-provider 9.12.2 には、これらの項目を受け付けない設定がない
// （lib/helpers/client_schema.js は、認識した項目をそのまま受け入れる）。そこで、許す項目を肯定リストで決める。
// 不変条件9：企業のクライアント認証と ID トークンの署名は ES256 だけ。企業の鍵は jwks で受け取り、P-256 に限る。

export const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

export interface Tenant {
  readonly tenantId: string;
  /** 承認画面に出す企業名。割符の登録簿の値だけを使い、企業が送った値（client_name など）は使わない。 */
  readonly displayName: string;
}

export type TenantRegistry = ReadonlyMap<string, Tenant>;

export interface PublicEcJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly kid?: string;
  readonly alg?: 'ES256';
  readonly use?: 'sig';
}

export interface StaticClientMetadata {
  readonly client_id: string;
  readonly tenant_id: string;
  readonly jwks: { readonly keys: readonly PublicEcJwk[] };
  readonly grant_types: readonly string[];
  readonly response_types: readonly string[];
  readonly redirect_uris: readonly string[];
  readonly token_endpoint_auth_method: 'private_key_jwt';
  readonly token_endpoint_auth_signing_alg: 'ES256';
  readonly id_token_signed_response_alg: 'ES256';
  readonly backchannel_token_delivery_mode: 'poll';
}

/**
 * oidc-provider が外へ取りに行く（または外へ送る）クライアントの項目。
 * lib/models/client.js（jwks_uri、backchannel_client_notification_endpoint、backchannel_logout_uri）と
 * lib/helpers/sector_validate.js（sector_identifier_uri）で fetch を呼ぶ。request_uris は、要求オブジェクトを
 * 外から取る経路の登録値。二重の守りとして、Provider の extraClientMetadata.validator でもこの一覧を拒否する。
 */
export const OUTBOUND_CLIENT_METADATA: readonly string[] = [
  'jwks_uri',
  'sector_identifier_uri',
  'request_uris',
  'backchannel_client_notification_endpoint',
  'backchannel_logout_uri',
];

const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'client_id',
  'tenant_id',
  'jwks',
  'grant_types',
  'response_types',
  'redirect_uris',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'id_token_signed_response_alg',
  'backchannel_token_delivery_mode',
]);

const ALLOWED_JWK_MEMBERS: ReadonlySet<string> = new Set([
  'kty',
  'crv',
  'x',
  'y',
  'kid',
  'alg',
  'use',
]);

// sub の導出で `tenant_id + ':' + 利用者 ID` をつなぐので、tenant_id に ':' を含めない。
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

export class StaticClientError extends Error {
  override name = 'StaticClientError';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sameStrings(value: unknown, expected: readonly string[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
}

function assertPublicEcJwk(clientId: string, jwk: unknown): PublicEcJwk {
  if (!isRecord(jwk)) {
    throw new StaticClientError(`${clientId}：jwks の鍵がオブジェクトではない`);
  }
  for (const member of Object.keys(jwk)) {
    // d（秘密鍵）、x5u（外の URL）、x5c などは受け付けない。
    if (!ALLOWED_JWK_MEMBERS.has(member)) {
      throw new StaticClientError(
        `${clientId}：jwks の鍵に、許可していない項目がある（${member}）`,
      );
    }
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new StaticClientError(`${clientId}：jwks の鍵は EC の P-256 だけを受け付ける`);
  }
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new StaticClientError(`${clientId}：jwks の鍵に x と y がない`);
  }
  if (jwk.alg !== undefined && jwk.alg !== 'ES256') {
    throw new StaticClientError(`${clientId}：jwks の鍵の alg は ES256 だけを受け付ける`);
  }
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new StaticClientError(`${clientId}：jwks の鍵の use は sig だけを受け付ける`);
  }
  return jwk as unknown as PublicEcJwk;
}

/**
 * 静的なクライアントの設定を、oidc-provider に渡す前に検査する。
 * 許可していない項目が1つでもあれば、Provider を作らずに止める（起動時に失敗させる）。
 */
export function assertStaticClient(
  input: Readonly<Record<string, unknown>>,
  tenants: TenantRegistry,
): StaticClientMetadata {
  const clientId = typeof input.client_id === 'string' ? input.client_id : '';
  if (!ID_PATTERN.test(clientId)) {
    throw new StaticClientError('client_id の形式が正しくない');
  }

  for (const key of Object.keys(input)) {
    if (OUTBOUND_CLIENT_METADATA.includes(key)) {
      throw new StaticClientError(
        `${clientId}：${key} は受け付けない（不変条件7。外への取得が起きるため）`,
      );
    }
    if (!ALLOWED_KEYS.has(key)) {
      throw new StaticClientError(`${clientId}：許可していない項目がある（${key}）`);
    }
  }

  const tenantId = input.tenant_id;
  if (typeof tenantId !== 'string' || !ID_PATTERN.test(tenantId) || !tenants.has(tenantId)) {
    throw new StaticClientError(`${clientId}：tenant_id が登録簿にない`);
  }
  if (input.token_endpoint_auth_method !== 'private_key_jwt') {
    throw new StaticClientError(`${clientId}：クライアント認証は private_key_jwt だけ`);
  }
  if (input.token_endpoint_auth_signing_alg !== 'ES256') {
    throw new StaticClientError(`${clientId}：クライアント認証の署名は ES256 だけ`);
  }
  if (input.id_token_signed_response_alg !== 'ES256') {
    throw new StaticClientError(`${clientId}：ID トークンの署名は ES256 だけ`);
  }
  if (!sameStrings(input.grant_types, [CIBA_GRANT_TYPE])) {
    throw new StaticClientError(`${clientId}：このスパイクでは CIBA だけのクライアントを扱う`);
  }
  if (!sameStrings(input.response_types, [])) {
    throw new StaticClientError(`${clientId}：CIBA だけのクライアントの response_types は空にする`);
  }
  if (input.redirect_uris !== undefined && !sameStrings(input.redirect_uris, [])) {
    throw new StaticClientError(`${clientId}：CIBA だけのクライアントの redirect_uris は空にする`);
  }
  if (input.backchannel_token_delivery_mode !== 'poll') {
    throw new StaticClientError(`${clientId}：CIBA の受け渡しは poll だけ`);
  }

  const jwks = input.jwks;
  if (!isRecord(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new StaticClientError(`${clientId}：jwks がない`);
  }
  for (const member of Object.keys(jwks)) {
    if (member !== 'keys') {
      throw new StaticClientError(`${clientId}：jwks に、許可していない項目がある（${member}）`);
    }
  }
  const keys = jwks.keys.map((jwk: unknown) => assertPublicEcJwk(clientId, jwk));

  return {
    client_id: clientId,
    tenant_id: tenantId,
    jwks: { keys },
    grant_types: [CIBA_GRANT_TYPE],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    id_token_signed_response_alg: 'ES256',
    backchannel_token_delivery_mode: 'poll',
  };
}
