// oidc-provider 9.12.2 の設定（plan 9章、ADR 0006、ADR 0007、ADR 0018）。
//
// - 認可コードと PKCE（S256）だけ。refresh token は出さない。userinfo は無効にし、クレームは ID トークンに入れる。
// - クライアント認証は private_key_jwt（ES256）だけ。企業の鍵は登録簿の jwks。動的クライアント登録は無効（不変条件7）。
// - sub はテナント単位の pairwise（subject.ts）。email クレームは別名で、email_verified は常に false（不変条件5）。
// - 署名は鍵サービス（signing-key.ts）。クッキーは署名せず、値は乱数の id（ADR 0018）。
// - 外へはつながない：fetch を常に失敗させる（不変条件7）。jwks_uri などは登録簿の検査と validator の二重で止める。
// - acr は urn:warifu:acr:passkey（UV 付きのパスキー）。step-up は max_age か prompt=login で、新しい認証を求める。

import type { TenantId, WarifuUserId } from '@pii-token-vault/warifu-core';
import { isUuid } from '@pii-token-vault/warifu-core';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import type { Account, Configuration, KoaContextWithOIDC } from 'oidc-provider';
import Provider, { errors } from 'oidc-provider';
import { currentAlias } from './alias.ts';
import { type ClientEntry, OUTBOUND_CLIENT_METADATA, type Registry } from './registry.ts';
import { hasConnection, type RepoDeps, userExists } from './repo.ts';
import type { KeysvcSigningKey } from './signing-key.ts';
import type { MacMemoryStore } from './storage.ts';
import { deriveSub } from './subject.ts';

export const ACR_PASSKEY = 'urn:warifu:acr:passkey';
export const OIDC_MOUNT = '/oidc';
export const OIDC_COOKIES = Object.freeze({
  session: 'warifu_idp_oidc',
  interaction: 'warifu_idp_interaction',
  resume: 'warifu_idp_resume',
});

/** 認可の要求で受け付けない項目。id_token_hint は自分の ID トークンの検証が要る（この構成では検証の鍵を持たない）。 */
export const REJECTED_AUTHORIZATION_PARAMS: readonly string[] = Object.freeze([
  'id_token_hint',
  'request',
  'request_uri',
  'registration',
  'claims',
]);

export const TTL = Object.freeze({
  AccessToken: 300,
  AuthorizationCode: 60,
  IdToken: 300,
  Interaction: 600,
  Session: 600,
  Grant: 600,
});

export interface ProviderDeps {
  readonly issuer: string;
  readonly registry: Registry;
  readonly keys: IdpKeyClient;
  readonly repo: RepoDeps;
  readonly store: MacMemoryStore;
  readonly signingKey: KeysvcSigningKey;
  /** テストで、oidc-provider が外へつなごうとしたかを数える。 */
  readonly onOutboundAttempt?: () => void;
}

const ES256_ONLY = ['ES256'] as const;

export function clientEntryOf(registry: Registry, clientId: string | undefined): ClientEntry {
  const entry = clientId === undefined ? undefined : registry.clients.get(clientId);
  if (entry === undefined) throw new Error('クライアントが登録簿にない');
  return entry;
}

export function buildProvider(deps: ProviderDeps): Provider {
  const { registry, keys, repo } = deps;
  const secureCookies = new URL(deps.issuer).protocol === 'https:';
  const cookieOptions = {
    httpOnly: true,
    sameSite: 'lax' as const,
    signed: false,
    secure: secureCookies,
  };

  const tenantOf = (clientId: string | undefined): TenantId =>
    clientEntryOf(registry, clientId).tenantId;

  const configuration: Configuration = {
    adapter: deps.store.adapterFactory(),
    clients: [...registry.clients.values()].map((client) => ({
      client_id: client.clientId,
      redirect_uris: [...client.redirectUris],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'ES256',
      id_token_signed_response_alg: 'ES256',
      subject_type: 'pairwise',
      jwks: { keys: client.jwks.keys.map((key) => ({ ...key })) },
      // acr と auth_time は、要求されたときだけ ID トークンに入る（lib/actions/authorization/claims.js）。
      // 企業が送らなくても入るように、割符の側でクライアントに付ける。
      default_acr_values: [ACR_PASSKEY],
      require_auth_time: true,
      tenant_id: client.tenantId,
      warifu_alias_claim: client.aliasClaim,
    })),
    // 既定は RS256 と client_secret_basic（lib/consts/client_attributes.js）。書き忘れても ES256 と private_key_jwt にする。
    clientDefaults: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      id_token_signed_response_alg: 'ES256',
      token_endpoint_auth_method: 'private_key_jwt',
      subject_type: 'pairwise',
    },
    jwks: { keys: [deps.signingKey as never] },
    cookies: {
      names: { ...OIDC_COOKIES },
      long: cookieOptions,
      short: cookieOptions,
    },
    scopes: ['openid', 'email'],
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified', 'contact_alias'],
      acr: null,
      auth_time: null,
    },
    acrValues: [ACR_PASSKEY],
    responseTypes: ['code'],
    subjectTypes: ['pairwise'],
    pkce: { required: () => true },
    clientAuthMethods: ['private_key_jwt'],
    conformIdTokenClaims: false,
    issueRefreshToken: async () => false,
    enabledJWA: {
      clientAuthSigningAlgValues: ES256_ONLY,
      idTokenSigningAlgValues: ES256_ONLY,
      requestObjectSigningAlgValues: ES256_ONLY,
      userinfoSigningAlgValues: ES256_ONLY,
      introspectionSigningAlgValues: ES256_ONLY,
      authorizationSigningAlgValues: ES256_ONLY,
      dPoPSigningAlgValues: ES256_ONLY,
      attestSigningAlgValues: ES256_ONLY,
      idTokenEncryptionAlgValues: [],
      idTokenEncryptionEncValues: [],
      requestObjectEncryptionAlgValues: [],
      requestObjectEncryptionEncValues: [],
      userinfoEncryptionAlgValues: [],
      userinfoEncryptionEncValues: [],
      introspectionEncryptionAlgValues: [],
      introspectionEncryptionEncValues: [],
      authorizationEncryptionAlgValues: [],
      authorizationEncryptionEncValues: [],
    },
    // lib/shared/jwt_client_auth.js は、aud に issuer・トークンエンドポイント・今のエンドポイントのどれでも受け付ける。
    // 割符では issuer だけにする（ADR 0006）。alg も重ねて確かめる。
    assertJwtClientAuthClaimsAndHeader: async (ctx, claims, header) => {
      if (header.alg !== 'ES256') {
        throw new errors.InvalidClientAuth('client assertion alg must be ES256');
      }
      if (claims.aud !== ctx.oidc.issuer) {
        throw new errors.InvalidClientAuth('client assertion aud must be the issuer identifier');
      }
    },
    extraClientMetadata: {
      properties: ['tenant_id', 'warifu_alias_claim'],
      // 二重の守り（不変条件7）。登録簿の検査を通らない値が渡っても、Client を作る段階で止める。
      validator: (_ctx, key, value, metadata) => {
        const all = metadata as unknown as Record<string, unknown>;
        for (const name of OUTBOUND_CLIENT_METADATA) {
          if (all[name] !== undefined)
            throw new errors.InvalidClientMetadata(`${name} is not accepted`);
        }
        if (
          key === 'tenant_id' &&
          (typeof value !== 'string' || !registry.tenants.has(value as TenantId))
        ) {
          throw new errors.InvalidClientMetadata('tenant_id is not registered');
        }
        if (key === 'warifu_alias_claim' && value !== 'email' && value !== 'contact_alias') {
          throw new errors.InvalidClientMetadata('warifu_alias_claim is invalid');
        }
      },
    },
    pairwiseIdentifier: async (_ctx, accountId, client) => {
      if (!isUuid(accountId)) throw new Error('accountId の形が違う');
      return deriveSub(keys, tenantOf(client.clientId), accountId as WarifuUserId);
    },
    findAccount: async (ctx, id): Promise<Account | undefined> => {
      if (!isUuid(id)) return undefined;
      const userId = id as WarifuUserId;
      if (!(await userExists(repo, userId))) return undefined;
      return {
        accountId: userId,
        // sub 以外は、scope が email のときの別名だけ。本物の連絡先、氏名などは返さない（不変条件4・5）。
        claims: async (_use, scope) => {
          const out: { sub: string; [key: string]: unknown } = { sub: userId };
          if (
            !String(scope ?? '')
              .split(' ')
              .includes('email')
          )
            return out;
          const entry = clientEntryOf(registry, ctx.oidc.client?.clientId);
          const tenant = registry.tenants.get(entry.tenantId);
          if (tenant === undefined) return out;
          const alias = await currentAlias(repo, keys, tenant, userId);
          if (alias === undefined) return out;
          if (entry.aliasClaim === 'email') {
            out.email = alias;
            out.email_verified = false;
          } else {
            out.contact_alias = alias;
          }
          return out;
        },
      };
    },
    // 接続の同意（idp.connections）を正にする。同意済みなら、Grant をその場で作り直す（Grant はメモリで短命）。
    loadExistingGrant: async (ctx: KoaContextWithOIDC) => {
      const grantId = ctx.oidc.result?.consent?.grantId;
      if (typeof grantId === 'string') return ctx.oidc.provider.Grant.find(grantId);
      const accountId = ctx.oidc.session?.accountId;
      const clientId = ctx.oidc.client?.clientId;
      if (accountId === undefined || clientId === undefined || !isUuid(accountId)) return undefined;
      if (!(await hasConnection(repo, accountId as WarifuUserId, tenantOf(clientId))))
        return undefined;
      const grant = new ctx.oidc.provider.Grant({ clientId, accountId });
      grant.addOIDCScope('openid email');
      await grant.save();
      return grant;
    },
    // エラーの画面には、受け取った値（state、redirect_uri、エラーの説明）を出さない。
    renderError: async (ctx) => {
      ctx.type = 'html';
      ctx.body =
        '<!doctype html><html lang="ja"><meta charset="utf-8"><title>割符</title>' +
        '<main><h1>処理を続けられませんでした</h1><p>はじめの画面に戻って、もう一度お試しください。</p></main></html>';
    },
    // 不変条件7：oidc-provider が外へつなぐ経路は、すべてこの fetch を通る（lib/helpers/fetch_request.js）。
    fetch: async () => {
      deps.onOutboundAttempt?.();
      throw new Error('outbound requests are not allowed here');
    },
    ttl: { ...TTL },
    features: {
      externalSigningSupport: { enabled: true, ack: 'experimental-01' },
      devInteractions: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      clientIdMetadataDocument: { enabled: false },
      requestObjects: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      rpInitiatedLogout: { enabled: false },
      backchannelLogout: { enabled: false },
      userinfo: { enabled: false },
      introspection: { enabled: false },
      revocation: { enabled: false },
      resourceIndicators: { enabled: false },
      claimsParameter: { enabled: false },
      clientCredentials: { enabled: false },
      deviceFlow: { enabled: false },
      encryption: { enabled: false },
      dPoP: { enabled: false },
      ciba: { enabled: false },
      jwtResponseModes: { enabled: false },
      webMessageResponseMode: { enabled: false },
      richAuthorizationRequests: { enabled: false },
    } as Configuration['features'],
  };

  const provider = new Provider(deps.issuer, configuration);
  provider.proxy = false;

  provider.use(async (ctx, next) => {
    if (ctx.path === '/auth' || ctx.path.startsWith('/auth/')) {
      // 認可の要求は GET だけ（POST の本文の項目は、ここでは見られないため）。
      const rejected =
        ctx.method !== 'GET' ||
        REJECTED_AUTHORIZATION_PARAMS.some((name) => ctx.query[name] !== undefined);
      if (rejected) {
        ctx.status = 400;
        ctx.type = 'html';
        ctx.body =
          '<!doctype html><html lang="ja"><meta charset="utf-8"><title>割符</title><main><h1>要求の形が違います</h1></main></html>';
        return;
      }
    }
    await next();
    ctx.set('x-content-type-options', 'nosniff');
    ctx.set('referrer-policy', 'no-referrer');
    ctx.set('cache-control', 'no-store');
    ctx.set(
      'content-security-policy',
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
  });

  return provider;
}
