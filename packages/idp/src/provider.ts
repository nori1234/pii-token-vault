// oidc-provider 9.12.2 の設定（plan 9章、ADR 0006、ADR 0007、ADR 0018）。
//
// - 認可コードと PKCE（S256）だけ。refresh token は出さない。userinfo は無効にし、クレームは ID トークンに入れる。
// - クライアント認証は private_key_jwt（ES256）だけ。企業の鍵は登録簿の jwks。動的クライアント登録は無効（不変条件7）。
// - sub はテナント単位の pairwise（subject.ts）。email クレームは別名で、email_verified は常に false（不変条件5）。
// - 署名は鍵サービス（signing-key.ts）。クッキーは署名せず、値は乱数の id（ADR 0018）。
// - 外へはつながない：fetch を常に失敗させる（不変条件7）。jwks_uri などは登録簿の検査と validator の二重で止める。
// - acr は urn:warifu:acr:passkey（UV 付きのパスキー）。step-up は max_age か prompt=login で、新しい認証を求める。
// - 窓口の操作別承認（ADR 0025、ADR 0026）：authorization_details（型 warifu_desk）を付けた要求は、PAR の受け口
//   （/oidc/request）だけで受け取る。認可の入口の URL の authorization_details は 400。request_uri は、割符の PAR が
//   発行した urn の形のものだけを oidc-provider に渡す（外へは取りに行かない。不変条件7）。要求オブジェクトは無効のまま。

import type { TenantId, WarifuUserId } from '@pii-token-vault/warifu-core';
import { isUuid } from '@pii-token-vault/warifu-core';
import { DESK_DETAIL_TYPE } from '@pii-token-vault/warifu-core/desk/protocol';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import type { Account, Configuration, KoaContextWithOIDC } from 'oidc-provider';
import Provider, { errors } from 'oidc-provider';
import { currentAlias } from './alias.ts';
import { deskDetailFromParam, parseDeskDetail, sameDeskDetail } from './desk.ts';
import type { RateLimiter } from './rate-limit.ts';
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

/**
 * 認可の入口（GET）で受け付けない項目。id_token_hint は自分の ID トークンの検証が要る（この構成では検証の鍵を持たない）。
 * authorization_details は PAR の受け口だけで受け取る（URL に申請ID を載せない。ADR 0025 の O-50）。
 * request_uri は、下の形のものだけを通す（O-51）。
 */
export const REJECTED_AUTHORIZATION_PARAMS: readonly string[] = Object.freeze([
  'id_token_hint',
  'request',
  'registration',
  'claims',
  'authorization_details',
  // リソースサーバーは置かない（RAR のために resourceIndicators を有効にしただけ）。
  'resource',
]);

/** 窓口の承認の、仮のリソース（RAR に resource が要るため。ほかのリソースサーバーは置かない。ADR 0026）。 */
export const DESK_RESOURCE = 'urn:warifu:desk';

/** 割符の PAR の受け口が発行する request_uri の形（oidc-provider の urn と、nanoid の id）。 */
export const PAR_REQUEST_URI_PATTERN = /^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{21,64}$/;

export const TTL = Object.freeze({
  AccessToken: 300,
  AuthorizationCode: 60,
  IdToken: 300,
  Interaction: 600,
  Session: 600,
  Grant: 600,
  // PAR の request_uri（oidc-provider の上限のまま。ADR 0025 の O-52）。
  PushedAuthorizationRequest: 60,
});

export interface ProviderDeps {
  readonly issuer: string;
  readonly registry: Registry;
  readonly keys: IdpKeyClient;
  readonly repo: RepoDeps;
  readonly store: MacMemoryStore;
  readonly signingKey: KeysvcSigningKey;
  /** PAR の受け口のレート制限（ADR 0026 の O-70）。 */
  readonly limiter: RateLimiter;
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
      // 窓口の操作を許したクライアントだけが、RAR の型 warifu_desk を送れる（ADR 0026 の O-60）。
      authorization_details_types: client.deskActions.length > 0 ? [DESK_DETAIL_TYPE] : [],
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
    discovery: {
      // 操作ごとの承認の JWT の公開鍵（ID トークンの鍵とは別。ADR 0026 の O-62）。
      warifu_op_approval_jwks_uri: `${new URL(deps.issuer).origin}/op-approval/jwks`,
    },
    features: {
      externalSigningSupport: { enabled: true, ack: 'experimental-01' },
      devInteractions: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      clientIdMetadataDocument: { enabled: false },
      requestObjects: { enabled: false },
      // PAR（ADR 0025）。すべての要求に必須にするかは P1（FAPI 2.0）。登録していない redirect_uri は受け付けない。
      pushedAuthorizationRequests: {
        enabled: true,
        requirePushedAuthorizationRequests: false,
        allowUnregisteredRedirectUris: false,
      },
      rpInitiatedLogout: { enabled: false },
      backchannelLogout: { enabled: false },
      userinfo: { enabled: false },
      introspection: { enabled: false },
      revocation: { enabled: false },
      // RAR は resourceIndicators を有効にしないと使えず、RAR の要求には resource が要る（oidc-provider 9.12.2 の
      // checkDependantFeatures と check_resource。ADR 0026）。リソースサーバーは、窓口のための仮の DESK_RESOURCE だけを
      // 置き、authorization_details のある要求にだけ既定で付ける。それ以外の resource は invalid_target で断る。
      // アクセストークンは不透明で、受け付ける口はない（userinfo も introspection も無効）。
      resourceIndicators: {
        enabled: true,
        defaultResource: (ctx: KoaContextWithOIDC, _client: unknown, oneOf?: string[]) => {
          if (oneOf !== undefined) return oneOf;
          return ctx.oidc.params?.authorization_details === undefined ? undefined : DESK_RESOURCE;
        },
        getResourceServerInfo: (_ctx: KoaContextWithOIDC, identifier: string) => {
          if (identifier !== DESK_RESOURCE) throw new errors.InvalidTarget();
          return {
            scope: '',
            audience: DESK_RESOURCE,
            accessTokenFormat: 'opaque',
            accessTokenTTL: TTL.AccessToken,
          };
        },
        useGrantedResource: () => true,
      },
      claimsParameter: { enabled: false },
      clientCredentials: { enabled: false },
      deviceFlow: { enabled: false },
      encryption: { enabled: false },
      dPoP: { enabled: false },
      ciba: { enabled: false },
      jwtResponseModes: { enabled: false },
      webMessageResponseMode: { enabled: false },
      // RAR（RFC 9396）は、窓口の型 warifu_desk だけ（ADR 0026 の O-60）。
      richAuthorizationRequests: {
        enabled: true,
        types: {
          [DESK_DETAIL_TYPE]: {
            validate: async (
              ctx: KoaContextWithOIDC,
              detail: unknown,
              client: { clientId: string },
            ) => {
              const entry = registry.clients.get(client.clientId);
              // 1件だけ（ライブラリは型ごとに1件ずつ検査する）。型に合わない項目、許していない操作も断る。
              if (
                entry === undefined ||
                deskDetailFromParam(ctx.oidc.params?.authorization_details, entry.deskActions) ===
                  undefined ||
                parseDeskDetail(detail, entry.deskActions) === undefined
              ) {
                throw new errors.InvalidAuthorizationDetails(
                  'authorization details are not accepted',
                );
              }
            },
          },
        },
        // 認可コードに入れるのは、窓口の承認で作った Grant の内容（操作ごとの承認の JWT を含む）だけ。要求の
        // authorization_details と、Grant の内容（approval を除く）が食い違えば、コードを出さない。要求に
        // authorization_details があるのに Grant に承認がなければ（通常のログインに縮退した）、コードを出さない（D-20）。
        authorizationDetailsForGrantSource: (ctx: KoaContextWithOIDC) => {
          const requested = ctx.oidc.params?.authorization_details;
          const granted = ctx.oidc.grant?.rar;
          if (requested === undefined) return undefined;
          const entry = registry.clients.get(String(ctx.oidc.client?.clientId));
          const detail =
            entry === undefined ? undefined : deskDetailFromParam(requested, entry.deskActions);
          const [first, ...rest] = Array.isArray(granted) ? granted : [];
          if (detail === undefined || first === undefined || rest.length > 0) {
            throw new errors.AccessDenied('the request was not approved');
          }
          const { approval, ...withoutApproval } = first as Record<string, unknown>;
          const approved = parseDeskDetail(withoutApproval, entry?.deskActions ?? []);
          if (
            typeof approval !== 'string' ||
            approved === undefined ||
            !sameDeskDetail(approved, detail)
          ) {
            throw new errors.AccessDenied('the request was not approved');
          }
          return [first];
        },
        // トークンの応答に返すのは、認可コードに入れたものだけ（認可コードのフローだけ）。
        authorizationDetailsForAccessToken: (
          _ctx: KoaContextWithOIDC,
          _token: unknown,
          source: { rar?: unknown } | undefined,
          grantType: string,
        ) => (grantType === 'authorization_code' ? (source?.rar as never) : undefined),
        // introspection は無効。
        authorizationDetailsForIntrospection: () => undefined,
      },
    } as Configuration['features'],
  };

  const provider = new Provider(deps.issuer, configuration);
  provider.proxy = false;

  provider.use(async (ctx, next) => {
    if (ctx.path === '/auth' || ctx.path.startsWith('/auth/')) {
      // 認可の要求は GET だけ（POST の本文の項目は、ここでは見られないため）。request_uri は、割符の PAR が発行した
      // urn の形だけ（それ以外は oidc-provider に渡さない。外へも取りに行かない。ADR 0025 の O-51）。
      const requestUri = ctx.query.request_uri;
      const rejected =
        ctx.method !== 'GET' ||
        REJECTED_AUTHORIZATION_PARAMS.some((name) => ctx.query[name] !== undefined) ||
        (requestUri !== undefined &&
          (typeof requestUri !== 'string' || !PAR_REQUEST_URI_PATTERN.test(requestUri)));
      if (rejected) {
        ctx.status = 400;
        ctx.type = 'html';
        ctx.body =
          '<!doctype html><html lang="ja"><meta charset="utf-8"><title>割符</title><main><h1>要求の形が違います</h1></main></html>';
        return;
      }
    }
    if (ctx.path === '/request') {
      // PAR の受け口（ADR 0026 の O-70）。クライアントを確かめる前は IP ごと、受け付けた後はクライアントごと。
      if (!deps.limiter.take('parByIp', ctx.ip)) {
        ctx.status = 429;
        ctx.type = 'json';
        ctx.body = { error: 'rate_limited' };
        return;
      }
      await next();
      const clientId = ctx.oidc?.client?.clientId;
      const issued = (ctx.body as { request_uri?: unknown } | undefined)?.request_uri;
      if (
        ctx.status === 201 &&
        typeof clientId === 'string' &&
        typeof issued === 'string' &&
        !deps.limiter.take('parByClient', clientId)
      ) {
        // 上限を超えたら、作った request_uri を消して断る（使えない値を返さない）。
        const id = issued.slice('urn:ietf:params:oauth:request_uri:'.length);
        const stored = await ctx.oidc.provider.PushedAuthorizationRequest.find(id);
        await stored?.destroy();
        ctx.status = 429;
        ctx.type = 'json';
        ctx.body = { error: 'rate_limited' };
      }
      ctx.set('cache-control', 'no-store');
      return;
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
