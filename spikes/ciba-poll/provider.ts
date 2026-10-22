// 捨てスパイク2：oidc-provider 9.12.2 の CIBA（poll）を組み立てる。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
//
// 何を oidc-provider に任せ、何を自作するかは docs/adr/0006-ciba-spike-findings.md に記録した。
// このファイルの要点：
// - 不変条件5：sub はテナント ID と利用者 ID の HMAC。CIBA のクライアントは pairwise にできない
//   （oidc-provider が jwks_uri を必須にする）ので、public にして、導出済みの sub を accountId として渡す。
// - 不変条件6：hint は窓口コード（login_hint_token）だけ。login_hint、id_token_hint、user_code は、
//   どの hint の処理よりも前（validateRequestContext）で拒否する。企業の binding_message は使わない。
// - 不変条件7：oidc-provider の fetch を、常に失敗する関数に差し替える。静的なクライアントは事前に検査する。
// - 不変条件9：クライアント認証、ID トークンなど、設定できる JWS はすべて ES256 だけにする。
//   クッキーの署名も HMAC-SHA-256 にする（cookieKeys の説明を参照）。
// - 不変条件4：保存アダプタは id を HMAC にする。ログには何も書かない。
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { exportJWK, generateKeyPair } from 'jose';
import type { Client, Configuration, KoaContextWithOIDC } from 'oidc-provider';
import Provider, { errors } from 'oidc-provider';
import { type DeskChannel, type DeskCodeRecord, DeskCodeStore } from './desk-codes.ts';
import { DeviceInbox } from './device-inbox.ts';
import { HmacMemoryStore, StorageKeyRef } from './hmac-adapter.ts';
import {
  assertStaticClient,
  OUTBOUND_CLIENT_METADATA,
  type Tenant,
  type TenantRegistry,
} from './static-clients.ts';

/** CIBA（窓口）の結果であることを企業に示す acr。step-up の結果と区別させる（不変条件1(a)）。 */
export const ACR_DESK = 'urn:warifu:acr:desk';

/** 企業に許す CIBA の hint は login_hint_token（窓口コード）だけ。 */
export const REJECTED_HINTS: readonly string[] = ['login_hint', 'id_token_hint', 'user_code'];

const CHANNEL_LABEL: Readonly<Record<DeskChannel, string>> = {
  phone: '電話',
  chat: 'チャット',
  store: '店頭',
};

const DISCOVERY_PATHS: ReadonlySet<string> = new Set([
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
]);

export interface SpikeWarifuOptions {
  readonly issuer: string;
  readonly tenants: readonly Tenant[];
  readonly clients: readonly Readonly<Record<string, unknown>>[];
  /** 割符の内部の利用者 ID */
  readonly users: readonly string[];
  /** 窓口コードの期限に使う時刻（ミリ秒） */
  readonly now?: () => number;
  readonly deskCodeTtlMs?: number;
}

export interface SpikeWarifu {
  readonly provider: Provider;
  readonly deskCodes: DeskCodeStore;
  readonly inbox: DeviceInbox;
  readonly storage: HmacMemoryStore;
  /** oidc-provider が外へつなごうとしたときのホスト名。空のままであることをテストで確かめる。 */
  readonly outboundAttempts: readonly string[];
  deriveSub(tenantId: string, userId: string): string;
  /** 利用者が端末で承認したことにする（本番は UV 付きのパスキーで確かめる。M6、M7）。 */
  approve(entryId: string, userId: string): Promise<void>;
  /** 利用者が端末で拒否したことにする。 */
  deny(entryId: string, userId: string): Promise<void>;
}

type BackchannelRequest = InstanceType<Provider['BackchannelAuthenticationRequest']>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function epochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * クッキーの署名の鍵。鍵を配列で渡すと、Koa の cookies が Keygrip の既定（HMAC-SHA1）で署名する
 * （cookies/index.js と keygrip/index.js）。HMAC-SHA1 は不変条件9の許可リストにないので、
 * Keygrip と同じ形（sign、verify、index）のオブジェクトを渡し、HMAC-SHA-256 で署名する。
 * oidc-provider は、配列でない keys をそのまま Koa に渡す（lib/provider.js）。
 * いまの CIBA だけの構成ではクッキーを使わないが、M3 の画面とセッションはこの設定の上に作る。
 */
function cookieKeys(key: Buffer) {
  const sign = (data: unknown): string =>
    createHmac('sha256', key).update(String(data)).digest('base64url');
  const index = (data: unknown, digest: string): number => {
    const expected = Buffer.from(sign(data));
    const actual = Buffer.from(digest);
    return expected.length === actual.length && timingSafeEqual(expected, actual) ? 0 : -1;
  };
  return { sign, index, verify: (data: unknown, digest: string) => index(data, digest) === 0 };
}

function hostOf(input: string | URL | Request): string {
  const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  try {
    return new URL(href).host;
  } catch {
    return '(unparsable)';
  }
}

/**
 * hint の入口の検査（不変条件6）。features.ciba.validateRequestContext から呼ぶ。
 * この関数は、lib/actions/authorization/index.js の checkCibaContext で呼ばれる。
 * 要求オブジェクトの展開（processRequestObject）の後で、hint の処理（cibaLoadAccount）より前に当たる。
 * id_token_hint は cibaLoadAccount の中で oidc-provider 自身が検証してしまう（フックがない）ため、ここで止める。
 * error_description は RFC 6749 により ASCII だけにする。値は埋め込まない。
 */
function enforceHintPolicy(ctx: KoaContextWithOIDC): void {
  const params = ctx.oidc.params ?? {};
  for (const name of REJECTED_HINTS) {
    if (params[name] !== undefined) {
      throw new errors.InvalidRequest(`${name} is not accepted; use login_hint_token only`);
    }
  }
  if (typeof params.login_hint_token !== 'string') {
    throw new errors.InvalidRequest('login_hint_token is required');
  }
}

export async function buildSpikeWarifu(options: SpikeWarifuOptions): Promise<SpikeWarifu> {
  const tenants: TenantRegistry = new Map(
    options.tenants.map((tenant) => [tenant.tenantId, tenant]),
  );
  // 不変条件7：Provider を作る前に検査する。ここで止まれば、oidc-provider は jwks_uri などを見ることもない。
  const clients = options.clients.map((metadata) => assertStaticClient(metadata, tenants));
  const users = new Set(options.users);

  // 本番では鍵サービス（KMS）の HMAC 鍵を使い、鍵を外に出さない（plan 8章）。
  const subKey = randomBytes(32);
  const deriveSub = (tenantId: string, userId: string): string =>
    createHmac('sha256', subKey).update(`${tenantId}:${userId}`).digest('base64url');

  const deskCodes = new DeskCodeStore({ now: options.now, ttlMs: options.deskCodeTtlMs });
  const inbox = new DeviceInbox();
  const storage = new HmacMemoryStore();
  const outboundAttempts: string[] = [];
  // 企業に渡した sub → テナントと利用者。トークンを発行するときに、利用者がまだ有効かを確かめるために使う。
  const issuedSubs = new Map<string, { tenantId: string; userId: string }>();
  // 1つの要求の中で、窓口コードから得た利用者を triggerAuthenticationDevice へ渡す。
  // processLoginHintToken と triggerAuthenticationDevice は、同じ Koa の ctx を受け取る。
  const resolvedByRequest = new WeakMap<KoaContextWithOIDC, DeskCodeRecord>();

  function tenantOf(client: Client | undefined): Tenant {
    // tenant_id は extraClientMetadata なので、Client のインスタンスにそのままの名前で載る。
    // @types/oidc-provider 9.12.1 の Client には、この項目の型がない。
    const tenantId =
      client === undefined ? undefined : (client as unknown as Record<string, unknown>).tenant_id;
    const tenant = typeof tenantId === 'string' ? tenants.get(tenantId) : undefined;
    if (tenant === undefined) {
      throw new Error('クライアントのテナントが登録簿にない');
    }
    return tenant;
  }

  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const signingJwk = {
    ...(await exportJWK(privateKey)),
    alg: 'ES256',
    use: 'sig',
    kid: randomUUID(),
  };

  const configuration: Configuration = {
    adapter: storage.adapterFactory(),
    clients: clients.map((client) => ({
      ...client,
      grant_types: [...client.grant_types],
      response_types: [],
      redirect_uris: [],
      jwks: { keys: client.jwks.keys.map((key) => ({ ...key })) },
      // acr と auth_time は、要求されたときだけ ID トークンに入る（lib/actions/authorization/claims.js の
      // assignClaims）。企業が acr_values を送らなくても入るように、割符の側でクライアントに付ける。
      default_acr_values: [ACR_DESK],
      require_auth_time: true,
    })),
    // クライアントの既定値は id_token_signed_response_alg が RS256、token_endpoint_auth_method が
    // client_secret_basic（lib/consts/client_attributes.js）。書き忘れても ES256 と private_key_jwt になるようにする。
    clientDefaults: {
      id_token_signed_response_alg: 'ES256',
      token_endpoint_auth_method: 'private_key_jwt',
      grant_types: [],
      response_types: [],
    },
    jwks: { keys: [signingJwk] },
    cookies: { keys: cookieKeys(randomBytes(32)) },
    scopes: ['openid'],
    claims: { acr: null, auth_time: null, openid: ['sub'] },
    acrValues: [ACR_DESK],
    responseTypes: [],
    subjectTypes: ['public'],
    clientAuthMethods: ['private_key_jwt'],
    enabledJWA: {
      clientAuthSigningAlgValues: ['ES256'],
      idTokenSigningAlgValues: ['ES256'],
      requestObjectSigningAlgValues: ['ES256'],
      userinfoSigningAlgValues: ['ES256'],
      introspectionSigningAlgValues: ['ES256'],
      authorizationSigningAlgValues: ['ES256'],
      dPoPSigningAlgValues: ['ES256'],
      attestSigningAlgValues: ['ES256'],
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
    // 割符では issuer だけにする（aud の取り違えを使う攻撃への備え）。alg も重ねて確かめる。
    assertJwtClientAuthClaimsAndHeader: async (ctx, claims, header) => {
      if (header.alg !== 'ES256') {
        throw new errors.InvalidClientAuth('client assertion alg must be ES256');
      }
      if (claims.aud !== ctx.oidc.issuer) {
        throw new errors.InvalidClientAuth('client assertion aud must be the issuer identifier');
      }
    },
    extraClientMetadata: {
      properties: ['tenant_id'],
      // 二重の守り（不変条件7）。静的なクライアントの事前検査を通らない値が、何かの経路で Provider に
      // 渡っても、Client を作る段階（lib/helpers/client_schema.js の processCustomMetadata）で止める。
      // この関数は、登録された追加の項目（tenant_id）ごとに必ず呼ばれ、metadata の全体を見られる。
      validator: (_ctx, key, value, metadata) => {
        if (key !== 'tenant_id') {
          return;
        }
        const all = metadata as unknown as Record<string, unknown>;
        for (const name of OUTBOUND_CLIENT_METADATA) {
          if (all[name] !== undefined) {
            throw new errors.InvalidClientMetadata(`${name} is not accepted`);
          }
        }
        if (typeof value !== 'string' || !tenants.has(value)) {
          throw new errors.InvalidClientMetadata('tenant_id is not registered');
        }
      },
    },
    // 不変条件7：oidc-provider が外へつなぐ経路は、すべてこの fetch を通る（lib/helpers/fetch_request.js）。
    // 割符では、常に失敗させる。
    fetch: async (input) => {
      outboundAttempts.push(hostOf(input));
      throw new Error('outbound requests are not allowed here');
    },
    findAccount: async (ctx, id) => {
      const entry = issuedSubs.get(id);
      if (entry === undefined || !users.has(entry.userId)) {
        return undefined;
      }
      if (tenantOf(ctx.oidc.client).tenantId !== entry.tenantId) {
        return undefined;
      }
      // sub 以外のクレーム（メール、電話、氏名など）は返さない。
      return { accountId: id, claims: () => ({ sub: id }) };
    },
    ttl: {
      AccessToken: 600,
      IdToken: 600,
      Grant: 600,
      BackchannelAuthenticationRequest: 300,
    },
    features: {
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
      ciba: {
        enabled: true,
        deliveryModes: ['poll'],
        // request_context は使わない。この位置を hint の入口の検査に使う（enforceHintPolicy の説明を参照）。
        validateRequestContext: async (ctx) => {
          enforceHintPolicy(ctx);
        },
        // 企業が送った binding_message は使わない。拒否はせず、無視する（保存もしない。hmac-adapter.ts）。
        // 承認画面には、割符が生成した文言を出す（triggerAuthenticationDevice）。
        validateBindingMessage: async () => {},
        processLoginHintToken: async (ctx, loginHintToken) => {
          const client = ctx.oidc.client;
          if (client === undefined || typeof loginHintToken !== 'string') {
            return undefined;
          }
          // 照合と同時に失効させる。この後の手順が失敗しても、窓口コードは戻さない。
          const record = deskCodes.consume(loginHintToken, client.clientId);
          if (record === undefined || !users.has(record.userId)) {
            // 理由を区別せず unknown_user_id にする（lib/actions/authorization/ciba.js）。
            return undefined;
          }
          const tenant = tenantOf(client);
          const sub = deriveSub(tenant.tenantId, record.userId);
          issuedSubs.set(sub, { tenantId: tenant.tenantId, userId: record.userId });
          resolvedByRequest.set(ctx, record);
          return sub;
        },
        // 二重の守り。enforceHintPolicy を通れば、ここには来ない。
        processLoginHint: async () => {
          throw new errors.InvalidRequest('login_hint is not accepted; use login_hint_token only');
        },
        verifyUserCode: async (_ctx, _account, userCode) => {
          if (userCode !== undefined) {
            throw new errors.InvalidRequest('user_code is not accepted; use login_hint_token only');
          }
        },
        triggerAuthenticationDevice: async (ctx, request, _account, client) => {
          const record = resolvedByRequest.get(ctx);
          if (record === undefined) {
            throw new Error('窓口コードの照合結果がない');
          }
          const tenant = tenantOf(client);
          inbox.push({
            userId: record.userId,
            companyName: tenant.displayName,
            channel: record.channel,
            operation: '窓口での本人確認',
            scopeNote: '照会と軽い手続きだけ',
            bindingMessage: `${tenant.displayName}の${CHANNEL_LABEL[record.channel]}窓口での本人確認`,
            warning: 'A-1',
            codeIssuedAt: record.issuedAt,
            requestKey: storage.storageKey('BackchannelAuthenticationRequest', request.jti),
          });
        },
      },
    },
  };

  const provider = new Provider(options.issuer, configuration);

  // 静的なクライアントは、最初に使われたときに検証される（lib/models/client.js の Client.find）。
  // 設定の誤りを要求の時点ではなく起動の時点で見つけるため、ここで全部を読み込む。
  for (const client of clients) {
    if ((await provider.Client.find(client.client_id)) === undefined) {
      throw new Error('静的なクライアントを読み込めない');
    }
  }

  // discovery は backchannel_user_code_parameter_supported を常に true にする（lib/actions/discovery.js）。
  // configuration.discovery は値のない項目しか埋めないので、応答を後から書き換える。
  provider.use(async (ctx, next) => {
    await next();
    if (
      ctx.method === 'GET' &&
      DISCOVERY_PATHS.has(ctx.path) &&
      ctx.status === 200 &&
      isRecord(ctx.body)
    ) {
      ctx.body.backchannel_user_code_parameter_supported = false;
    }
  });

  // @types/oidc-provider 9.12.1 のコンストラクタの型は clientId と accountId しか受けないが、
  // 実装（lib/models/base_model.js）は IN_PAYLOAD の項目をすべて受け取る。find と同じ作り方をする。
  const BackchannelRequestModel = provider.BackchannelAuthenticationRequest as unknown as new (
    payload: Record<string, unknown>,
  ) => BackchannelRequest;

  async function loadRequest(requestKey: string): Promise<BackchannelRequest> {
    const payload = storage.get(requestKey);
    if (payload === undefined || typeof payload.exp !== 'number' || payload.exp <= epochSeconds()) {
      throw new Error('承認待ちの要求が見つからないか、期限が切れている');
    }
    // 二重の守り。backchannelResult は、結果がもう入っているかを確かめずに上書きする（lib/provider.js）。
    if (
      payload.grantId !== undefined ||
      payload.error !== undefined ||
      payload.consumed !== undefined
    ) {
      throw new Error('この要求には、もう結果が入っている');
    }
    // jti には保存キーの参照を入れる。backchannelResult の中の save は、これをアダプタにそのまま渡す。
    return new BackchannelRequestModel({ ...payload, jti: new StorageKeyRef(requestKey) });
  }

  /**
   * 承認と拒否に共通の手順。受信箱の状態を、最初の await より前に resolving に変える。
   * そうしないと、同じ承認待ちへの承認と拒否が、どちらも pendingFor を通ってから await で入れ替わり、
   * 両方が成功してしまう（Grant が作られ、poll には ID トークンが出る）。途中で失敗したら、承認待ちに戻す。
   * 本番（M6、M7）では、この状態の変更を DB の1つの文で行う（ADR 0006）。
   */
  async function settle(
    entryId: string,
    userId: string,
    outcome: 'approved' | 'denied',
    apply: (request: BackchannelRequest) => Promise<void>,
  ): Promise<void> {
    const entry = inbox.pendingFor(entryId, userId);
    if (entry === undefined) {
      throw new Error('承認待ちが見つからない');
    }
    entry.state = 'resolving';
    try {
      await apply(await loadRequest(entry.requestKey));
    } catch (error) {
      entry.state = 'pending';
      throw error;
    }
    entry.state = outcome;
  }

  return {
    provider,
    deskCodes,
    inbox,
    storage,
    outboundAttempts,
    deriveSub,
    async approve(entryId, userId) {
      await settle(entryId, userId, 'approved', async (request) => {
        const grant = new provider.Grant({
          accountId: request.accountId,
          clientId: request.clientId,
        });
        grant.addOIDCScope('openid');
        await grant.save();
        await provider.backchannelResult(request, grant, {
          acr: ACR_DESK,
          authTime: epochSeconds(),
        });
      });
    },
    async deny(entryId, userId) {
      await settle(entryId, userId, 'denied', async (request) => {
        await provider.backchannelResult(
          request,
          new errors.AccessDenied('end-user denied the authentication request'),
        );
      });
    },
  };
}
