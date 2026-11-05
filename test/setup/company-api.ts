// company-api のテストの補助（ADR 0022）。ワーカーの DB と globalSetup の鍵サービスを使う。
// - startTestCompanyApi：テナントと API のクライアント（ES256 の鍵はテストの中で作る）で company-api を立てる。
//   要求は Fastify の inject で送る（ソケットを開かない）。
// - clientAssertion：企業のサーバーの代わりに、private_key_jwt の client assertion を作る。
// - connectUser：idp と同じ境界で、利用者、第1世代の別名、sub の索引を置く（接続の同意の後と同じ状態）。

import { generateKeyPairSync, type KeyObject, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { type CompanyApi, createCompanyApi } from '../../packages/company-api/src/app.ts';
import { deriveSub } from '../../packages/idp/src/subject.ts';
import { aliasLookupMessage } from '../../packages/warifu-core/src/aliases.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import {
  parseTenantId,
  parseWarifuUserId,
  type TenantId,
  type WarifuUserId,
} from '../../packages/warifu-core/src/ids.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import type { SenderConnection } from '../../packages/warifu-core/src/sender/client.ts';
import { serviceDb } from './db.ts';
import { keysvcConnection } from './keys.ts';
import { workerDatabase } from './worker-db.ts';

export const ISSUER = 'http://localhost:4400';
export const HOST = 'localhost:4400';
export const TOKEN_ENDPOINT = `${ISSUER}/token`;

export interface TestApiClient {
  readonly clientId: string;
  readonly kid: string;
  readonly privateKey: KeyObject;
}

export interface TestTenant {
  readonly tenantId: TenantId;
  readonly relayDomain: string;
  readonly client: TestApiClient;
  readonly webhookUrl?: string;
}

export interface TenantSpec {
  readonly tenantId?: TenantId;
  readonly relayDomain?: string;
  readonly webhookUrl?: string;
  readonly suspended?: boolean;
  readonly client?: TestApiClient;
  /** クライアントに許す scope（既定は company_api だけ。窓口は desk。ADR 0026）。 */
  readonly scopes?: readonly ('company_api' | 'desk')[];
  /** SET の受け口の設定の版（ADR 0026 の O-72）。 */
  readonly setDeliveryRevision?: number;
}

export interface InjectResult {
  readonly status: number;
  readonly headers: Record<string, unknown>;
  readonly text: string;
  json(): unknown;
}

export interface TestCompanyApi {
  readonly api: CompanyApi;
  readonly tenants: readonly TestTenant[];
  readonly logs: string[];
  /** POST /token（client assertion の中身を変えられる）。 */
  token(tenant: TestTenant, form?: Record<string, string>): Promise<InjectResult>;
  /** トークンを得る（失敗したら例外）。scope を省けば company_api。 */
  accessToken(tenant: TestTenant, scope?: 'company_api' | 'desk'): Promise<string>;
  request(input: {
    readonly method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    readonly path: string;
    readonly token?: string;
    readonly json?: unknown;
    readonly headers?: Record<string, string>;
    readonly body?: string;
  }): Promise<InjectResult>;
  stop(): Promise<void>;
}

export function newApiClient(): TestApiClient {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    clientId: `api-${randomBytes(4).toString('hex')}`,
    kid: randomBytes(4).toString('hex'),
    privateKey,
  };
}

export function publicJwkOf(client: TestApiClient) {
  const jwk = client.privateKey.export({ format: 'jwk' }) as Record<string, string>;
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: client.kid, alg: 'ES256', use: 'sig' };
}

/** private_key_jwt の client assertion（RFC 7523）。overrides で中身を変える（攻撃の段で使う）。 */
export async function clientAssertion(
  client: TestApiClient,
  overrides?: {
    readonly iss?: string;
    readonly sub?: string;
    readonly aud?: string | string[];
    readonly jti?: string;
    readonly iat?: number;
    readonly exp?: number;
    readonly key?: KeyObject;
    readonly kid?: string;
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ jti: overrides?.jti ?? randomUUID() })
    .setProtectedHeader({ alg: 'ES256', kid: overrides?.kid ?? client.kid })
    .setIssuer(overrides?.iss ?? client.clientId)
    .setSubject(overrides?.sub ?? client.clientId)
    .setAudience(overrides?.aud ?? TOKEN_ENDPOINT)
    .setIssuedAt(overrides?.iat ?? now)
    .setExpirationTime(overrides?.exp ?? now + 60)
    .sign(overrides?.key ?? client.privateKey);
}

export async function startTestCompanyApi(options: {
  readonly tenants: readonly TenantSpec[];
  readonly sender?: SenderConnection;
  readonly now?: () => Date;
  /** idp からの窓口の内部 API（ADR 0026）。 */
  readonly deskInternal?: {
    readonly socketPath: string;
    readonly credentials: Readonly<Record<'idp', Uint8Array>>;
  };
}): Promise<TestCompanyApi> {
  const tenants: TestTenant[] = options.tenants.map((spec) => ({
    tenantId: spec.tenantId ?? parseTenantId(randomUUID()),
    relayDomain: spec.relayDomain ?? `t${randomBytes(4).toString('hex')}.relay.warifu.test`,
    client: spec.client ?? newApiClient(),
    ...(spec.webhookUrl === undefined ? {} : { webhookUrl: spec.webhookUrl }),
  }));
  const db = await workerDatabase();
  const logs: string[] = [];
  const api = await createCompanyApi({
    config: {
      issuer: ISSUER,
      tenants: tenants.map((t, i) => ({
        tenantId: t.tenantId,
        relayDomain: t.relayDomain,
        participation: 'full',
        ...(options.tenants[i]?.suspended === true ? { suspended: true } : {}),
        apiClients: [
          {
            clientId: t.client.clientId,
            jwks: { keys: [publicJwkOf(t.client)] },
            ...(options.tenants[i]?.scopes === undefined
              ? {}
              : { scopes: options.tenants[i]?.scopes }),
          },
        ],
        ...(t.webhookUrl === undefined ? {} : { webhookUrl: t.webhookUrl }),
        ...(options.tenants[i]?.setDeliveryRevision === undefined
          ? {}
          : { setDeliveryRevision: options.tenants[i]?.setDeliveryRevision }),
      })),
    },
    keysvc: keysvcConnection('company-api'),
    db: { host: String(db.host), port: Number(db.port), database: String(db.database) },
    ...(options.sender === undefined ? {} : { sender: options.sender }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.deskInternal === undefined ? {} : { deskInternal: options.deskInternal }),
    logWrite: (line) => logs.push(line),
    deliveryIntervalMs: 0,
  });
  const wrap = (res: {
    statusCode: number;
    headers: Record<string, unknown>;
    body: string;
  }): InjectResult => ({
    status: res.statusCode,
    headers: res.headers,
    text: res.body,
    json: () => JSON.parse(res.body),
  });
  const handle: TestCompanyApi = {
    api,
    tenants,
    logs,
    async token(tenant, form) {
      // client assertion の iat と exp は、company-api の時計（options.now）に合わせる。
      const nowSeconds = Math.floor((options.now?.() ?? new Date()).getTime() / 1000);
      const params = new URLSearchParams({
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await clientAssertion(tenant.client, {
          iat: nowSeconds,
          exp: nowSeconds + 60,
        }),
        ...form,
      });
      const res = await api.app.inject({
        method: 'POST',
        url: '/token',
        headers: { host: HOST, 'content-type': 'application/x-www-form-urlencoded' },
        payload: params.toString(),
      });
      return wrap(res);
    },
    async accessToken(tenant, scope) {
      const res = await handle.token(tenant, scope === undefined ? undefined : { scope });
      if (res.status !== 200) throw new Error(`トークンを得られない（${res.status}）`);
      return (res.json() as { access_token: string }).access_token;
    },
    async request(input) {
      const res = await api.app.inject({
        method: input.method ?? 'POST',
        url: input.path,
        headers: {
          host: HOST,
          ...(input.json === undefined ? {} : { 'content-type': 'application/json' }),
          ...(input.token === undefined ? {} : { authorization: `Bearer ${input.token}` }),
          ...input.headers,
        },
        ...(input.json === undefined
          ? input.body === undefined
            ? {}
            : { payload: input.body }
          : { payload: JSON.stringify(input.json) }),
      });
      return wrap(res);
    },
    async stop() {
      await api.close();
    },
  };
  return handle;
}

export interface ConnectedUser {
  readonly userId: WarifuUserId;
  /** テナントの番号 → sub。 */
  readonly subs: readonly string[];
  /** テナントの番号 → 第1世代の別名。 */
  readonly aliases: readonly string[];
}

/** 接続の同意の後と同じ状態（第1世代の別名と、sub の索引）を、idp と同じ境界で作る。 */
export async function connectUser(
  tenants: readonly { readonly tenantId: TenantId; readonly relayDomain: string }[],
  existing?: WarifuUserId,
): Promise<ConnectedUser> {
  const userId = existing ?? parseWarifuUserId(randomUUID());
  const keys = createIdpKeyClient(keysvcConnection('idp'));
  const idp = await serviceDb('idp');
  try {
    if (existing === undefined) {
      await idp.withWarifuUser(userId, (tx) =>
        tx.execute(sql`INSERT INTO idp.users (user_id) VALUES (${userId})`),
      );
    }
    const subs: string[] = [];
    const aliases: string[] = [];
    for (const t of tenants) {
      const local = await keys.deriveAlias({ tenantId: t.tenantId, userId, generation: 1 });
      const lookupMac = await keys.mac('alias_lookup', aliasLookupMessage(local));
      const sub = await deriveSub(keys, t.tenantId, userId);
      await idp.withTenant(t.tenantId, async (tx) => {
        await tx.execute(
          sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
              VALUES (${t.tenantId}, ${userId}, 1, ${lookupMac}) ON CONFLICT DO NOTHING`,
        );
        await tx.execute(
          sql`INSERT INTO aliases.subject (tenant_id, user_id, sub) VALUES (${t.tenantId}, ${userId}, ${sub})
              ON CONFLICT DO NOTHING`,
        );
      });
      subs.push(sub);
      aliases.push(`${local}@${t.relayDomain}`);
    }
    return { userId, subs, aliases };
  } finally {
    await idp.close();
  }
}
