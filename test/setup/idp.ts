// テストから idp を動かすための補助（ADR 0018）。
// - startTestIdp：ワーカーの DB と globalSetup の鍵サービスで、idp をプロセスの中で起動する。テナントとクライアントは乱数。
// - Browser：クッキーを持つ、ブラウザ役の HTTP クライアント（リダイレクトは自分でたどる）。
// - codeFlow：企業（RP）役。認可コードと PKCE と private_key_jwt で、ID トークンを受け取る。
// 外への通信：oidc-provider の fetch は idp の設定で塞ぎ、テストでは globalThis.fetch の宛先も数える。

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  jwtVerify,
  SignJWT,
} from 'jose';
import { inject } from 'vitest';
import { createIdp, type Idp } from '../../packages/idp/src/app.ts';
import { type Mailer, MemoryOutbox } from '../../packages/idp/src/mailer.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';
import { workerDatabase } from './worker-db.ts';

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

export interface TestTenant {
  readonly tenantId: string;
  readonly displayName: string;
  readonly relayDomain: string;
}

export interface TestClient {
  readonly clientId: string;
  readonly tenantId: string;
  readonly redirectUri: string;
  readonly privateKey: PrivateKey;
  readonly kid: string;
  readonly aliasClaim: 'email' | 'contact_alias';
}

export interface TestIdp {
  readonly idp: Idp;
  readonly origin: string;
  readonly issuer: string;
  readonly outbox: MemoryOutbox;
  readonly tenants: readonly TestTenant[];
  readonly clients: readonly TestClient[];
  /** oidc-provider が外へつなごうとした回数。 */
  outboundAttempts(): number;
  /** ログの出力（1行ずつ）。 */
  logLines(): readonly string[];
  stop(): Promise<void>;
}

export interface ClientSpec {
  readonly tenant: number;
  readonly aliasClaim?: 'email' | 'contact_alias';
}

/** テナントを tenants 個、クライアントを clients の指定どおりに作って起動する。 */
export async function startTestIdp(
  spec: { readonly tenants: number; readonly clients: readonly ClientSpec[] },
  now?: () => Date,
  options?: {
    /** 既定はメモリの送信箱（outbox）。relay の内部配送 API につなぐときは RelayMailer を渡す。 */
    readonly mailer?: Mailer;
  },
): Promise<TestIdp> {
  const tenants: TestTenant[] = Array.from({ length: spec.tenants }, (_, i) => ({
    tenantId: randomUUID(),
    displayName: `テスト企業${i + 1}`,
    relayDomain: `t${randomBytes(4).toString('hex')}.relay.warifu.test`,
  }));
  const clients: TestClient[] = [];
  const publicClients: Record<string, unknown>[] = [];
  for (const [i, c] of spec.clients.entries()) {
    const tenant = tenants[c.tenant];
    if (tenant === undefined) throw new Error('テナントの番号が違う');
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const kid = `rp-key-${i}`;
    const jwk = await exportJWK(publicKey);
    const clientId = `rp-${i}-${randomBytes(3).toString('hex')}`;
    const redirectUri = `http://127.0.0.1:65000/callback/${i}`;
    clients.push({
      clientId,
      tenantId: tenant.tenantId,
      redirectUri,
      privateKey,
      kid,
      aliasClaim: c.aliasClaim ?? 'email',
    });
    publicClients.push({
      clientId,
      tenantId: tenant.tenantId,
      redirectUris: [redirectUri],
      jwks: {
        keys: [{ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, kid, alg: 'ES256', use: 'sig' }],
      },
      aliasClaim: c.aliasClaim ?? 'email',
    });
  }

  // ポートを先に決めるため、一度 0 番で起動してから origin を決め直すことはできない（origin は起動の前に要る）。
  // そこで、空いているポートを OS に聞いてから使う。
  const port = await freePort();
  const origin = `http://localhost:${port}`;
  const config = await workerDatabase();
  const provided = inject('keysvc');
  const outbox = new MemoryOutbox();
  const lines: string[] = [];
  let outbound = 0;
  const idp = await createIdp({
    origin,
    rpId: 'localhost',
    registry: { tenants, clients: publicClients },
    keysvc: { socketPath: provided.socketPath, credential: provided.credentials.idp },
    db: { host: String(config.host), port: Number(config.port), database: String(config.database) },
    mailer: options?.mailer ?? outbox,
    logWrite: (line) => {
      lines.push(line);
    },
    onOutboundAttempt: () => {
      outbound += 1;
    },
    ...(now === undefined ? {} : { now }),
  });
  await idp.app.listen({ host: 'localhost', port });
  return {
    idp,
    origin,
    issuer: idp.issuer,
    outbox,
    tenants,
    clients,
    outboundAttempts: () => outbound,
    logLines: () => [...lines],
    async stop() {
      await idp.close();
    },
  };
}

async function freePort(): Promise<number> {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, 'localhost', () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

export interface HttpResult {
  readonly status: number;
  readonly location: string | undefined;
  readonly headers: Headers;
  readonly text: string;
  readonly json: Record<string, unknown>;
}

/** クッキーを持つブラウザ役。クッキーは名前だけで持つ（パスは見ない。テストでは十分）。 */
export class Browser {
  readonly origin: string;
  readonly cookies = new Map<string, string>();
  readonly authenticator: SoftAuthenticator;

  constructor(origin: string, authenticator?: SoftAuthenticator) {
    this.origin = origin;
    this.authenticator = authenticator ?? new SoftAuthenticator(origin);
  }

  async request(
    method: 'GET' | 'POST',
    pathOrUrl: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<HttpResult> {
    const url = new URL(pathOrUrl, this.origin);
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const response = await fetch(url, {
      method,
      redirect: 'manual',
      headers: {
        ...(cookie === '' ? {} : { cookie }),
        ...(method === 'POST' ? { origin: this.origin, 'content-type': 'application/json' } : {}),
        ...headers,
      },
      ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
    });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const index = pair?.indexOf('=') ?? -1;
      if (pair === undefined || index < 1) continue;
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const expired = attrs.some((a) => /^\s*(max-age=0|expires=thu, 01 jan 1970)/i.test(a));
      if (value === '' || expired) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await response.text();
    let json: Record<string, unknown> = {};
    try {
      json = text === '' ? {} : (JSON.parse(text) as Record<string, unknown>);
    } catch {
      json = {};
    }
    return {
      status: response.status,
      location: response.headers.get('location') ?? undefined,
      headers: response.headers,
      text,
      json,
    };
  }

  get(pathOrUrl: string): Promise<HttpResult> {
    return this.request('GET', pathOrUrl);
  }

  post(pathOrUrl: string, body?: unknown): Promise<HttpResult> {
    return this.request('POST', pathOrUrl, body);
  }

  /** 同じオリジンの中のリダイレクトをたどり、外（企業の redirect_uri）に出たらその URL を返す。 */
  async follow(start: string): Promise<{ last: HttpResult; external?: URL; path: string }> {
    let current = start;
    for (let i = 0; i < 10; i += 1) {
      const result = await this.get(current);
      if (result.status < 300 || result.status >= 400 || result.location === undefined) {
        return { last: result, path: new URL(current, this.origin).pathname };
      }
      const next = new URL(result.location, new URL(current, this.origin));
      if (next.origin !== this.origin) return { last: result, external: next, path: next.pathname };
      current = next.href;
    }
    throw new Error('リダイレクトが多すぎる');
  }

  /** PWA でアカウントを作る（ログインした状態になる）。 */
  async registerAccount(): Promise<HttpResult> {
    const options = await this.post('/api/register/options');
    const response = this.authenticator.create(options.json.options as never);
    return this.post('/api/register/verify', { ceremonyId: options.json.ceremonyId, response });
  }

  /** PWA の step-up。 */
  async stepUp(): Promise<HttpResult> {
    const options = await this.post('/api/stepup/options');
    const response = this.authenticator.get(options.json.options as never);
    return this.post('/api/stepup/verify', { ceremonyId: options.json.ceremonyId, response });
  }
}

export interface FlowResult {
  readonly idToken: string;
  readonly claims: Record<string, unknown>;
  readonly tokenResponse: Record<string, unknown>;
  readonly interactionPaths: readonly string[];
}

export interface FlowOptions {
  /** 'register' はインタラクションの中でアカウントを作る。'login' は既存のパスキーでログインする。 */
  readonly mode: 'register' | 'login' | 'session';
  readonly scope?: string;
  readonly maxAge?: number;
  readonly prompt?: string;
  readonly consent?: 'connect' | 'decline';
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export async function clientAssertion(t: TestIdp, client: TestClient): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: client.kid })
    .setIssuer(client.clientId)
    .setSubject(client.clientId)
    .setAudience(t.issuer)
    .setIssuedAt()
    .setExpirationTime('2m')
    .setJti(randomUUID())
    .sign(client.privateKey);
}

/** 認可の要求を始め、最初のインタラクション（または企業への戻り）まで進める。 */
export async function startAuthorization(
  browser: Browser,
  client: TestClient,
  options: {
    scope?: string;
    maxAge?: number;
    prompt?: string;
    extra?: Record<string, string>;
  } = {},
) {
  const { verifier, challenge } = pkce();
  const state = randomBytes(12).toString('base64url');
  const nonce = randomBytes(12).toString('base64url');
  const params = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    scope: options.scope ?? 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(options.maxAge === undefined ? {} : { max_age: String(options.maxAge) }),
    ...(options.prompt === undefined ? {} : { prompt: options.prompt }),
    ...(options.extra ?? {}),
  });
  const followed = await browser.follow(`/oidc/auth?${params}`);
  return { followed, verifier, state, nonce };
}

/** インタラクションを1つ進める（ログイン、登録、同意）。戻り値は次のリダイレクトをたどった結果。 */
export async function actOnInteraction(
  browser: Browser,
  path: string,
  action: 'register' | 'login' | 'connect' | 'decline',
) {
  if (action === 'connect' || action === 'decline') {
    const result = await browser.post(`${path}/consent`, { decision: action });
    if (result.status !== 200) return { result };
    return { result, followed: await browser.follow(String(result.json.redirectTo)) };
  }
  const kind = action === 'register' ? 'register' : 'login';
  const options = await browser.post(`${path}/${kind}/options`);
  if (options.status !== 200) return { result: options };
  const response =
    action === 'register'
      ? browser.authenticator.create(options.json.options as never)
      : browser.authenticator.get(options.json.options as never);
  const result = await browser.post(`${path}/${kind}/verify`, {
    ceremonyId: options.json.ceremonyId,
    response,
  });
  if (result.status !== 200) return { result };
  return { result, followed: await browser.follow(String(result.json.redirectTo)) };
}

/** 企業のサーバー役：認可コードをトークンに換え、ID トークンを検証する。 */
export async function redeemCode(
  t: TestIdp,
  client: TestClient,
  external: URL,
  verifier: string,
  state: string,
) {
  if (external.searchParams.get('state') !== state) throw new Error('state が違う');
  const code = external.searchParams.get('code');
  if (code === null)
    throw new Error(`認可コードがない（${external.searchParams.get('error') ?? ''}）`);
  const response = await fetch(`${t.issuer}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: client.redirectUri,
      code_verifier: verifier,
      client_id: client.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion(t, client),
    }),
  });
  const body = (await response.json()) as Record<string, unknown>;
  if (response.status !== 200) throw new Error(`トークンの要求が失敗した（${String(body.error)}）`);
  const jwks = createLocalJWKSet((await (await fetch(`${t.issuer}/jwks`)).json()) as JSONWebKeySet);
  const { payload } = await jwtVerify(String(body.id_token), jwks, {
    issuer: t.issuer,
    audience: client.clientId,
    algorithms: ['ES256'],
  });
  return {
    tokenResponse: body,
    idToken: String(body.id_token),
    claims: payload as Record<string, unknown>,
  };
}

/** 1往復：認可 → （登録かログイン）→（初めてなら同意）→ トークン。 */
export async function codeFlow(
  t: TestIdp,
  browser: Browser,
  client: TestClient,
  options: FlowOptions,
): Promise<FlowResult> {
  const { followed, verifier, state } = await startAuthorization(browser, client, options);
  let current = followed;
  const paths: string[] = [];
  for (let step = 0; step < 4 && current.external === undefined; step += 1) {
    const path = current.path;
    if (!path.startsWith('/interaction/')) throw new Error('インタラクションに来ていない');
    paths.push(path);
    const html = current.last.text;
    const action = html.includes('data-prompt="consent"')
      ? (options.consent ?? 'connect')
      : options.mode === 'register'
        ? 'register'
        : 'login';
    const acted = await actOnInteraction(browser, path, action);
    if (acted.followed === undefined)
      throw new Error(`インタラクションが失敗した（${acted.result.status}）`);
    current = acted.followed;
  }
  if (current.external === undefined) throw new Error('企業に戻ってこない');
  const redeemed = await redeemCode(t, client, current.external, verifier, state);
  return { ...redeemed, interactionPaths: paths };
}
