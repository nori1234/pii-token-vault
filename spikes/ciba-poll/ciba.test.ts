// 捨てスパイク2：oidc-provider 9.12.2 の CIBA を poll で1往復させる。
// プロセスの中で http サーバーを立て、企業（RP）の役は fetch で呼ぶ。外へのつなぎは、すべて失敗させて数える。
// 各テストの先頭のコメントは、漏えいシナリオのテストの形式（CLAUDE.md 不変条件12）に合わせる。
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  jwtVerify,
  SignJWT,
  UnsecuredJWT,
} from 'jose';
import Provider from 'oidc-provider';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { HmacMemoryStore } from './hmac-adapter.ts';
import { ACR_DESK, buildSpikeWarifu, type SpikeWarifu } from './provider.ts';
import { CIBA_GRANT_TYPE, StaticClientError } from './static-clients.ts';

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

interface HttpResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const DESK_CODE_TTL_MS = 3 * 60 * 1000;
const USER_1 = 'user-0001';
const USER_2 = 'user-0002';
const TENANTS = [
  { tenantId: 'tenant-a', displayName: 'A社' },
  { tenantId: 'tenant-b', displayName: 'B社' },
] as const;
const CLIENTS = [
  { clientId: 'rp-a-web', tenantId: 'tenant-a' },
  { clientId: 'rp-a-desk', tenantId: 'tenant-a' },
  { clientId: 'rp-b-desk', tenantId: 'tenant-b' },
] as const;

const realFetch = globalThis.fetch;
const blockedOutbound: string[] = [];
const rpKeys = new Map<string, { privateKey: PrivateKey; publicJwk: Record<string, unknown> }>();
/** テストで作った秘密（窓口コード、トークン、client assertion）。保存先に残っていないかを確かめる。 */
const secrets: { label: string; value: string }[] = [];
let clockOffsetMs = 0;
let server: Server;
let issuer: string;
let warifu: SpikeWarifu;

function remember(label: string, value: string): string {
  secrets.push({ label, value });
  return value;
}

/** 平文が含まれていないことを確かめる。失敗しても、秘密そのものはテストの出力に出さない。 */
function expectNoSecretsIn(haystack: string): void {
  const found = secrets.filter(({ value }) => haystack.includes(value)).map(({ label }) => label);
  expect(found).toEqual([]);
}

function cibaClientMetadata(
  clientId: string,
  tenantId: string,
  publicJwk: Record<string, unknown>,
): Record<string, unknown> {
  return {
    client_id: clientId,
    tenant_id: tenantId,
    jwks: { keys: [publicJwk] },
    grant_types: [CIBA_GRANT_TYPE],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    id_token_signed_response_alg: 'ES256',
    backchannel_token_delivery_mode: 'poll',
  };
}

function allClientMetadata(): Record<string, unknown>[] {
  return CLIENTS.map(({ clientId, tenantId }) => {
    const keys = rpKeys.get(clientId);
    if (keys === undefined) {
      throw new Error('テストの鍵がない');
    }
    return cibaClientMetadata(clientId, tenantId, keys.publicJwk);
  });
}

interface AssertionOptions {
  readonly aud?: string;
  readonly alg?: string;
  readonly key?: PrivateKey | Uint8Array;
}

async function clientAssertion(clientId: string, options: AssertionOptions = {}): Promise<string> {
  const keys = rpKeys.get(clientId);
  const key = options.key ?? keys?.privateKey;
  if (key === undefined) {
    throw new Error('テストの鍵がない');
  }
  const kid = options.key === undefined ? keys?.publicJwk.kid : undefined;
  const jwt = await new SignJWT({})
    .setProtectedHeader({
      alg: options.alg ?? 'ES256',
      ...(typeof kid === 'string' ? { kid } : {}),
    })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(options.aud ?? issuer)
    .setIssuedAt()
    .setExpirationTime('2m')
    .setJti(randomUUID())
    .sign(key);
  return remember('client_assertion', jwt);
}

async function postForm(
  path: string,
  form: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<HttpResult> {
  const response = await realFetch(`${issuer}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...headers,
    },
    body: new URLSearchParams(form),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
  };
}

async function backchannel(
  clientId: string,
  params: Record<string, string>,
  assertion?: string,
): Promise<HttpResult> {
  const result = await postForm('/backchannel', {
    client_id: clientId,
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: assertion ?? (await clientAssertion(clientId)),
    scope: 'openid',
    ...params,
  });
  if (typeof result.body.auth_req_id === 'string') {
    remember('auth_req_id', result.body.auth_req_id);
  }
  return result;
}

async function pollToken(clientId: string, authReqId: string): Promise<HttpResult> {
  const result = await postForm('/token', {
    grant_type: CIBA_GRANT_TYPE,
    auth_req_id: authReqId,
    client_id: clientId,
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: await clientAssertion(clientId),
  });
  for (const name of ['access_token', 'id_token', 'refresh_token']) {
    const value = result.body[name];
    if (typeof value === 'string') {
      remember(name, value);
    }
  }
  return result;
}

function issueDeskCode(userId: string, clientId: string): string {
  return remember('desk_code', warifu.deskCodes.issue(userId, clientId, 'phone').code);
}

function latestPending(userId: string) {
  const entry = warifu.inbox
    .listFor(userId)
    .filter((item) => item.state === 'pending')
    .at(-1);
  if (entry === undefined) {
    throw new Error('承認待ちがない');
  }
  return entry;
}

/** 窓口コードの発行 → CIBA の要求 → 端末での承認 → トークンの受け取り、を通す。 */
async function completeCiba(clientId: string, userId: string): Promise<Record<string, unknown>> {
  const started = await backchannel(clientId, {
    login_hint_token: issueDeskCode(userId, clientId),
  });
  expect(started.status).toBe(200);
  await warifu.approve(latestPending(userId).entryId, userId);
  const token = await pollToken(clientId, String(started.body.auth_req_id));
  expect(token.status).toBe(200);
  return token.body;
}

async function verifyIdToken(idToken: string, clientId: string) {
  const response = await realFetch(`${issuer}/jwks`);
  const jwks = createLocalJWKSet((await response.json()) as JSONWebKeySet);
  return jwtVerify(idToken, jwks, { issuer, audience: clientId, algorithms: ['ES256'] });
}

async function subOf(clientId: string, userId: string): Promise<string> {
  const body = await completeCiba(clientId, userId);
  const { payload } = await verifyIdToken(String(body.id_token), clientId);
  return String(payload.sub);
}

beforeAll(async () => {
  for (const { clientId } of CLIENTS) {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = { ...(await exportJWK(publicKey)), kid: `${clientId}-key-1`, alg: 'ES256' };
    rpKeys.set(clientId, { privateKey, publicJwk });
  }

  server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  issuer = `http://127.0.0.1:${port}`;

  warifu = await buildSpikeWarifu({
    issuer,
    tenants: TENANTS,
    clients: allClientMetadata(),
    users: [USER_1, USER_2],
    now: () => Date.now() + clockOffsetMs,
    deskCodeTtlMs: DESK_CODE_TTL_MS,
  });
  server.on('request', warifu.provider.callback());

  // テストの中で、自分のサーバー以外への fetch が起きたら失敗させて数える（不変条件7）。
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(href);
    if (url.origin !== issuer) {
      blockedOutbound.push(url.host);
      throw new Error('outbound blocked in test');
    }
    return realFetch(input, init);
  });
});

afterEach(() => {
  // どのテストでも、oidc-provider が外へつなごうとしていないこと（不変条件7）。
  expect(warifu.outboundAttempts).toEqual([]);
  expect(blockedOutbound).toEqual([]);
  clockOffsetMs = 0;
});

afterAll(async () => {
  vi.unstubAllGlobals();
  server.close();
  await once(server, 'close');
});

describe('1. 正常な1往復（poll）', () => {
  // 攻撃者が持っている情報：なし（正規の企業の窓口が、利用者から窓口コードを受け取った場面）
  // 試す経路：CIBA の要求 → 承認前の poll → 端末での承認 → poll
  // 期待する結果：要求は 200 と auth_req_id。承認前は 400 authorization_pending。承認後は 200 で、
  //   ES256 の ID トークン（aud は client_id、sub はテナント単位）。メールや電話のクレームはない。
  //   同じ auth_req_id での2回目の poll は 400 invalid_grant。保存先に平文の秘密が残らない（plan 11章 テスト7 の一部）。
  it('窓口コードで要求し、承認の後にトークンを受け取る', async () => {
    const started = await backchannel('rp-a-desk', {
      login_hint_token: issueDeskCode(USER_1, 'rp-a-desk'),
    });
    expect(started.status).toBe(200);
    expect(typeof started.body.auth_req_id).toBe('string');
    expect(started.body.expires_in).toBe(300);
    // oidc-provider は interval を返さず、slow_down も行わない（ADR 0006）。
    expect(started.body.interval).toBeUndefined();
    const authReqId = String(started.body.auth_req_id);

    const pending = await pollToken('rp-a-desk', authReqId);
    expect(pending.status).toBe(400);
    expect(pending.body.error).toBe('authorization_pending');

    // 別のクライアント（別のテナントと、同じテナントの別のクライアント）は、この auth_req_id で poll できない。
    for (const other of ['rp-b-desk', 'rp-a-web']) {
      const stolen = await pollToken(other, authReqId);
      expect(stolen.status).toBe(400);
      expect(stolen.body.error).toBe('invalid_grant');
    }

    const entry = latestPending(USER_1);
    expect(entry.companyName).toBe('A社');
    await warifu.approve(entry.entryId, USER_1);

    const token = await pollToken('rp-a-desk', authReqId);
    expect(token.status).toBe(200);
    expect(token.body.token_type).toBe('Bearer');
    expect(typeof token.body.access_token).toBe('string');
    expect(token.body.refresh_token).toBeUndefined();
    const idToken = String(token.body.id_token);

    expect(decodeProtectedHeader(idToken).alg).toBe('ES256');
    const { payload } = await verifyIdToken(idToken, 'rp-a-desk');
    expect(payload.sub).toBe(warifu.deriveSub('tenant-a', USER_1));
    expect(payload.aud).toBe('rp-a-desk');
    expect(payload.acr).toBe(ACR_DESK);
    expect(typeof payload.auth_time).toBe('number');
    for (const claim of ['email', 'email_verified', 'phone_number', 'name', 'address']) {
      expect(payload).not.toHaveProperty(claim);
    }
    expect(Object.keys(payload).sort()).toEqual(
      ['acr', 'aud', 'auth_time', 'exp', 'iat', 'iss', 'sub'].sort(),
    );

    const replay = await pollToken('rp-a-desk', authReqId);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    // 保存先（DB に当たる）、受信箱、窓口コードの保管に、平文の秘密が残っていない（不変条件4）。
    expectNoSecretsIn(warifu.storage.dump());
    expectNoSecretsIn(warifu.inbox.dump());
    expectNoSecretsIn(warifu.deskCodes.dump());
    // oidc-provider の保存先には、割符の内部の利用者 ID も入らない（テナント単位の sub だけ）。
    expect(warifu.storage.dump().includes(USER_1)).toBe(false);
  });
});

describe('2. sub はテナント単位（不変条件5）', () => {
  // 攻撃者が持っている情報：A社とB社の両方で同じ人の sub（両社の結託、または両社からの漏えい）
  // 試す経路：同じ利用者を、A社の2つのクライアントと、B社のクライアントで CIBA に通す
  // 期待する結果：A社の2つのクライアントでは sub が同じ、B社とは別。別の利用者とも別。
  //   sub に内部の利用者 ID は含まれない（plan 11章 テスト4 の sub の部分）。
  it('同じテナントの2つのクライアントで同じ sub、別のテナントでは別の sub になる', async () => {
    const aWeb = await subOf('rp-a-web', USER_1);
    const aDesk = await subOf('rp-a-desk', USER_1);
    const bDesk = await subOf('rp-b-desk', USER_1);
    const otherUser = await subOf('rp-a-desk', USER_2);

    expect(aWeb).toBe(aDesk);
    expect(bDesk).not.toBe(aDesk);
    expect(otherUser).not.toBe(aDesk);
    expect(aDesk.includes(USER_1)).toBe(false);
  });
});

describe('3. hint は窓口コードだけ（不変条件6）', () => {
  // 攻撃者が持っている情報：利用者の sub やログイン名、過去に受け取った本物の ID トークン（企業が侵害された場面）
  // 試す経路：CIBA の要求に login_hint、id_token_hint、user_code を付ける。hint を付けない
  // 期待する結果：どれも 400 invalid_request で、受信箱に何も届かない（plan 11章 テスト2）
  it('login_hint を拒否する', async () => {
    const before = warifu.inbox.listFor(USER_1).length;
    const result = await backchannel('rp-a-desk', { login_hint: USER_1 });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('invalid_request');
    expect(result.body.error_description).toBe(
      'login_hint is not accepted; use login_hint_token only',
    );
    expect(warifu.inbox.listFor(USER_1).length).toBe(before);
  });

  it('本物の ID トークンでも id_token_hint を拒否する', async () => {
    const issued = await completeCiba('rp-a-desk', USER_1);
    const before = warifu.inbox.listFor(USER_1).length;
    const result = await backchannel('rp-a-desk', { id_token_hint: String(issued.id_token) });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('invalid_request');
    expect(result.body.error_description).toBe(
      'id_token_hint is not accepted; use login_hint_token only',
    );
    expect(warifu.inbox.listFor(USER_1).length).toBe(before);
  });

  it('user_code を、窓口コードに触れる前に拒否する', async () => {
    const code = issueDeskCode(USER_1, 'rp-a-desk');
    const before = warifu.inbox.listFor(USER_1).length;
    const result = await backchannel('rp-a-desk', { login_hint_token: code, user_code: '1234' });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('invalid_request');
    expect(result.body.error_description).toBe(
      'user_code is not accepted; use login_hint_token only',
    );
    expect(warifu.inbox.listFor(USER_1).length).toBe(before);
    // 入口で止めたので、窓口コードはまだ照合されていない。
    const retry = await backchannel('rp-a-desk', { login_hint_token: code });
    expect(retry.status).toBe(200);
  });

  it('窓口コードと login_hint を同時に付けても拒否する', async () => {
    const result = await backchannel('rp-a-desk', {
      login_hint_token: issueDeskCode(USER_1, 'rp-a-desk'),
      login_hint: USER_1,
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('invalid_request');
  });

  it('hint がない要求を拒否する', async () => {
    const result = await backchannel('rp-a-desk', {});
    expect(result.status).toBe(400);
    expect(result.body.error).toBe('invalid_request');
    expect(result.body.error_description).toBe('login_hint_token is required');
  });
});

describe('4. 窓口コードの性質', () => {
  // 攻撃者が持っている情報：利用者が一度伝えた窓口コード、または別のテナント向けの窓口コード
  // 試す経路：使用済みのコード、別のテナント（と同じテナントの別のクライアント）での使用、期限切れのコード、形式の違う値
  // 期待する結果：どれも 400 unknown_user_id で、応答の本文はすべて同じ（存在の有無を区別させない）。
  //   別のクライアントに出したコードは、その時点で失効する（plan 11章 テスト2）
  it('使用済み、別のテナント、期限切れ、形式違いのコードを、同じ応答で拒否する', async () => {
    const used = issueDeskCode(USER_1, 'rp-a-desk');
    expect((await backchannel('rp-a-desk', { login_hint_token: used })).status).toBe(200);
    const reused = await backchannel('rp-a-desk', { login_hint_token: used });

    const forTenantA = issueDeskCode(USER_1, 'rp-a-desk');
    const crossTenant = await backchannel('rp-b-desk', { login_hint_token: forTenantA });
    // 別のテナントで一度照合されたので、本来のクライアントでも使えない。
    const afterCrossTenant = await backchannel('rp-a-desk', { login_hint_token: forTenantA });

    const forDesk = issueDeskCode(USER_1, 'rp-a-desk');
    const otherClientSameTenant = await backchannel('rp-a-web', { login_hint_token: forDesk });

    const expiring = issueDeskCode(USER_1, 'rp-a-desk');
    clockOffsetMs = DESK_CODE_TTL_MS + 1000;
    const expired = await backchannel('rp-a-desk', { login_hint_token: expiring });
    clockOffsetMs = 0;

    const malformed = await backchannel('rp-a-desk', { login_hint_token: 'not-a-desk-code' });

    const failures = [
      reused,
      crossTenant,
      afterCrossTenant,
      otherClientSameTenant,
      expired,
      malformed,
    ];
    for (const failure of failures) {
      expect(failure.status).toBe(400);
      expect(failure.body).toEqual({
        error: 'unknown_user_id',
        error_description: 'could not identify end-user',
      });
    }
  });
});

describe('5. 企業が送った binding_message は表示しない', () => {
  // 攻撃者が持っている情報：企業の資格情報（侵害された企業、または悪意のある窓口担当者）
  // 試す経路：CIBA の要求に、利用者をだます binding_message を付ける
  // 期待する結果：要求は受け付けるが（200）、受信箱には割符が生成した文言だけが入り、企業の文言は
  //   受信箱にも保存先にも残らない（plan 11章 テスト2）
  it('受信箱には、割符の登録簿の企業名と操作の種類だけが入る', async () => {
    const lure = remember('binding_message', '返金先の変更を承認してください');
    const result = await backchannel('rp-b-desk', {
      login_hint_token: issueDeskCode(USER_2, 'rp-b-desk'),
      binding_message: lure,
    });
    expect(result.status).toBe(200);

    const entry = latestPending(USER_2);
    expect(entry).toMatchObject({
      kind: 'ciba-approval',
      companyName: 'B社',
      channel: 'phone',
      operation: '窓口での本人確認',
      scopeNote: '照会と軽い手続きだけ',
      bindingMessage: 'B社の電話窓口での本人確認',
      warning: 'A-1',
    });
    expect(warifu.inbox.dump().includes(lure)).toBe(false);
    expect(warifu.storage.dump().includes(lure)).toBe(false);
  });
});

describe('6. 利用者が拒否した場合', () => {
  // 攻撃者が持っている情報：だまして聞き出した窓口コード（利用者は心当たりがなく、拒否する）
  // 試す経路：CIBA の要求 → 端末での拒否 → poll
  // 期待する結果：poll は 400 access_denied で、ID トークンは出ない（plan 11章 テスト1 の一部）
  it('拒否すると access_denied になる', async () => {
    const started = await backchannel('rp-a-desk', {
      login_hint_token: issueDeskCode(USER_2, 'rp-a-desk'),
    });
    expect(started.status).toBe(200);
    const entry = latestPending(USER_2);
    await warifu.deny(entry.entryId, USER_2);
    expect(warifu.inbox.listFor(USER_2).find((item) => item.entryId === entry.entryId)?.state).toBe(
      'denied',
    );

    const token = await pollToken('rp-a-desk', String(started.body.auth_req_id));
    expect(token.status).toBe(400);
    expect(token.body.error).toBe('access_denied');
    // backchannelResult は説明を error_description に入れるが、保存する項目は errorDescription なので、
    // 説明は企業に届かない（lib/provider.js と lib/models/backchannel_authentication_request.js）。
    expect(token.body.error_description).toBeUndefined();
    expect(token.body.id_token).toBeUndefined();
  });

  it('持ち主でない利用者は、承認も拒否もできない', async () => {
    await backchannel('rp-a-desk', { login_hint_token: issueDeskCode(USER_1, 'rp-a-desk') });
    const entry = latestPending(USER_1);
    await expect(warifu.approve(entry.entryId, USER_2)).rejects.toThrow('承認待ちが見つからない');
    await expect(warifu.deny(entry.entryId, USER_2)).rejects.toThrow('承認待ちが見つからない');
  });

  // 攻撃者が持っている情報：だまして聞き出した窓口コード（利用者は拒否し、同じ承認待ちに承認も届く。
  //   二重の送信や、端末を2台持つ場面）
  // 試す経路：同じ承認待ちに、拒否と承認を同時に送る（順番も入れ替える）
  // 期待する結果：成功するのは先に送った方だけで、もう一方は「承認待ちが見つからない」で失敗する。
  //   拒否が先なら、poll は 400 access_denied で、Grant は作られない（plan 11章 テスト1 の一部）
  it.each([
    ['拒否', '承認'],
    ['承認', '拒否'],
  ])('%sと%sが同時に届いても、先に届いた方だけが効く', async (first) => {
    const started = await backchannel('rp-a-desk', {
      login_hint_token: issueDeskCode(USER_2, 'rp-a-desk'),
    });
    expect(started.status).toBe(200);
    const entry = latestPending(USER_2);
    const grantsBefore = warifu.storage.keysWhere('Grant', () => true).length;
    const deny = () => warifu.deny(entry.entryId, USER_2);
    const approve = () => warifu.approve(entry.entryId, USER_2);
    const [winner, loser] = await Promise.allSettled(
      first === '拒否' ? [deny(), approve()] : [approve(), deny()],
    );
    expect(winner?.status).toBe('fulfilled');
    expect(loser).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({ message: '承認待ちが見つからない' }),
    });

    const state = warifu.inbox
      .listFor(USER_2)
      .find((item) => item.entryId === entry.entryId)?.state;
    const token = await pollToken('rp-a-desk', String(started.body.auth_req_id));
    const grantsAfter = warifu.storage.keysWhere('Grant', () => true).length;
    if (first === '拒否') {
      expect(state).toBe('denied');
      expect(token.status).toBe(400);
      expect(token.body.error).toBe('access_denied');
      expect(token.body.id_token).toBeUndefined();
      expect(grantsAfter).toBe(grantsBefore);
    } else {
      expect(state).toBe('approved');
      expect(token.status).toBe(200);
      expect(grantsAfter).toBe(grantsBefore + 1);
    }
  });
});

describe('7. 外へ取りに行く値を受け付けない（不変条件7）', () => {
  // 攻撃者が持っている情報：クライアントの登録の内容を書き換えられる立場（侵害されたテナントの登録申請など）
  // 試す経路：jwks_uri、sector_identifier_uri、request_uris などを含む静的なクライアント。
  //   CIBA の要求に request と request_uri を付ける
  // 期待する結果：Provider を作る前に拒否する。Provider に渡っても Client を作る段階で拒否する。
  //   要求は 400（request_not_supported、request_uri_not_supported）。外へのつなぎは0回（plan 11章 テスト11 の一部）
  it.each([
    ['jwks_uri', 'https://rp.invalid/jwks.json'],
    ['sector_identifier_uri', 'https://rp.invalid/sector.json'],
    ['request_uris', ['https://rp.invalid/request.jwt']],
    ['backchannel_client_notification_endpoint', 'https://rp.invalid/notify'],
    ['subject_type', 'pairwise'],
    ['client_name', '企業が付けた名前'],
  ])('静的なクライアントの %s を、Provider を作る前に拒否する', async (key, value) => {
    const keys = rpKeys.get('rp-a-desk');
    if (keys === undefined) {
      throw new Error('テストの鍵がない');
    }
    const metadata = { ...cibaClientMetadata('rp-x', 'tenant-a', keys.publicJwk), [key]: value };
    await expect(
      buildSpikeWarifu({ issuer, tenants: TENANTS, clients: [metadata], users: [USER_1] }),
    ).rejects.toThrow(StaticClientError);
  });

  it.each(['jwks_uri', 'sector_identifier_uri', 'backchannel_client_notification_endpoint'])(
    '事前検査をすり抜けた %s も、Client を作る段階で拒否する',
    async (key) => {
      await expect(
        warifu.provider.Client.validate({
          client_id: 'rp-x',
          tenant_id: 'tenant-a',
          grant_types: [CIBA_GRANT_TYPE],
          response_types: [],
          token_endpoint_auth_method: 'private_key_jwt',
          backchannel_token_delivery_mode: 'poll',
          [key]: 'https://rp.invalid/x',
        }),
      ).rejects.toMatchObject({
        error: 'invalid_client_metadata',
        error_description: `${key} is not accepted`,
      });
    },
  );

  it('oidc-provider は request_uris を認識せず、黙って捨てる（だから事前検査で止める）', async () => {
    const keys = rpKeys.get('rp-a-desk');
    if (keys === undefined) {
      throw new Error('テストの鍵がない');
    }
    await expect(
      warifu.provider.Client.validate({
        ...cibaClientMetadata('rp-x', 'tenant-a', keys.publicJwk),
        client_id: 'rp-x',
        request_uris: ['https://rp.invalid/request.jwt'],
      }),
    ).resolves.toBeUndefined();
  });

  // 調査：pairwise の CIBA クライアントを、jwks_uri なしで作れるか。
  // lib/helpers/client_schema.js の required() は、CIBA で pairwise なら jwks_uri を必須にする。
  // sector_identifier_uri が必須になるのは、response_types が空でないときだけ（CIBA だけのクライアントでは不要）。
  // sector_identifier_uri を付けても、jwks_uri の必須は外れない。jwks と jwks_uri は同時に使えない。
  // jwks_uri だけなら検証は通るが、鍵は最初のクライアント認証のときに取りに行く（lib/models/client.js の
  // ClientKeyStore.refresh）。どの組み合わせでも、割符の鍵の受け取り方（jwks だけ）とは両立しない。
  it.each([
    ['jwks だけ', {}, 'jwks_uri is mandatory property'],
    [
      'jwks と sector_identifier_uri',
      { sector_identifier_uri: 'https://rp.invalid/sector.json' },
      'jwks_uri is mandatory property',
    ],
    [
      'jwks と jwks_uri',
      { jwks_uri: 'https://rp.invalid/jwks.json' },
      'jwks and jwks_uri must not be used at the same time',
    ],
    ['jwks_uri だけ', { jwks_uri: 'https://rp.invalid/jwks.json', jwks: undefined }, undefined],
  ])(
    'pairwise の CIBA クライアント（%s）を oidc-provider に渡すとどうなるか',
    async (_label, extra, error) => {
      const keys = rpKeys.get('rp-a-desk');
      if (keys === undefined) {
        throw new Error('テストの鍵がない');
      }
      const fetchCalls: string[] = [];
      const unused = async (): Promise<never> => {
        throw new Error('このテストでは呼ばれない');
      };
      const probeKey = await generateKeyPair('ES256', { extractable: true });
      const probe = new Provider(issuer, {
        adapter: new HmacMemoryStore().adapterFactory(),
        subjectTypes: ['public', 'pairwise'],
        pairwiseIdentifier: unused,
        clientAuthMethods: ['private_key_jwt'],
        // sector_identifier_uri の取得（lib/helpers/sector_validate.js）は、required() の後に走る。
        // ここでは取得を止めて、required() の結果だけを見る。
        sectorIdentifierUriValidate: () => false,
        // 割符と同じく ES256 だけにする（既定の idTokenSigningAlgValues は RS256 だけ）。
        // 署名の alg は、Provider の鍵にあるものだけが使えるので、ES256 の鍵も渡す。
        jwks: { keys: [{ ...(await exportJWK(probeKey.privateKey)), alg: 'ES256', use: 'sig' }] },
        enabledJWA: {
          clientAuthSigningAlgValues: ['ES256'],
          idTokenSigningAlgValues: ['ES256'],
        },
        features: {
          devInteractions: { enabled: false },
          ciba: {
            enabled: true,
            deliveryModes: ['poll'],
            triggerAuthenticationDevice: unused,
            validateRequestContext: unused,
            verifyUserCode: unused,
          },
        },
        fetch: async (input) => {
          fetchCalls.push(String(input));
          throw new Error('outbound blocked in test');
        },
      });
      // tenant_id は、このプローブでは認識されない項目として捨てられる（lib/helpers/client_schema.js）。
      const pairwise = {
        ...cibaClientMetadata('rp-p', 'tenant-a', keys.publicJwk),
        client_id: 'rp-p',
        subject_type: 'pairwise' as const,
        ...extra,
      };
      if (error === undefined) {
        await expect(probe.Client.validate(pairwise)).resolves.toBeUndefined();
      } else {
        await expect(probe.Client.validate(pairwise)).rejects.toMatchObject({
          error: 'invalid_client_metadata',
          error_description: error,
        });
      }
      expect(fetchCalls).toEqual([]);
    },
  );

  it('CIBA の要求の request と request_uri を拒否する', async () => {
    const code = issueDeskCode(USER_1, 'rp-a-desk');
    const byRequest = await backchannel('rp-a-desk', {
      login_hint_token: code,
      request: 'eyJhbGciOiJub25lIn0.e30.',
    });
    expect(byRequest.status).toBe(400);
    expect(byRequest.body.error).toBe('request_not_supported');

    const byRequestUri = await backchannel('rp-a-desk', {
      login_hint_token: code,
      request_uri: 'https://rp.invalid/request.jwt',
    });
    expect(byRequestUri.status).toBe(400);
    expect(byRequestUri.body.error).toBe('request_uri_not_supported');
  });

  it('動的なクライアント登録の経路がない', async () => {
    const response = await realFetch(`${issuer}/reg`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jwks_uri: 'https://rp.invalid/jwks.json' }),
    });
    expect(response.status).toBe(404);
  });

  it('discovery が、許した方式だけを示す', async () => {
    const response = await realFetch(`${issuer}/.well-known/openid-configuration`);
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata).toMatchObject({
      backchannel_token_delivery_modes_supported: ['poll'],
      backchannel_user_code_parameter_supported: false,
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      id_token_signing_alg_values_supported: ['ES256'],
      subject_types_supported: ['public'],
      request_uri_parameter_supported: false,
      grant_types_supported: [CIBA_GRANT_TYPE],
    });
    expect(metadata.registration_endpoint).toBeUndefined();
    expect(metadata.request_parameter_supported).toBeUndefined();
    expect(
      metadata.backchannel_authentication_request_signing_alg_values_supported,
    ).toBeUndefined();
    expect(metadata.userinfo_endpoint).toBeUndefined();
    expect(metadata.pushed_authorization_request_endpoint).toBeUndefined();
  });
});

describe('8. クライアント認証は ES256 の private_key_jwt だけ（不変条件9）', () => {
  // 攻撃者が持っている情報：client_id（秘密ではない）。共有鍵や、登録されていない鍵
  // 試す経路：HS256、RS256、alg なし、登録されていない ES256 の鍵、aud の取り違え、client_secret_basic で認証する
  // 期待する結果：どれも 401 invalid_client で、受信箱に何も届かない（plan 11章 テスト8 の一部）
  it('ES256 以外の client assertion と、ほかの認証方式を拒否する', async () => {
    const before = warifu.inbox.listFor(USER_1).length;
    const code = issueDeskCode(USER_1, 'rp-a-desk');

    const hs256 = await clientAssertion('rp-a-desk', {
      alg: 'HS256',
      key: new TextEncoder().encode('a-shared-secret-that-is-long-enough!!'),
    });
    const rsa = await generateKeyPair('RS256');
    const rs256 = await clientAssertion('rp-a-desk', { alg: 'RS256', key: rsa.privateKey });
    const unsecured = remember(
      'client_assertion',
      new UnsecuredJWT({ jti: randomUUID() })
        .setIssuer('rp-a-desk')
        .setSubject('rp-a-desk')
        .setAudience(issuer)
        .setIssuedAt()
        .setExpirationTime('2m')
        .encode(),
    );
    const stranger = await generateKeyPair('ES256');
    const unregistered = await clientAssertion('rp-a-desk', { key: stranger.privateKey });
    const tokenEndpointAud = await clientAssertion('rp-a-desk', { aud: `${issuer}/token` });
    const endpointAud = await clientAssertion('rp-a-desk', { aud: `${issuer}/backchannel` });

    for (const assertion of [
      hs256,
      rs256,
      unsecured,
      unregistered,
      tokenEndpointAud,
      endpointAud,
    ]) {
      const result = await backchannel('rp-a-desk', { login_hint_token: code }, assertion);
      expect(result.status).toBe(401);
      expect(result.body.error).toBe('invalid_client');
    }

    const basic = await postForm(
      '/backchannel',
      { scope: 'openid', login_hint_token: code },
      { authorization: `Basic ${Buffer.from('rp-a-desk:guess').toString('base64')}` },
    );
    expect(basic.status).toBe(401);
    expect(basic.body.error).toBe('invalid_client');

    expect(warifu.inbox.listFor(USER_1).length).toBe(before);
    // クライアント認証で止まったので、窓口コードはまだ照合されていない。
    expect((await backchannel('rp-a-desk', { login_hint_token: code })).status).toBe(200);
  });

  // 攻撃者が持っている情報：なし（設定の確認。M3 の画面とセッションのクッキーは、この設定の上に作る）
  // 試す経路：oidc-provider が Koa に渡したクッキーの署名の鍵で、署名して検証する
  // 期待する結果：署名は HMAC-SHA-256 の長さ（32バイトの base64url で43文字）で、Keygrip の既定の
  //   HMAC-SHA1（27文字）ではない。別の値の署名は検証を通らない（plan 11章 テスト8 の一部）
  it('クッキーの署名は HMAC-SHA-256 になる', () => {
    const keys = warifu.provider.keys;
    expect(Array.isArray(keys)).toBe(false);
    if (keys === undefined || Array.isArray(keys)) {
      throw new Error('クッキーの署名の鍵が、Keygrip の形で渡っていない');
    }
    const signature = keys.sign('_probe=value');
    expect(signature).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(keys.verify('_probe=value', signature)).toBe(true);
    expect(keys.verify('_probe=other', signature)).toBe(false);
  });

  it('トークンエンドポイントでも ES256 以外を拒否する', async () => {
    const started = await backchannel('rp-a-desk', {
      login_hint_token: issueDeskCode(USER_1, 'rp-a-desk'),
    });
    const hs256 = await clientAssertion('rp-a-desk', {
      alg: 'HS256',
      key: new TextEncoder().encode('a-shared-secret-that-is-long-enough!!'),
    });
    const result = await postForm('/token', {
      grant_type: CIBA_GRANT_TYPE,
      auth_req_id: String(started.body.auth_req_id),
      client_id: 'rp-a-desk',
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: hs256,
    });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe('invalid_client');
  });

  it('登録されていない client_id を拒否する（アダプタからクライアントを探しても見つからない）', async () => {
    const stranger = await generateKeyPair('ES256');
    const assertion = await clientAssertion('rp-unknown', { key: stranger.privateKey });
    const result = await backchannel(
      'rp-unknown',
      { login_hint_token: issueDeskCode(USER_1, 'rp-a-desk') },
      assertion,
    );
    expect(result.status).toBe(401);
    expect(result.body.error).toBe('invalid_client');
  });
});

describe('9. 調査：保存アダプタから、認証済みのクライアントが分かるか（不変条件8）', () => {
  // 攻撃者が持っている情報：なし（設計の確認。アダプタを withTenant の中で動かせるかを確かめる）
  // 試す経路：poll のときに、アダプタの読み出しの中で Provider.ctx（AsyncLocalStorage）を見る。
  //   端末での承認（要求の外）でも見る
  // 期待する結果：要求の中では、認証済みのクライアントの client_id が見える。要求の外では見えない
  it('要求の中では Provider.ctx から client_id が分かり、承認の経路では分からない', async () => {
    const started = await backchannel('rp-b-desk', {
      login_hint_token: issueDeskCode(USER_2, 'rp-b-desk'),
    });
    const seen: { during: string; clientId: string | undefined }[] = [];
    const originalGet = warifu.storage.get.bind(warifu.storage);
    let during = 'approve';
    warifu.storage.get = (key: string) => {
      if (key.startsWith('BackchannelAuthenticationRequest:')) {
        seen.push({ during, clientId: Provider.ctx?.oidc.client?.clientId });
      }
      return originalGet(key);
    };
    try {
      await warifu.approve(latestPending(USER_2).entryId, USER_2);
      during = 'poll';
      const token = await pollToken('rp-b-desk', String(started.body.auth_req_id));
      expect(token.status).toBe(200);
    } finally {
      warifu.storage.get = originalGet;
    }
    expect(seen).toContainEqual({ during: 'approve', clientId: undefined });
    expect(seen).toContainEqual({ during: 'poll', clientId: 'rp-b-desk' });
  });
});
