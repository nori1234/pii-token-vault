// 窓口の操作別承認のテストの補助（ADR 0026）。idp、company-api（idp からの内部 API）、sender（取消の SET の配送）を
// 1つのテストの中で立て、企業のサーバーの役（PAR、トークン、操作ごとの承認の検証、作成の知らせ、取消の結果の報告）を
// テストの中で行う。企業の側の参照実装（rp-kit）は M9 で作る。ここの検証は、その手前のテストのためのもの。

import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import type { DeskAction } from '../../packages/warifu-core/src/desk/protocol.ts';
import { parseTenantId } from '../../packages/warifu-core/src/ids.ts';
import { startTestCompanyApi, type TestCompanyApi } from './company-api.ts';
import {
  Browser,
  clientAssertion,
  codeFlow,
  redeemCode,
  startTestIdp,
  type TestClient,
  type TestIdp,
} from './idp.ts';
import {
  makeTlsFixture,
  PUBLIC_V4,
  startTestSender,
  type TestSender,
  WEBHOOK_HOST,
} from './sender.ts';

export const ALL_DESK_ACTIONS: readonly DeskAction[] = [
  'desk.case.status.read',
  'desk.order.status.read',
  'desk.case.create',
];
export const OP_APPROVAL_TYP = 'warifu-op-approval+jwt';

export interface DeskWorld {
  readonly t: TestIdp;
  readonly company: TestCompanyApi;
  readonly sender: TestSender;
  stop(): Promise<void>;
}

/**
 * テナントを tenants 個作り、idp のクライアントを clients のとおりに作る。company-api には、同じテナントを、
 * scope desk を許したクライアントと、テナントごとの SET の受け口（/set/<番号>）で登録する。
 */
export async function startDeskWorld(spec: {
  readonly tenants: number;
  readonly clients: readonly {
    readonly tenant: number;
    readonly deskActions?: readonly DeskAction[];
  }[];
  readonly now?: () => Date;
}): Promise<DeskWorld> {
  const dir = await mkdtemp(join(tmpdir(), 'warifu-desk-'));
  const secret = randomBytes(32);
  const tenantIds = Array.from({ length: spec.tenants }, () => randomUUID());
  const sender = await startTestSender(
    { A: { [WEBHOOK_HOST]: [PUBLIC_V4] } },
    await makeTlsFixture(),
  );
  const company = await startTestCompanyApi({
    tenants: tenantIds.map((tenantId, i) => ({
      tenantId: parseTenantId(tenantId),
      webhookUrl: `https://${WEBHOOK_HOST}/set/${i}`,
      scopes: ['company_api', 'desk'] as const,
    })),
    sender: { socketPath: sender.sender.socketPath, credential: sender.credentials['company-api'] },
    deskInternal: { socketPath: join(dir, 'company-api.sock'), credentials: { idp: secret } },
    ...(spec.now === undefined ? {} : { now: spec.now }),
  });
  const t = await startTestIdp(
    {
      tenants: spec.tenants,
      clients: spec.clients.map((c) => ({
        tenant: c.tenant,
        deskActions: c.deskActions ?? ALL_DESK_ACTIONS,
      })),
    },
    spec.now,
    {
      tenantIds,
      desk: {
        socketPath: join(dir, 'company-api.sock'),
        credential: `idp.${secret.toString('base64url')}`,
      },
    },
  );
  return {
    t,
    company,
    sender,
    async stop() {
      await t.stop();
      await company.stop();
      await sender.stop();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/** 申請（authorization_details の1件）。既定は一般問い合わせの作成。 */
export function deskDetail(
  sub: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: 'warifu_desk',
    actions: ['desk.case.create'],
    identifier: randomBytes(16).toString('base64url'),
    subject: sub,
    choices: { category: 'general', language: 'ja' },
    ...overrides,
  };
}

export interface ParResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly requestUri?: string;
  readonly verifier: string;
  readonly state: string;
  readonly nonce: string;
}

/** 企業のサーバー役：PAR の受け口に、申請を送る（client assertion の aud は issuer）。 */
export async function pushRequest(
  t: TestIdp,
  client: TestClient,
  authorizationDetails: unknown,
  extra: Record<string, string> = {},
  options: { readonly assertion?: boolean } = {},
): Promise<ParResult> {
  const verifier = randomBytes(32).toString('base64url');
  const { createHash } = await import('node:crypto');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(12).toString('base64url');
  const nonce = randomBytes(12).toString('base64url');
  const form = new URLSearchParams({
    client_id: client.clientId,
    response_type: 'code',
    redirect_uri: client.redirectUri,
    scope: 'openid',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    max_age: '0',
    ...(authorizationDetails === undefined
      ? {}
      : {
          authorization_details:
            typeof authorizationDetails === 'string'
              ? authorizationDetails
              : JSON.stringify(authorizationDetails),
        }),
    ...(options.assertion === false
      ? {}
      : {
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await clientAssertion(t, client),
        }),
    ...extra,
  });
  const response = await fetch(`${t.issuer}/request`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = {};
  }
  return {
    status: response.status,
    body,
    ...(typeof body.request_uri === 'string' ? { requestUri: body.request_uri } : {}),
    verifier,
    state,
    nonce,
  };
}

/** 利用者のブラウザ：request_uri で認可の入口に来て、承認用のオリジンへ引き継がれるまで進む。uid を返す。 */
export async function arriveAtDesk(
  browser: Browser,
  client: TestClient,
  requestUri: string,
): Promise<{ uid: string | undefined; external: URL | undefined; status: number }> {
  const params = new URLSearchParams({ client_id: client.clientId, request_uri: requestUri });
  const followed = await browser.follow(`/oidc/auth?${params}`);
  const external = followed.external;
  const uid = external?.pathname === '/desk' ? external.hash.slice(1) : undefined;
  return { uid, external, status: followed.last.status };
}

/** 承認用のオリジンで承認する（相手からの電話かの問いに「自分から」と答えたことにする）。 */
export async function approveDesk(
  approval: Browser,
  uid: string,
  options: { readonly call?: string; readonly origin?: string } = {},
) {
  const started = await approval.post('/api/desk/approve/options', {
    uid,
    call: options.call ?? 'self',
  });
  if (started.status !== 200) return started;
  const response = approval.authenticator.get(started.json.options as never, undefined, {
    origin: options.origin ?? approval.origin,
  });
  return approval.post('/api/desk/approve/verify', {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
}

/** 利用者を作り、その企業に接続する（通常のログインと同意）。sub を返す。 */
export async function connectedUser(
  world: DeskWorld,
  client: TestClient,
  browser: Browser = new Browser(world.t.origin),
): Promise<{ browser: Browser; approval: Browser; sub: string }> {
  const flow = await codeFlow(world.t, browser, client, { mode: 'register' });
  const approval = new Browser(world.t.approvalOrigin, browser.authenticator);
  return { browser, approval, sub: String(flow.claims.sub) };
}

export interface DeskOutcome {
  readonly uid: string;
  readonly approve: Awaited<ReturnType<typeof approveDesk>>;
  readonly external?: URL;
  readonly tokenResponse?: Record<string, unknown>;
  readonly approvalJwt?: string;
  readonly claims?: Record<string, unknown>;
}

/** 1往復：PAR → 入口 → 承認用のオリジンで承認 → インタラクションの完了 → トークン。 */
export async function deskFlow(
  world: DeskWorld,
  user: { readonly browser: Browser; readonly approval: Browser },
  client: TestClient,
  detail: Record<string, unknown>,
): Promise<DeskOutcome> {
  const par = await pushRequest(world.t, client, [detail]);
  if (par.requestUri === undefined)
    throw new Error(`PAR が失敗した（${par.status} ${JSON.stringify(par.body)}）`);
  const arrived = await arriveAtDesk(user.browser, client, par.requestUri);
  if (arrived.uid === undefined) throw new Error('承認用のオリジンに引き継がれない');
  const approve = await approveDesk(user.approval, arrived.uid);
  if (approve.status !== 200) return { uid: arrived.uid, approve };
  const finished = await user.browser.follow(String(approve.json.redirectTo));
  if (finished.external === undefined) return { uid: arrived.uid, approve };
  if (finished.external.searchParams.get('code') === null) {
    return { uid: arrived.uid, approve, external: finished.external };
  }
  const redeemed = await redeemCode(world.t, client, finished.external, par.verifier, par.state);
  const details = redeemed.tokenResponse.authorization_details as
    | { approval?: unknown }[]
    | undefined;
  const jwt = details?.[0]?.approval;
  return {
    uid: arrived.uid,
    approve,
    external: finished.external,
    tokenResponse: redeemed.tokenResponse,
    claims: redeemed.claims,
    ...(typeof jwt === 'string' ? { approvalJwt: jwt } : {}),
  };
}

/** 企業のサーバー役：操作ごとの承認の JWT を検証する（rp-kit の手前の、テストの中の検査）。 */
export async function verifyOpApproval(
  t: TestIdp,
  jwt: string,
  expected: { readonly clientId: string },
) {
  const jwks = (await (await fetch(`${t.origin}/op-approval/jwks`)).json()) as JSONWebKeySet;
  const header = decodeProtectedHeader(jwt);
  if (header.typ !== OP_APPROVAL_TYP) throw new Error('typ が違う');
  const { payload } = await jwtVerify(jwt, createLocalJWKSet(jwks), {
    issuer: t.issuer,
    audience: expected.clientId,
    algorithms: ['ES256'],
    typ: OP_APPROVAL_TYP,
    requiredClaims: ['sub', 'purpose', 'action', 'request_id', 'iat', 'exp', 'jti'],
  });
  return payload as Record<string, unknown>;
}

/** idp の項目 ID を、受信箱（承認用のオリジン）から引く。 */
export async function deskItems(approval: Browser): Promise<Record<string, unknown>[]> {
  const result = await approval.get('/api/desk-items');
  if (result.status !== 200) throw new Error(`窓口の項目を読めない（${result.status}）`);
  return result.json.items as Record<string, unknown>[];
}

/** 承認用のオリジンで、窓口の作成の項目を取り消す。 */
export async function cancelDeskItem(approval: Browser, id: string) {
  const started = await approval.post('/api/desk-items/cancel/options', { id });
  if (started.status !== 200) return started;
  const response = approval.authenticator.get(started.json.options as never, undefined, {
    origin: approval.origin,
  });
  return approval.post('/api/desk-items/cancel/verify', {
    ceremonyId: started.json.ceremonyId,
    response,
  });
}

/** PWA（本来のオリジン）にパスキーでログインする（受信箱を読むため）。 */
export async function pwaLogin(browser: Browser) {
  const options = await browser.post('/api/login/options');
  const response = browser.authenticator.get(options.json.options as never, undefined, {
    origin: browser.origin,
  });
  return browser.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response });
}
