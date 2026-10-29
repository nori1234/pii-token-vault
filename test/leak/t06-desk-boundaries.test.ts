// テスト6：窓口の境界（plan 11章 テスト6、ADR 0026 の O-63〜O-65、O-70）。
// 利用者 U1 は U2 の窓口の項目に触れない。A社のトークンでB社の変更に触れない。scope の違うトークンは 403。
// idp からの内部 API は、idp の資格情報だけで、頼んだ利用者の行だけを扱う。PAR と取消にレート制限が効く。

import { randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDeskClient } from '../../packages/warifu-core/src/desk/client.ts';
import { parseTenantId, parseWarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { udsPost } from '../../packages/warifu-core/src/internal/uds-client.ts';
import { userIdOf } from '../setup/approvals.ts';
import {
  connectedUser,
  type DeskWorld,
  deskDetail,
  deskFlow,
  deskItems,
  pushRequest,
  startDeskWorld,
} from '../setup/desk.ts';

let world: DeskWorld;
let u1: Awaited<ReturnType<typeof connectedUser>>;
let u2: Awaited<ReturnType<typeof connectedUser>>;

beforeAll(async () => {
  world = await startDeskWorld({ tenants: 2, clients: [{ tenant: 0 }, { tenant: 1 }] });
  u1 = await connectedUser(world, client(0));
  u2 = await connectedUser(world, client(0));
});

afterAll(async () => {
  await world?.stop();
});

function client(index: number) {
  const found = world.t.clients[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

function tenant(index: number) {
  const found = world.company.tenants[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

async function created(user: typeof u1) {
  const detail = deskDetail(user.sub);
  const flow = await deskFlow(world, user, client(0), detail);
  return { detail, changeId: String(decodeJwt(String(flow.approvalJwt)).change_id) };
}

describe('漏えい：窓口の境界（plan 11章 テスト6）', () => {
  it('利用者 U1 は、U2 の窓口の項目を一覧で見られず、ID を知っていても取り消せない', async () => {
    // 攻撃者が持っている情報：利用者 U1 の正規のアカウントと、U2 の窓口の項目の ID（画面や通信から盗んだ）
    // 試す経路：U1 の承認用のオリジンで、項目の一覧を読む。U2 の項目の ID と、知らない ID で取消の選択肢を求める
    // 期待する結果：一覧に U2 の項目はない。どちらの ID も同じ 400 {"error":"failed"}。U2 の項目は取り消されない
    // plan 11章：テスト6（D-41）
    await created(u2);
    await u2.approval.approvalLogin();
    const [theirs] = await deskItems(u2.approval);
    await u1.approval.approvalLogin();
    expect((await deskItems(u1.approval)).map((item) => item.id)).not.toContain(theirs?.id);
    for (const id of [String(theirs?.id), randomUUID()]) {
      const result = await u1.approval.post('/api/desk-items/cancel/options', { id });
      expect([result.status, result.text]).toEqual([400, '{"error":"failed"}']);
    }
    expect((await deskItems(u2.approval))[0]).toMatchObject({ state: 'awaiting_notice' });
  });

  it('企業向けの窓口のルートは、テナントの JWT（scope desk）がなければ使えず、別のテナントの変更には届かない', async () => {
    // 攻撃者が持っている情報：B社の正規のトークン（侵害されたテナント ATK-03）と、A社の変更ID と申請ID
    // 試す経路：トークンなし、scope が company_api のトークン、B社のトークンで、A社の変更に作成の知らせ、取消の
    //           状態の照会、取消の結果を送る。知らない ID でも送る
    // 期待する結果：トークンなしは 401、scope の違いは 403、B社のトークンでは知らない ID と同じ 404。本文は固定で、
    //               受け取った値を返さない。A社の変更の状態は変わらない
    // plan 11章：テスト6（D-31、D-37、D-39、D-44）
    const { detail, changeId } = await created(u1);
    const routes: [string, Record<string, string>][] = [
      ['/v1/desk/change-notices', { request_id: String(detail.identifier), change_id: changeId }],
      ['/v1/desk/cancellation-status', { change_id: changeId }],
      [
        '/v1/desk/cancellation-results',
        {
          change_id: changeId,
          cancellation_id: randomBytes(32).toString('base64url'),
          result: 'applied',
        },
      ],
      [
        '/v1/desk/execution-results',
        { request_id: String(detail.identifier), result: 'not_created' },
      ],
    ];
    const wrongScope = await world.company.accessToken(tenant(0), 'company_api');
    const other = await world.company.accessToken(tenant(1), 'desk');
    for (const [path, json] of routes) {
      const none = await world.company.request({ path, json });
      expect([path, none.status, none.text]).toEqual([path, 401, '{"error":"invalid_token"}']);
      const scoped = await world.company.request({ path, json, token: wrongScope });
      expect([path, scoped.status, scoped.text]).toEqual([
        path,
        403,
        '{"error":"insufficient_scope"}',
      ]);
      const crossed = await world.company.request({ path, json, token: other });
      expect([path, crossed.status, crossed.text]).toEqual([path, 404, '{"error":"not_found"}']);
      for (const value of Object.values(json)) expect(crossed.text).not.toContain(value);
    }
    const mine = await world.company.accessToken(tenant(0), 'desk');
    const status = await world.company.request({
      path: '/v1/desk/cancellation-status',
      json: { change_id: changeId },
      token: mine,
    });
    expect(status.json()).toEqual({ state: 'window_open' });
    const unknown = await world.company.request({
      path: '/v1/desk/cancellation-status',
      json: { change_id: randomBytes(32).toString('base64url') },
      token: mine,
    });
    expect([unknown.status, unknown.text]).toEqual([404, '{"error":"not_found"}']);
  });

  it('企業向けの窓口のルートは、決めた形の本文だけを受け付ける', async () => {
    // 攻撃者が持っている情報：正規のトークン（scope desk）
    // 試す経路：余分な項目（テナント ID、sub、自由文）を足した本文、型の違う値、知らない結果の語を送る
    // 期待する結果：400 {"error":"invalid_request"}。本文のテナントや sub で利用者を探さない
    // plan 11章：テスト6（D-37）
    const token = await world.company.accessToken(tenant(0), 'desk');
    for (const [path, json] of [
      ['/v1/desk/cancellation-status', { change_id: 'x', tenant_id: tenant(1).tenantId }],
      ['/v1/desk/cancellation-status', { change_id: 'x', sub: u1.sub }],
      ['/v1/desk/change-notices', { request_id: 1, change_id: 'x' }],
      ['/v1/desk/execution-results', { request_id: 'x', result: 'created' }],
      ['/v1/desk/cancellation-results', { change_id: 'x', cancellation_id: 'y', result: 'done' }],
      ['/v1/desk/change-notices', { request_id: 'x', change_id: 'y', note: '至急' }],
    ] as const) {
      const result = await world.company.request({ path, json, token });
      expect([path, result.status, result.text]).toEqual([
        path,
        400,
        '{"error":"invalid_request"}',
      ]);
    }
  });

  it('desk の scope は、許したクライアントにだけ出す', async () => {
    // 攻撃者が持っている情報：窓口を許されていない企業の API のクライアント（scope company_api だけ）
    // 試す経路：トークンの要求の scope に desk、知らない scope、2つの scope を書く
    // 期待する結果：invalid_scope か invalid_request で断る。トークンは出ない
    // plan 11章：テスト6（ADR 0026 の O-65）
    const { startTestCompanyApi } = await import('../setup/company-api.ts');
    const plain = await startTestCompanyApi({ tenants: [{}] });
    try {
      const [only] = plain.tenants;
      if (only === undefined) throw new Error('準備に失敗した');
      for (const scope of ['desk', 'admin', 'company_api desk']) {
        const result = await plain.token(only, { scope });
        expect([scope, result.status]).toEqual([scope, 400]);
        expect((result.json() as { error: string }).error).toBe('invalid_scope');
      }
      const ok = await plain.token(only, { scope: 'company_api' });
      expect(ok.status).toBe(200);
    } finally {
      await plain.stop();
    }
  });

  it('idp からの内部 API は、idp の資格情報だけで、頼んだ利用者の行だけを扱う', async () => {
    // 攻撃者が持っている情報：company-api のソケットに届く立場（同じホストのほかのプロセス）と、U2 の内部の
    //                       レコード ID（idp の DB から盗んだ）
    // 試す経路：違う資格情報で呼ぶ。知らないパスに送る。U1 の利用者 ID で、U2 の行の状態と取消を頼む
    // 期待する結果：違う資格情報は forbidden、知らないパスは 404。U2 の行は、U1 には unknown で、取消は not_found
    // plan 11章：テスト6（D-41。ADR 0026 の O-63）
    const socketPath = world.deskSocketPath;
    const forged = createDeskClient({
      socketPath,
      credential: `idp.${randomBytes(32).toString('base64url')}`,
    });
    await expect(
      forged.status({
        userId: parseWarifuUserId(randomUUID()),
        items: [{ tenantId: parseTenantId(tenant(0).tenantId), changeRef: randomUUID() }],
      }),
    ).rejects.toMatchObject({ code: 'forbidden' });
    const unknownPath = await udsPost({
      socketPath,
      path: '/v1/desk_lookup',
      headers: {
        authorization: `Bearer ${world.deskCredential}`,
        'content-type': 'application/json',
      },
      body: new TextEncoder().encode('{}'),
      timeoutMs: 2000,
      maxResponseBytes: 1024,
    });
    expect(unknownPath.status).toBe(404);
    const real = createDeskClient({ socketPath, credential: world.deskCredential });
    await created(u2);
    const ref = await world.changeRefOf(userIdOf(u2.browser.authenticator));
    const asU1 = parseWarifuUserId(userIdOf(u1.browser.authenticator));
    const status = await real.status({
      userId: asU1,
      items: [{ tenantId: parseTenantId(tenant(0).tenantId), changeRef: ref }],
    });
    expect(status).toEqual([{ changeRef: ref, state: 'unknown', cancelDeadline: null }]);
    const cancel = await real.cancel({
      tenantId: parseTenantId(tenant(0).tenantId),
      userId: asU1,
      changeRef: ref,
    });
    expect(cancel).toEqual({ ok: false, reason: 'not_found' });
  });

  it('PAR の受け口は、クライアントごとの上限を超えると 429 で、作った request_uri も使えない', async () => {
    // 攻撃者が持っている情報：企業のクライアントの資格情報（侵害された企業のサーバー。ATK-03）
    // 試す経路：1分の間に、上限（60）を超えて PAR を送る
    // 期待する結果：61件目は 429 {"error":"rate_limited"}。request_uri は返らない
    // plan 11章：テスト6（ADR 0026 の O-70）
    let last = await pushRequest(world.t, client(1), [deskDetail(u1.sub)]);
    for (let i = 0; i < 60 && last.status === 201; i += 1) {
      last = await pushRequest(world.t, client(1), [deskDetail(u1.sub)]);
    }
    expect([last.status, last.body.error]).toEqual([429, 'rate_limited']);
    expect(last.requestUri).toBeUndefined();
  });

  it('窓口の作成の取消の選択肢は、利用者ごとの上限を超えると 429', async () => {
    // 攻撃者が持っている情報：利用者の承認用のセッション（盗んだ）
    // 試す経路：1分の間に、上限（10）を超えて取消の選択肢を求める
    // 期待する結果：11回目は 429。上限の前の取消は、パスキーがなければ通らない
    // plan 11章：テスト6（ADR 0026 の O-70）
    await created(u1);
    await u1.approval.approvalLogin();
    const [item] = await deskItems(u1.approval);
    let status = 200;
    for (let i = 0; i < 11; i += 1) {
      status = (await u1.approval.post('/api/desk-items/cancel/options', { id: item?.id })).status;
    }
    expect(status).toBe(429);
  });
});
