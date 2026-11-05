// 回復を企業に知らせる（plan 11章 テスト3 の「recovered_at が企業に届く」とテスト12、ADR 0027 の O-79・O-81、RP-53）。
// idp、company-api（idp からの内部 API）、sender（回復の SET の配送）を立て、企業のサーバーの役はテストの中で行う。

import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { createDeskClient } from '../../packages/warifu-core/src/desk/client.ts';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover, userIdOf } from '../setup/approvals.ts';
import { ISSUER } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import { type DeskWorld, deskDetail, deskFlow, pwaLogin, startDeskWorld } from '../setup/desk.ts';
import {
  Browser,
  codeFlow,
  redeemCode,
  startAuthorization,
  startTestIdp,
  type TestClient,
  type TestIdp,
} from '../setup/idp.ts';
import {
  bindingCodeOf,
  cancelRecovery,
  helperApprove,
  issueCode,
  makeHelper,
  resume,
  startOnNewDevice,
} from '../setup/recovery.ts';

const HOUR = 3600_000;
const DAY = 24 * HOUR;
const RECOVERED = 'urn:warifu:secevent:account-recovered';

let world: DeskWorld;
let clock = Date.now();

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [{ tenant: 0 }, { tenant: 1 }],
    now: () => new Date(clock),
  });
});

afterAll(async () => {
  await world?.stop();
});

/** 回復の前の利用者：2社（または指定の企業）に接続し、回復コードと協力者を持つ。 */
async function connectedOwner(t: TestIdp, clients: readonly TestClient[]) {
  const browser = new Browser(t.origin);
  const flows = [];
  for (const [i, client] of clients.entries()) {
    flows.push(await codeFlow(t, browser, client, { mode: i === 0 ? 'register' : 'session' }));
  }
  const approval = new Browser(t.approvalOrigin, browser.authenticator);
  expect((await approval.approvalLogin()).status).toBe(200);
  const helper = await newApprover(t);
  const code = await issueCode(approval);
  await makeHelper(approval, helper.approval);
  return { browser, approval, helper, code, subs: flows.map((f) => String(f.claims.sub)), flows };
}

/** 回復を、待機の終わりまで進める（成立はさせない）。新しい端末を返す。 */
async function readyToComplete(t: TestIdp, code: string, helper: Browser): Promise<Browser> {
  const device = await startOnNewDevice(t, code);
  expect(device.register?.status).toBe(200);
  const approved = await helperApprove(helper, bindingCodeOf(device.register));
  expect(approved.status).toBe(200);
  clock = Date.parse(String(approved.json.readyAt));
  return device.browser;
}

/** 回復した端末で、PWA のオリジンのパスキーでログインし、企業の ID トークンを受け取る（同意は済み）。 */
async function loginFlow(t: TestIdp, pwa: Browser, client: TestClient) {
  const { followed, verifier, state } = await startAuthorization(pwa, client);
  // 2社目は、1社目のログインの OIDC のセッションで、そのまま企業に戻る。
  if (followed.external !== undefined) {
    return redeemCode(t, client, followed.external, verifier, state);
  }
  expect(followed.path).toMatch(/^\/interaction\//);
  const options = await pwa.post(`${followed.path}/login/options`);
  const response = pwa.authenticator.get(options.json.options as never, undefined, {
    origin: t.origin,
  });
  const verified = await pwa.post(`${followed.path}/login/verify`, {
    ceremonyId: options.json.ceremonyId,
    response,
  });
  expect(verified.status).toBe(200);
  const next = await pwa.follow(String(verified.json.redirectTo));
  if (next.external === undefined) throw new Error('企業に戻ってこない');
  return redeemCode(t, client, next.external, verifier, state);
}

async function recoveredRows(tenantId: TenantId) {
  const db = await serviceDb('company-api');
  try {
    return await db.withTenant(tenantId, (tx) =>
      tx.query<{
        deliver_after: Date;
        recovered_day: string;
        recovery_ref: string;
        recovery_confirmed: boolean;
      }>(
        sql`SELECT deliver_after, recovered_day, recovery_ref, recovery_confirmed FROM company_api.set_outbox
             WHERE event_type = 'account_recovered'`,
      ),
    );
  } finally {
    await db.close();
  }
}

describe('漏えい：回復を企業に知らせる（plan 11章 テスト3、テスト12）', () => {
  it('回復が成立すると、接続している企業ごとに、その企業の sub で回復の SET が届き、ID トークンの recovered_at は回復した日になる', async () => {
    // 攻撃者が持っている情報：2社に届いた回復の SET と ID トークン（企業をまたいで、同じ利用者の回復を突き合わせようとする者）
    // 試す経路：A社とB社に接続した利用者が回復する。送信待ちの送る時刻と、届いた SET と、回復の後の ID トークンを比べる
    // 期待する結果：SET の sub_id は各社の sub（別々）、aud は各社のテナント、jti は別。送る時刻は成立から0〜6時間の
    //               独立の乱数。SET と ID トークンの recovered_at は、回復した日の UTC の0時（時刻は渡さない）。
    //               回復の前の ID トークンには recovered_at がない
    // plan 11章：テスト3、テスト12
    const clients = world.t.clients;
    const owner = await connectedOwner(world.t, clients);
    for (const flow of owner.flows) expect(flow.claims).not.toHaveProperty('recovered_at');
    expect(new Set(owner.subs).size).toBe(2);
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    // 成立の時刻を日の途中にずらしても、企業に渡る値は日の始まり。
    clock += 13 * HOUR + 17 * 60_000;
    const completedAt = clock;
    const day = Math.floor(completedAt / DAY) * 86_400;
    world.sender.respondWith(202);
    const before = world.sender.requests.length;
    const done = await resume(device);
    expect(done.json.state).toBe('completed');

    for (const tenant of world.company.tenants) {
      const rows = await recoveredRows(tenant.tenantId);
      expect(rows).toHaveLength(1);
      const delay = (rows[0]?.deliver_after.getTime() ?? -1) - completedAt;
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(6 * HOUR);
      expect(Number(rows[0]?.recovered_day)).toBe(day);
    }

    clock = completedAt + 6 * HOUR + 1000;
    expect((await world.company.api.deliverDue()).delivered).toBeGreaterThanOrEqual(2);
    const jwks = (await world.company.request({ method: 'GET', path: '/jwks' })).json() as {
      keys: object[];
    };
    const received = world.sender.requests
      .slice(before)
      .filter((r) => r.body.split('.').length === 3);
    const sets = [];
    for (const [i, tenant] of world.company.tenants.entries()) {
      const request = received.find((r) => r.url === `/set/${i}`);
      if (request === undefined) throw new Error('回復の SET が届いていない');
      const { payload } = await jwtVerify(request.body, createLocalJWKSet(jwks as never), {
        algorithms: ['ES256'],
        issuer: ISSUER,
        audience: tenant.tenantId,
        typ: 'secevent+jwt',
      });
      sets.push(payload);
      expect(Object.keys(payload).sort()).toEqual(['aud', 'events', 'iat', 'iss', 'jti', 'sub_id']);
      expect(payload.sub_id).toEqual({ format: 'opaque', id: owner.subs[i] });
      expect(payload.events).toEqual({ [RECOVERED]: { recovered_at: day } });
    }
    expect(new Set(sets.map((s) => s.jti)).size).toBe(2);

    const pwa = new Browser(world.t.origin, device.authenticator);
    expect((await pwaLogin(pwa)).status).toBe(200);
    for (const [i, client] of clients.entries()) {
      const after = await loginFlow(world.t, pwa, client);
      expect(after.claims.sub).toBe(owner.subs[i]);
      expect(after.claims.recovered_at).toBe(day);
    }
  });

  it('同じ回復の知らせを送り直しても、企業ごとの送信待ちは1つ（二重に送らない）', async () => {
    // 攻撃者が持っている情報：idp と company-api の間の内部 API を再送させられる立場（成立の直前に接続が切れた）
    // 試す経路：company-api の内部 API に、同じ回復の記録の ID で2回知らせる
    // 期待する結果：2回とも 204 で、送信待ちはテナントごとに1つ
    // plan 11章：テスト12
    const owner = await connectedOwner(world.t, world.t.clients.slice(0, 1));
    const tenant = world.company.tenants[0];
    if (tenant === undefined) throw new Error('準備に失敗した');
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    const desk = createDeskClient({
      socketPath: world.deskSocketPath,
      credential: world.deskCredential,
    });
    const before = (await recoveredRows(tenant.tenantId)).length;
    expect((await owner.approval.approvalLogin()).status).toBe(200);
    const input = {
      userId: userIdOf(owner.browser.authenticator),
      attemptId: (
        (await owner.approval.get('/api/recovery/settings')).json.attempt as { id: string }
      ).id,
      tenantIds: [tenant.tenantId],
      recoveredDay: Math.floor(clock / DAY) * 86_400,
    };
    await desk.accountRecovered(input);
    await desk.accountRecovered(input);
    expect((await recoveredRows(tenant.tenantId)).length).toBe(before + 1);
    // 成立の時の知らせ（同じ回復の記録）も、二重には入らない。
    expect((await resume(device)).json.state).toBe('completed');
    expect((await recoveredRows(tenant.tenantId)).length).toBe(before + 1);
  });

  it('回復の後の7日間も、窓口の操作別承認（照会と軽い手続き）は受け付ける', async () => {
    // 攻撃者が持っている情報：（正規の利用者）回復した直後に、企業の窓口で問い合わせをしたい
    // 試す経路：回復の直後に、窓口の作成を承認する
    // 期待する結果：承認でき、操作ごとの承認の JWT が企業に渡る（窓口の承認は高リスクの操作を含まない。ADR 0027 の O-80）
    // plan 11章：テスト3
    const client = world.t.clients[0];
    if (client === undefined) throw new Error('準備に失敗した');
    const owner = await connectedOwner(world.t, [client]);
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    expect((await resume(device)).json.state).toBe('completed');
    const pwa = new Browser(world.t.origin, device.authenticator);
    expect((await pwaLogin(pwa)).status).toBe(200);
    const outcome = await deskFlow(
      world,
      { browser: pwa, approval: device },
      client,
      deskDetail(owner.subs[0] ?? ''),
    );
    expect(outcome.approve.status).toBe(200);
    expect(typeof outcome.approvalJwt).toBe('string');
  });

  it('取り消された回復は、企業への知らせを準備していても届かない。確定されない準備は30日で消える', async () => {
    // 攻撃者が持っている情報：（競合）成立の直前に企業への知らせを準備した、攻撃者の回復（持ち主が同時に取り消す）
    // 試す経路：待機を終えた回復で、企業への知らせを準備した後に、持ち主が登録済みの端末で取り消す。新しい端末で成立を
    //           試みる。6時間の後に配送の回を回す。30日の後に、もう一度回す
    // 期待する結果：成立は 401。準備の行は確定されず、回復の SET は企業に届かない。確定されない準備は30日で消える
    // plan 11章：テスト3、テスト12（ADR 0027 の O-81。オーナーのレビュー）
    const client = world.t.clients[0];
    const tenant = world.company.tenants[0];
    if (client === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const owner = await connectedOwner(world.t, [client]);
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    expect((await owner.approval.approvalLogin()).status).toBe(200);
    const attemptId = (
      (await owner.approval.get('/api/recovery/settings')).json.attempt as { id: string }
    ).id;
    // 成立の処理が準備を済ませた直後の状態（ここで取消が先に確定する）。
    const desk = createDeskClient({
      socketPath: world.deskSocketPath,
      credential: world.deskCredential,
    });
    await desk.accountRecovered({
      userId: userIdOf(owner.browser.authenticator),
      attemptId,
      tenantIds: [tenant.tenantId],
      recoveredDay: Math.floor(clock / DAY) * 86_400,
    });
    expect((await cancelRecovery(owner.approval)).status).toBe(200);
    expect((await resume(device)).status).toBe(401);
    const prepared = (await recoveredRows(tenant.tenantId)).filter(
      (row) => row.recovery_ref === attemptId,
    );
    expect(prepared.map((row) => row.recovery_confirmed)).toEqual([false]);

    clock += 7 * HOUR;
    world.sender.respondWith(202);
    const before = world.sender.requests.length;
    await world.company.api.deliverDue();
    const recoveredSubs = world.sender.requests
      .slice(before)
      .map((request) => decodeJwt(request.body))
      .filter((claims) => RECOVERED in ((claims.events as object | undefined) ?? {}))
      .map((claims) => (claims.sub_id as { id: string }).id);
    expect(recoveredSubs).not.toContain(owner.subs[0]);

    clock += 31 * DAY;
    await world.company.api.deliverDue();
    expect(
      (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === attemptId),
    ).toEqual([]);
  });

  it('企業への知らせの確定が届かなかった回復は、回復した端末で受信箱を読んだときに確定する', async () => {
    // 攻撃者が持っている情報：（障害）回復の成立の直後に、company-api への確定が届かなかった状態
    // 試す経路：成立した回復の準備の行を「確定前」に戻し、idp に「確定がまだ」と記録した状態にする（成立と確定の間で
    //           idp が止まった状態の再現）。その後で、回復した端末で PWA の受信箱を読む
    // 期待する結果：受信箱を読むと確定を送り直し、準備の行が確定され、idp の記録も済みになる
    // plan 11章：テスト3、テスト12（ADR 0027 の O-79、O-81。オーナーのレビュー）
    const client = world.t.clients[0];
    const tenant = world.company.tenants[0];
    if (client === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const owner = await connectedOwner(world.t, [client]);
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    expect((await resume(device)).json.state).toBe('completed');
    const userId = userIdOf(owner.browser.authenticator);
    const idp = await serviceDb('idp');
    const company = await serviceDb('company-api');
    try {
      const pendingOf = () =>
        idp.withWarifuUser(userId, (tx) =>
          tx.query<{ attempt_id: string; company_notice_pending: boolean }>(
            sql`SELECT attempt_id, company_notice_pending FROM idp.recovery_attempts
                 WHERE state = 'completed'`,
          ),
        );
      const [attempt] = await pendingOf();
      if (attempt === undefined) throw new Error('成立した回復の記録がない');
      expect(attempt.company_notice_pending).toBe(false);
      await idp.withWarifuUser(userId, (tx) =>
        tx.execute(
          sql`UPDATE idp.recovery_attempts SET company_notice_pending = true
               WHERE attempt_id = ${attempt.attempt_id}`,
        ),
      );
      await company.withTenant(tenant.tenantId, (tx) =>
        tx.execute(
          sql`UPDATE company_api.set_outbox SET recovery_confirmed = false
               WHERE recovery_ref = ${attempt.attempt_id}`,
        ),
      );
      const confirmedOf = async () =>
        (await recoveredRows(tenant.tenantId))
          .filter((row) => row.recovery_ref === attempt.attempt_id)
          .map((row) => row.recovery_confirmed);
      expect(await confirmedOf()).toEqual([false]);

      const pwa = new Browser(world.t.origin, device.authenticator);
      expect((await pwaLogin(pwa)).status).toBe(200);
      expect((await pwa.get('/api/inbox')).status).toBe(200);
      expect(await confirmedOf()).toEqual([true]);
      expect((await pendingOf()).map((row) => row.company_notice_pending)).toEqual([false]);
    } finally {
      await idp.close();
      await company.close();
    }
  });
});

describe('漏えい：企業に知らせられないときは、回復を成立させない（ADR 0027 の O-79）', () => {
  it('company-api に届かない、または idp に窓口の内部 API がないとき、成立は 503 で、前のパスキーはそのまま', async () => {
    // 攻撃者が持っている情報：回復コードと協力者の承認（企業に知らせずに回復を成立させ、企業の保留を避けたい）
    // 試す経路：company-api の内部 API に届かない idp と、内部 API を設定していない idp で、企業に接続した利用者の
    //           回復を、待機の後に成立させる
    // 期待する結果：どちらも 503 { error: 'unavailable' } で、回復は待機のまま。前のパスキーでログインできる
    // plan 11章：テスト3
    const dir = await mkdtemp(join(tmpdir(), 'warifu-recovery-'));
    const idps = [
      await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
        desk: {
          socketPath: join(dir, 'missing.sock'),
          credential: `idp.${randomBytes(32).toString('base64url')}`,
        },
      }),
      await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock)),
    ];
    try {
      for (const t of idps) {
        const owner = await connectedOwner(t, t.clients);
        const device = await readyToComplete(t, owner.code, owner.helper.approval);
        for (let i = 0; i < 2; i += 1) {
          const result = await resume(device);
          expect(result.status).toBe(503);
          expect(result.json).toEqual({ error: 'unavailable' });
        }
        expect((await owner.approval.approvalLogin()).status).toBe(200);
        const settings = await owner.approval.get('/api/recovery/settings');
        expect((settings.json.attempt as { state: string }).state).toBe('waiting');
        expect(settings.json.restrictedUntil).toBeNull();
      }
    } finally {
      for (const t of idps) await t.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
