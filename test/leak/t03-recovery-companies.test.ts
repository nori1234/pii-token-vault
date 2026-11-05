// 回復を企業に知らせる（plan 11章 テスト3 の「recovered_at が企業に届く」とテスト12、ADR 0027 の O-79・O-81、RP-53）。
// idp、company-api（idp からの内部 API）、sender（回復の SET の配送）を立て、企業のサーバーの役はテストの中で行う。

import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deliverRecoveryNotices } from '../../packages/idp/src/recovery.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { createDeskClient } from '../../packages/warifu-core/src/desk/client.ts';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover, userIdOf } from '../setup/approvals.ts';
import { ISSUER, startTestCompanyApi } from '../setup/company-api.ts';
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
      tx.query<{ deliver_after: Date; recovered_day: string; recovery_ref: string }>(
        sql`SELECT deliver_after, recovered_day, recovery_ref FROM company_api.set_outbox
             WHERE event_type = 'account_recovered'`,
      ),
    );
  } finally {
    await db.close();
  }
}

/** idp の、企業への知らせの送信待ち（テナントの範囲で読む。idp の配送の回と同じ境界）。 */
async function queuedFor(tenantId: TenantId, attemptId?: string) {
  const db = await serviceDb('idp');
  try {
    const rows = await db.withTenant(tenantId, (tx) =>
      tx.query<{ attempt_id: string; recovered_day: string; attempts: number }>(
        sql`SELECT attempt_id, recovered_day, attempts FROM idp.recovery_notice_queue`,
      ),
    );
    return attemptId === undefined ? rows : rows.filter((row) => row.attempt_id === attemptId);
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

  it('取消と成立を同時に送っても、通るのは一方だけで、企業に届くのは成立した回復だけ', async () => {
    // 攻撃者が持っている情報：待機を終えた回復（攻撃者の新しい端末）。持ち主は、同じ時に登録済みの端末で取り消す
    // 試す経路：持ち主の取消の確定と、新しい端末の成立を、同時に送る。その後で、idp と company-api の送信待ちを見る
    // 期待する結果：どちらか一方だけが通る。成立しなければ、その回復の知らせは idp の送信待ちにも company-api にもない。
    //               成立すれば、知らせは company-api に1つだけ届く（idp の送信待ちは空になる）
    // plan 11章：テスト3、テスト12（ADR 0027 の O-79、O-81。オーナーのレビュー）
    const client = world.t.clients[0];
    const tenant = world.company.tenants[0];
    if (client === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const owner = await connectedOwner(world.t, [client]);
    const device = await readyToComplete(world.t, owner.code, owner.helper.approval);
    expect((await owner.approval.approvalLogin()).status).toBe(200);
    const attemptId = (
      (await owner.approval.get('/api/recovery/settings')).json.attempt as { id: string }
    ).id;
    const cancelOptions = await owner.approval.post('/api/recovery/cancel/options', {
      id: attemptId,
    });
    const resumeOptions = await device.post('/api/recovery/resume/options');
    const [cancelled, resumed] = await Promise.all([
      owner.approval.post('/api/recovery/cancel/verify', {
        ceremonyId: cancelOptions.json.ceremonyId,
        response: owner.approval.authenticator.get(cancelOptions.json.options as never, undefined, {
          origin: world.t.approvalOrigin,
        }),
      }),
      device.post('/api/recovery/resume/verify', {
        ceremonyId: resumeOptions.json.ceremonyId,
        response: device.authenticator.get(resumeOptions.json.options as never, undefined, {
          origin: world.t.approvalOrigin,
        }),
      }),
    ]);
    const completed = resumed.status === 200 && resumed.json.state === 'completed';
    expect(completed).toBe(cancelled.status !== 200);
    expect(
      (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === attemptId),
    ).toHaveLength(completed ? 1 : 0);
    expect(await queuedFor(tenant.tenantId, attemptId)).toEqual([]);
  });

  it('送信待ちにある企業への知らせは、利用者の操作によらず、idp の配送の回が送る', async () => {
    // 攻撃者が持っている情報：（障害）成立の直後に company-api へ渡せず、送信待ちに残った知らせ（利用者は何もしない）
    // 試す経路：送信待ちに知らせがある状態で、利用者は何もしない。配送の回の間隔を短くした idp が、自分で回る
    // 期待する結果：利用者の要求なしに、company-api に回復の SET の送信待ちができ、idp の送信待ちは空になる
    // plan 11章：テスト3、テスト12（ADR 0027 の O-81。オーナーの再レビュー）
    const tenant = world.company.tenants[0];
    if (tenant === undefined) throw new Error('準備に失敗した');
    const ticking = await startTestIdp(
      { tenants: 1, clients: [{ tenant: 0 }] },
      () => new Date(clock),
      {
        tenantIds: [tenant.tenantId],
        desk: { socketPath: world.deskSocketPath, credential: world.deskCredential },
      },
    );
    try {
      const owner = await connectedOwner(ticking, ticking.clients);
      const userId = userIdOf(owner.browser.authenticator);
      const attemptId = randomUUID();
      const db = await serviceDb('idp');
      try {
        // 成立のトランザクションが置くのと同じ行（成立の直後に渡せなかった状態）。
        await db.withWarifuUser(userId, (tx) =>
          tx.execute(
            sql`INSERT INTO idp.recovery_notice_queue
                  (notice_id, tenant_id, user_id, attempt_id, recovered_day, next_attempt_at, created_at)
                VALUES (${randomUUID()}, ${tenant.tenantId}, ${userId}, ${attemptId},
                        ${Math.floor(clock / DAY) * 86_400}, ${new Date(clock)}, ${new Date(clock)})`,
          ),
        );
      } finally {
        await db.close();
      }
      expect(await queuedFor(tenant.tenantId, attemptId)).toHaveLength(1);
      // テストの idp は自分では回さない。ここでは、配送の回を起動したときと同じ関数を呼ぶ。
      expect((await ticking.idp.deliverRecoveryNotices()).delivered).toBe(1);
      expect(await queuedFor(tenant.tenantId, attemptId)).toEqual([]);
      expect(
        (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === attemptId),
      ).toHaveLength(1);
    } finally {
      await ticking.stop();
    }
  });
});

describe('漏えい：企業に渡せないときも、知らせは失われない（ADR 0027 の O-79、O-81）', () => {
  it('緊急停止の間に回復しても、知らせは company-api に残り、停止を解いた後に届く。登録簿にないテナントへの知らせは受け取らない', async () => {
    // 攻撃者が持っている情報：企業が緊急停止している間に成立させた回復（停止を解いた後も、企業に知られないことを期待する）
    // 試す経路：company-api の登録で、テナントを緊急停止にして配備し直す（同じ DB）。その間に、そのテナントに接続した
    //           利用者の回復を成立させ、配送の回を回す。停止を解いて配備し直し、配送の回を回す。別に、登録簿にない
    //           テナントを含む知らせを、idp の資格情報で内部 API に渡す
    // 期待する結果：停止の間は SET を送らず、company-api の送信待ちに残る（idp の送信待ちは空）。停止を解くと、その企業の
    //               sub で回復の SET が届く。登録簿にないテナントを含む知らせは 404 で、どのテナントにも入れない
    //               （idp は送信待ちに残して送り直す）
    // plan 11章：テスト3、テスト12（ADR 0027 の O-81。オーナーの再々レビュー）
    const tenant = world.company.tenants[0];
    if (tenant === undefined || tenant.client === undefined) throw new Error('準備に失敗した');
    const dir = await mkdtemp(join(tmpdir(), 'warifu-recovery-'));
    const secret = randomBytes(32);
    const stopped = await startTestCompanyApi({
      tenants: [
        {
          tenantId: tenant.tenantId,
          relayDomain: tenant.relayDomain,
          client: tenant.client,
          ...(tenant.webhookUrl === undefined ? {} : { webhookUrl: tenant.webhookUrl }),
          scopes: ['company_api', 'desk'] as const,
          suspended: true,
        },
      ],
      sender: {
        socketPath: world.sender.sender.socketPath,
        credential: world.sender.credentials['company-api'],
      },
      deskInternal: { socketPath: join(dir, 'company-api.sock'), credentials: { idp: secret } },
      now: () => new Date(clock),
    });
    const idp = await startTestIdp(
      { tenants: 1, clients: [{ tenant: 0 }] },
      () => new Date(clock),
      {
        tenantIds: [tenant.tenantId],
        desk: {
          socketPath: join(dir, 'company-api.sock'),
          credential: `idp.${secret.toString('base64url')}`,
        },
      },
    );
    try {
      const owner = await connectedOwner(idp, idp.clients);
      const device = await readyToComplete(idp, owner.code, owner.helper.approval);
      expect((await resume(device)).json.state).toBe('completed');
      const userId = userIdOf(owner.browser.authenticator);
      const db = await serviceDb('idp');
      let attemptId: string;
      try {
        const [row] = await db.withWarifuUser(userId, (tx) =>
          tx.query<{ attempt_id: string }>(
            sql`SELECT attempt_id FROM idp.recovery_attempts WHERE state = 'completed'`,
          ),
        );
        attemptId = row?.attempt_id ?? '';
      } finally {
        await db.close();
      }
      expect(await queuedFor(tenant.tenantId, attemptId)).toEqual([]);
      const rowsOf = async () =>
        (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === attemptId);
      expect(await rowsOf()).toHaveLength(1);

      const sentTo = (from: number) =>
        world.sender.requests
          .slice(from)
          .map((request) => decodeJwt(request.body))
          .filter((claims) => RECOVERED in ((claims.events as object | undefined) ?? {}))
          .map((claims) => (claims.sub_id as { id: string }).id);
      world.sender.respondWith(202);
      clock += 7 * HOUR;
      const before = world.sender.requests.length;
      await stopped.api.deliverDue();
      expect(sentTo(before)).not.toContain(owner.subs[0]);
      expect(await rowsOf()).toHaveLength(1);

      // 停止を解いて配備し直した company-api（world.company は、同じテナントを停止なしで登録している）。
      await world.company.api.deliverDue();
      expect(sentTo(before)).toContain(owner.subs[0]);
      expect(await rowsOf()).toEqual([]);

      const desk = createDeskClient({
        socketPath: join(dir, 'company-api.sock'),
        credential: `idp.${secret.toString('base64url')}`,
      });
      const unknownAttempt = randomUUID();
      await expect(
        desk.accountRecovered({
          userId,
          attemptId: unknownAttempt,
          tenantIds: [tenant.tenantId, randomUUID() as TenantId],
          recoveredDay: Math.floor(clock / DAY) * 86_400,
        }),
      ).rejects.toThrow();
      expect(
        (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === unknownAttempt),
      ).toEqual([]);
    } finally {
      await idp.stop();
      await stopped.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('送るときに sub の索引が見つからない回復の知らせは、company-api の送信待ちから消さずに送り直し、索引を戻した後に、その sub で届く', async () => {
    // 攻撃者が持っている情報：回復コードと協力者の承認（運用の誤りなどで、企業の sub の索引が欠けている間に回復を
    //                         成立させ、索引を直した後も、企業に回復を知られないことを期待する）
    // 試す経路：sub の索引のない利用者の回復の知らせを、idp の資格情報で内部 API に渡し、配送の回を何度も回す。その後、
    //           idp と同じ境界で索引を置き直し、配送の回を回す
    // 期待する結果：索引のない間は SET を送らず、送信待ちに残る（消さない）。索引を戻すと、その sub と、成立した日の
    //               recovered_at で回復の SET が届き、送信待ちから消える
    // plan 11章：テスト3、テスト12（ADR 0027 の O-81。オーナーの4回目のレビュー）
    const tenant = world.company.tenants[0];
    if (tenant === undefined) throw new Error('準備に失敗した');
    const userId = randomUUID();
    const attemptId = randomUUID();
    const day = Math.floor(clock / DAY) * 86_400;
    const desk = createDeskClient({
      socketPath: world.deskSocketPath,
      credential: world.deskCredential,
    });
    await desk.accountRecovered({
      userId: userId as never,
      attemptId,
      tenantIds: [tenant.tenantId],
      recoveredDay: day,
    });
    const rowsOf = async () =>
      (await recoveredRows(tenant.tenantId)).filter((row) => row.recovery_ref === attemptId);
    expect(await rowsOf()).toHaveLength(1);

    const sub = randomBytes(32).toString('base64url');
    const setsFor = (from: number) =>
      world.sender.requests
        .slice(from)
        .map((request) => decodeJwt(request.body))
        .filter((claims) => (claims.sub_id as { id?: string } | undefined)?.id === sub);
    world.sender.respondWith(202);
    const before = world.sender.requests.length;
    // 初めの遅延（0〜6時間）と、送り直しの間（1分、5分、30分、2時間、6時間。どれも最大で2割の揺らぎを足す）を
    // 越えて、何度も回す。
    for (const hours of [7, 1, 1, 3, 8, 8]) {
      clock += hours * HOUR;
      await world.company.api.deliverDue();
      expect(await rowsOf()).toHaveLength(1);
    }
    expect(setsFor(before)).toEqual([]);

    const idp = await serviceDb('idp');
    try {
      await idp.withTenant(tenant.tenantId, (tx) =>
        tx.execute(
          sql`INSERT INTO aliases.subject (tenant_id, user_id, sub)
              VALUES (${tenant.tenantId}, ${userId}, ${sub})`,
        ),
      );
    } finally {
      await idp.close();
    }
    clock += 8 * HOUR;
    await world.company.api.deliverDue();
    const sets = setsFor(before);
    expect(sets).toHaveLength(1);
    expect(sets[0]?.events).toEqual({ [RECOVERED]: { recovered_at: day } });
    expect(await rowsOf()).toEqual([]);
  });

  it('company-api に届かない、または idp に窓口の内部 API がないとき、回復は成立し、知らせは idp の送信待ちに残る', async () => {
    // 攻撃者が持っている情報：回復コードと協力者の承認（company-api が止まっている間に回復し、企業の保留を避けたい）
    // 試す経路：company-api の内部 API に届かない idp と、内部 API を設定していない idp で、企業に接続した利用者の
    //           回復を成立させ、配送の回を回す
    // 期待する結果：回復は成立する。企業への知らせは、成立と同じトランザクションで idp の送信待ちに置かれ、渡せない間は
    //               残り続ける（送り直すたびに回数が増え、間隔が空く）。ID トークンの recovered_at は、その間も届く
    // plan 11章：テスト3（オーナーの再レビュー）
    const dir = await mkdtemp(join(tmpdir(), 'warifu-recovery-'));
    const tenantId = randomUUID() as TenantId;
    const idps = [
      await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
        tenantIds: [tenantId],
        desk: {
          socketPath: join(dir, 'missing.sock'),
          credential: `idp.${randomBytes(32).toString('base64url')}`,
        },
      }),
      await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
        tenantIds: [tenantId],
      }),
    ];
    try {
      for (const [i, t] of idps.entries()) {
        const owner = await connectedOwner(t, t.clients);
        const device = await readyToComplete(t, owner.code, owner.helper.approval);
        expect((await resume(device)).json.state).toBe('completed');
        const queued = await queuedFor(tenantId);
        expect(queued).toHaveLength(i + 1);
        clock += 61_000;
        const counts = await t.idp.deliverRecoveryNotices();
        expect(counts.delivered).toBe(0);
        expect(counts.retry).toBe(i === 0 ? 1 : 0);
        expect(await queuedFor(tenantId)).toHaveLength(i + 1);
      }
      const attempts = (await queuedFor(tenantId)).map((row) => row.attempts).sort();
      // 届かない idp の行は、成立のときと配送の回で2回。内部 API のない idp の行は、送ろうとしない。
      expect(attempts).toEqual([0, 2]);
    } finally {
      for (const t of idps) await t.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('日付をまたいで送り直しても、企業に渡す回復した日は、成立した日のまま', async () => {
    // 攻撃者が持っている情報：（障害）UTC の日付が変わる直前に成立した回復の知らせが、company-api に渡せなかった状態
    // 試す経路：23:59:59 に成立させる（company-api に届かない idp）。翌日になってから、company-api に届くようになった
    //           配送の回で送る
    // 期待する結果：company-api の SET の recovered_day は成立した日（ID トークンの recovered_at と同じ）で、送った日
    //               ではない
    // plan 11章：テスト3、テスト12（オーナーの再レビュー）
    const tenant = world.company.tenants[0];
    if (tenant === undefined) throw new Error('準備に失敗した');
    const dir = await mkdtemp(join(tmpdir(), 'warifu-recovery-'));
    const down = await startTestIdp(
      { tenants: 1, clients: [{ tenant: 0 }] },
      () => new Date(clock),
      {
        tenantIds: [tenant.tenantId],
        desk: {
          socketPath: join(dir, 'missing.sock'),
          credential: `idp.${randomBytes(32).toString('base64url')}`,
        },
      },
    );
    try {
      const owner = await connectedOwner(down, down.clients);
      const device = await readyToComplete(down, owner.code, owner.helper.approval);
      clock = Math.ceil(clock / DAY) * DAY + DAY - 1000;
      const completedDay = Math.floor(clock / DAY) * 86_400;
      expect((await resume(device)).json.state).toBe('completed');
      const userId = userIdOf(owner.browser.authenticator);
      const [queued] = await queuedFor(tenant.tenantId);
      expect(Number(queued?.recovered_day)).toBe(completedDay);

      clock += 2 * 60_000;
      expect(Math.floor(clock / DAY) * 86_400).toBe(completedDay + 86_400);
      const db = await serviceDb('idp');
      try {
        const deps = { db, keys: undefined as never, now: () => new Date(clock) };
        const desk = createDeskClient({
          socketPath: world.deskSocketPath,
          credential: world.deskCredential,
        });
        expect((await deliverRecoveryNotices(deps, desk, [tenant.tenantId])).delivered).toBe(1);
        const [user] = await db.withWarifuUser(userId, (tx) =>
          tx.query<{ recovered_at: Date }>(sql`SELECT recovered_at FROM idp.users`),
        );
        expect(Math.floor((user?.recovered_at.getTime() ?? 0) / DAY) * 86_400).toBe(completedDay);
      } finally {
        await db.close();
      }
      const rows = (await recoveredRows(tenant.tenantId)).filter(
        (row) => row.recovery_ref === queued?.attempt_id,
      );
      expect(rows.map((row) => Number(row.recovered_day))).toEqual([completedDay]);
      expect(await queuedFor(tenant.tenantId, queued?.attempt_id)).toEqual([]);
    } finally {
      await down.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
