// テスト9：demo-rp（A社のデモ証券）の旧会員の引き継ぎ（既存会員の初回紐付け）と窓口を、割符と端から端まで通す
// （plan 11章 テスト9・テスト1・テスト2、ADR 0028 の O-86〜O-91・O-103・O-104、spec 02 の RP-20〜RP-27・RP-30・RP-31）。
// 企業の側は demo-rp（rp-kit の SDK）。利用者の操作は、demo-rp の画面（DemoBrowser）と割符の画面（Browser）で行う。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { DemoRp } from '../../packages/demo-rp/src/app.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { userIdOf } from '../setup/approvals.ts';
import { serviceDb } from '../setup/db.ts';
import {
  approveAtWarifu,
  DEMO_ORIGIN_A,
  DemoBrowser,
  type DemoUser,
  demoSignIn,
  forwardSets,
  STAFF_KEY,
  startDemoRp,
} from '../setup/demo-rp.ts';
import { type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import { Browser } from '../setup/idp.ts';
import type { SoftAuthenticator } from '../setup/soft-authenticator.ts';

const HOUR = 3600 * 1000;
let clock = Date.now();
const now = () => new Date(clock);
/** demo-rp（企業）の時計のずれ（ミリ秒）。割符の時計とずれた受け口を作る。 */
let demoSkew = 0;
let world: DeskWorld;
let demo: DemoRp;
/** demo-rp から割符への結果の報告（/v1/initial-link/results）に差し込む障害。 */
const reportFault = {
  /**
   * unavailable：割符に届かない。lost：割符は受け取って処理したが、応答が失われる。reject：割符が 409 で断る。
   * rate_limited：割符がレート制限の 429 で断る（reject と rate_limited は、割符には届けない）。
   */
  mode: 'none' as 'none' | 'unavailable' | 'lost' | 'reject' | 'rate_limited',
};

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0, initialLink: true, redirectUri: `${DEMO_ORIGIN_A}/callback` }],
    now,
    initialLink: true,
  });
  demo = await startDemoRp(world, {
    company: 'securities',
    origin: DEMO_ORIGIN_A,
    client: world.t.clients[0] as never,
    tenantIndex: 0,
    now: () => new Date(clock + demoSkew),
    initialLink: true,
    wrapSend: (send) => async (request) => {
      if (reportFault.mode === 'none' || !request.url.endsWith('/v1/initial-link/results')) {
        return send(request);
      }
      if (reportFault.mode === 'reject') {
        return {
          status: 409,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ error: 'conflict' }),
        };
      }
      if (reportFault.mode === 'rate_limited') {
        // company-api のレート制限の応答と同じ形（packages/company-api/src/app.ts の limited）。
        return {
          status: 429,
          headers: { 'content-type': 'application/json', 'retry-after': '60' },
          body: JSON.stringify({ error: 'rate_limited' }),
        };
      }
      if (reportFault.mode === 'lost') await send(request);
      throw new Error('通信の障害（テストで差し込んだ）');
    },
  });
});

afterAll(async () => {
  await demo?.close();
  await world?.stop();
});

/** 割符の利用者を作り、demo-rp にログインする。legacy を渡せば、その旧パスキーを持つ。 */
async function newUser(legacy?: SoftAuthenticator): Promise<DemoUser> {
  const browser = new Browser(world.t.origin);
  const user: DemoUser = {
    site: new DemoBrowser(demo, DEMO_ORIGIN_A, legacy),
    browser,
    approval: new Browser(world.t.approvalOrigin, browser.authenticator),
  };
  expect((await demoSignIn(user, 'register')).text).toContain('ログインしました。');
  return user;
}

/** 待機の知らせなどの SET を送らせて、demo-rp の受け口に渡す。 */
async function deliverSets(): Promise<void> {
  clock += 61_000;
  const from = world.sender.requests.length;
  await world.company.api.deliverDue();
  const statuses = await forwardSets(world, { '/set/0': demo }, from);
  for (const status of statuses) expect(status).toBe(202);
}

/** 引き継ぎの申請（旧パスキーの確かめ、仮申請と証跡、割符での最初の承認）まで。 */
async function startLink(user: DemoUser) {
  expect((await user.site.verifyLegacy()).status).toBe(200);
  const started = await user.site.post('/legacy/link/start');
  expect(started.status).toBe(303);
  const approved = await approveAtWarifu(user, String(started.location), '/initial-link');
  return user.site.openCallback(String(approved.back));
}

const attemptStates = () =>
  demo.store.read((state) => [...state.linkAttempts.values()].map((a) => a.state));

/** demo-rp の結果の報告の送信待ち（結果、届かなかった回数、保留）。 */
const pendingReports = () =>
  demo.store.read((state) =>
    [...state.pendingReports.values()].map((r) => [r.result, r.failures, r.held]),
  );

/** 申請から、割符の最終の承認まで進め、企業への戻りの URL を返す（企業の確定の前で止める）。 */
async function untilFinalApproval(user: DemoUser): Promise<string> {
  expect((await user.site.seedLegacy()).status).toBe(200);
  expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
  await deliverSets();
  clock += 24 * HOUR + 1000;
  expect((await user.site.verifyLegacy()).status).toBe(200);
  const finalize = await user.site.post('/legacy/link/finalize');
  expect(finalize.status).toBe(303);
  const approved = await approveAtWarifu(user, String(finalize.location), '/initial-link');
  return String(approved.back);
}

/** 割符の受信箱の、この利用者の初回紐付けの項目の状態（割符の正本の状態から決まる）。 */
async function warifuStates(user: DemoUser): Promise<string[]> {
  await user.approval.approvalLogin();
  const items = (await user.approval.get('/api/initial-link-items')).json.items as {
    state: string;
  }[];
  return items.map((i) => i.state);
}

/** 割符に残った、この利用者の紐付け済みの記録の件数。 */
async function linkRecords(user: DemoUser): Promise<number> {
  const tenant = world.company.tenants[0];
  if (tenant === undefined) throw new Error('準備に失敗した');
  const userId = userIdOf(user.browser.authenticator);
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(tenant.tenantId, (tx) =>
      tx.query(sql`SELECT user_id FROM company_api.initial_link_records WHERE user_id = ${userId}`),
    );
    return rows.length;
  } finally {
    await db.close();
  }
}

describe('テスト9：demo-rp の旧会員の引き継ぎと窓口（ADR 0028）', () => {
  it('旧パスキーの確かめ、割符の承認、待機、最終の確かめを経て引き継ぎ、その後は旧パスキーを受け付けない', async () => {
    // 攻撃者が持っている情報：なし（正規の流れ。後のテストの土台）
    // 試す経路：旧会員を用意 → 割符でログイン → 旧パスキーで確かめて申請 → 割符で承認 → 待機の SET → 24時間 →
    //           旧パスキーをもう一度確かめて確定 → 割符で最終の承認
    // 期待する結果：待機が終わる前は確定できない。確定の後は、アカウントに旧会員が1つ結び付き、旧パスキーの確かめは 401。
    //               画面と URL に、申請ID・会員参照・移行専用ID は出ない
    // plan 11章：テスト9（RP-30・RP-31）
    const user = await newUser();
    expect((await user.site.seedLegacy()).status).toBe(200);
    const pending = await startLink(user);
    expect(pending.callback.location).toBe('/legacy?n=link_waiting');
    expect(await attemptStates()).toEqual(['pending_notice']);
    await deliverSets();
    expect(await attemptStates()).toEqual(['waiting']);

    // 待機が終わる前の確定は、割符が断る（2つ目の証跡を受け取らない）。
    expect((await user.site.verifyLegacy()).status).toBe(200);
    const early = await user.site.post('/legacy/link/finalize');
    expect(early.location).toBe('/legacy?n=link_not_ready');

    clock += 24 * HOUR + 1000;
    // 旧パスキーの確かめは5分で切れる。確定の前に、もう一度確かめる（新しいチャレンジ）。
    expect((await user.site.post('/legacy/link/finalize')).location).toBe(
      '/legacy?n=legacy_required',
    );
    expect((await user.site.verifyLegacy()).status).toBe(200);
    const finalize = await user.site.post('/legacy/link/finalize');
    expect(finalize.status).toBe(303);
    const approved = await approveAtWarifu(user, String(finalize.location), '/initial-link');
    const done = await user.site.openCallback(String(approved.back));
    expect(done.callback.location).toBe('/?n=link_done');
    expect(done.page.text).toContain('旧会員は、引き継ぎ済みです。');
    expect(await attemptStates()).toEqual(['linked']);
    // 引き継ぎの後は、旧パスキーの確かめを受け付けない（RP-31）。
    expect((await user.site.verifyLegacy()).status).toBe(401);
    // 申請ID、会員参照、移行専用ID は、画面にも、移る先の URL にも出ていない。
    const secrets = await demo.store.read((state) =>
      [...state.linkAttempts.values()].flatMap((a) => [a.requestId, a.memberRef, a.initialLinkId]),
    );
    const shown = [
      done.page.text,
      (await user.site.get('/legacy')).text,
      String(finalize.location),
    ].join('\n');
    for (const secret of secrets) expect(shown).not.toContain(secret);
    // 割符（idp と company-api）のログにも出ていない（不変条件4）。
    const logs = [...world.t.logLines(), ...world.company.logs].join('\n');
    for (const secret of secrets) expect(logs).not.toContain(secret);
    // 割符の正本でも、結果の報告（linked）が届いている。
    await user.approval.approvalLogin();
    const items = (await user.approval.get('/api/initial-link-items')).json.items as {
      state: string;
    }[];
    expect(items.map((i) => i.state)).toEqual(['linked']);
  });

  it('盗まれた旧パスキーで攻撃者が申請しても、持ち主は旧パスキーで確かめて知らせを見て、取り消せる', async () => {
    // 攻撃者が持っている情報：被害者の旧パスキー（盗んだ）と、自分の割符のアカウント。または、被害者のメールアドレス
    // 試す経路：攻撃者が、旧パスキーで確かめて、自分の割符のアカウントへの引き継ぎを申請する。持ち主が、待機の間に
    //           旧パスキーで確かめて、知らせを見て取り消す。その後、攻撃者が24時間後に確定しようとする
    // 期待する結果：持ち主に知らせが見え、取消が通る。攻撃者は確定できない。旧パスキーなしでは、知らせも取消もない。
    //               メールで旧会員を探したり、引き継いだりする入口はない
    // plan 11章：テスト9（紐付けの攻撃。ADR 0028 の O-103）
    const owner = new DemoBrowser(demo, DEMO_ORIGIN_A);
    expect((await owner.seedLegacy()).status).toBe(200);
    const attacker = await newUser(owner.legacy);
    expect((await startLink(attacker)).callback.location).toBe('/legacy?n=link_waiting');
    await deliverSets();

    // 旧パスキーで確かめていない人には、知らせも取消も出さない。
    const stranger = new DemoBrowser(demo, DEMO_ORIGIN_A);
    expect((await stranger.get('/legacy')).text).not.toContain('引き継ぐ申請が出ています');
    expect((await stranger.post('/legacy/cancel')).location).toBe('/legacy?n=legacy_required');

    // 持ち主（割符にログインしていない）は、旧パスキーで確かめると、知らせが見え、取り消せる。
    expect((await owner.verifyLegacy()).status).toBe(200);
    expect((await owner.get('/legacy')).text).toContain('引き継ぐ申請が出ています');
    expect((await owner.post('/legacy/cancel')).location).toBe('/legacy?n=link_cancelled');

    clock += 24 * HOUR + 1000;
    expect((await attacker.site.verifyLegacy()).status).toBe(200);
    expect((await attacker.site.post('/legacy/link/finalize')).location).toBe(
      '/legacy?n=link_not_ready',
    );
    const linked = await demo.store.read(
      (state) => [...state.accounts.values()].filter((a) => a.legacyMemberId !== null).length,
    );
    // 1つ目のテストで引き継いだ1件だけ。
    expect(linked).toBe(1);
    // 取消の後は、同じ旧パスキーでの申請のやり直しを受け付けない（不正の疑いとして止める）。
    expect((await attacker.site.post('/legacy/link/start')).location).toBe(
      '/legacy?n=link_refused',
    );
    // メールアドレスを送っても、どのルートも旧会員を探さない（入力として読むルートがない）。
    const fresh = await newUser();
    expect(
      (await fresh.site.post('/legacy/link/start', { email: 'victim@example.com' })).location,
    ).toBe('/legacy?n=legacy_required');
    expect(demo.routes.filter((r) => /mail|phone|lookup|search|merge|rebind/i.test(r))).toEqual([]);
  });

  it('受け口が古い SET を set_too_old で断ると、割符は新しい jti と iat で送り直し、待機はその後に始まる', async () => {
    // 攻撃者が持っている情報：以前に送られた、署名の正しい SET（受け口に送り直して、古い知らせを受け取らせたい）
    // 試す経路：企業の時計が10分進んでいる（SET が10分前のものに見える）ときに、待機の知らせの SET が届く。
    //           時計を直した後に、割符が送り直す。先の時刻の SET と、壊れた本文も受け口に送る
    // 期待する結果：最初の SET は 400 と set_too_old で、申請は待機に入らない。割符は5秒あけて新しい jti と iat で送り直し、
    //               それを受け取って待機が始まる。先の時刻は iat_in_future、壊れた本文は理由なしの 400
    // plan 11章：テスト12（RP-50、spec 02 の7章、ADR 0026 の O-67）
    const user = await newUser();
    expect((await user.site.seedLegacy()).status).toBe(200);
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    const mine = async () => {
      const key = await demo.store.read(
        (state) => state.sessions.get([...user.site.cookies.values()][0] ?? '')?.accountKey,
      );
      return demo.store.read((state) =>
        [...state.linkAttempts.values()].filter((a) => a.accountKey === key).map((a) => a.state),
      );
    };
    const answers: { status: number; body: string }[] = [];
    world.sender.respondThrough(async (request) => {
      const res = await demo.app.inject({
        method: 'POST',
        url: '/warifu/events',
        headers: { 'content-type': 'application/secevent+jwt' },
        payload: request.body,
      });
      answers.push({ status: res.statusCode, body: res.body });
      return {
        status: res.statusCode,
        headers: { 'content-type': 'application/json' },
        body: res.body,
      };
    });
    try {
      const logged = demo.setLog.length;
      const from = world.sender.requests.length;
      demoSkew = 10 * 60_000;
      clock += 61_000;
      expect(await world.company.api.deliverDue()).toMatchObject({ delivered: 0, reissue: 1 });
      expect(answers).toEqual([
        { status: 400, body: '{"err":"invalid_request","warifu_reason":"set_too_old"}' },
      ]);
      expect(await mine()).toEqual(['pending_notice']);
      expect(demo.setLog).toHaveLength(logged);

      // 先の時刻の SET（企業の時計が遅れている）と、壊れた本文。
      const first = String(world.sender.requests[from]?.body);
      demoSkew = -10 * 60_000;
      const future = await demo.app.inject({
        method: 'POST',
        url: '/warifu/events',
        headers: { 'content-type': 'application/secevent+jwt' },
        payload: first,
      });
      expect([future.statusCode, future.body]).toEqual([
        400,
        '{"err":"invalid_request","warifu_reason":"iat_in_future"}',
      ]);
      demoSkew = 0;
      const broken = await demo.app.inject({
        method: 'POST',
        url: '/warifu/events',
        headers: { 'content-type': 'application/secevent+jwt' },
        payload: `${first.slice(0, -4)}AAAA`,
      });
      expect([broken.statusCode, broken.body]).toEqual([400, '{"err":"invalid_request"}']);

      // 企業の時計が直った後、割符は5秒あけて、新しい jti と iat で送り直す。
      clock += 6_000;
      expect(await world.company.api.deliverDue()).toMatchObject({ delivered: 1 });
      expect(answers.at(-1)?.status).toBe(202);
      expect(await mine()).toEqual(['waiting']);
      const claimsOf = (body: string) =>
        JSON.parse(Buffer.from(body.split('.')[1] ?? '', 'base64url').toString('utf8')) as {
          jti: string;
          iat: number;
        };
      const sent = world.sender.requests.slice(from).map((r) => claimsOf(r.body));
      expect(sent).toHaveLength(2);
      expect(sent[1]?.jti).not.toBe(sent[0]?.jti);
      expect(Number(sent[1]?.iat)).toBeGreaterThan(Number(sent[0]?.iat));
      expect(demo.setLog).toHaveLength(logged + 1);
      expect(demo.setLog.at(-1)?.jti).toBe(sent[1]?.jti);
    } finally {
      demoSkew = 0;
      world.sender.respondThrough(undefined);
    }
  });

  it('期限の切れた申請は、割符の正本と照らして閉じ、同じ旧会員と割符のアカウントで申請し直せる', async () => {
    // 攻撃者が持っている情報：なし（利用者が、最初の承認の後に手続きを放置した、ふつうの場合）
    // 試す経路：最初の承認と待機の SET の後、親申請の期限（72時間）を過ぎてから、確定、取消、申請のやり直しを試す
    // 期待する結果：確定と取消はできない（申請は期限切れ）。企業の側の申請は expired に閉じ、同じ旧会員と同じ割符の
    //               アカウントで、新しい申請を出して、割符の最初の承認まで進める。割符に確かめられない間は、閉じない
    // plan 11章：テスト9（ADR 0028 の O-90）
    const user = await newUser();
    expect((await user.site.seedLegacy()).status).toBe(200);
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    await deliverSets();
    const accountKey = await demo.store.read(
      (state) => state.sessions.get([...user.site.cookies.values()][0] ?? '')?.accountKey,
    );
    const mine = () =>
      demo.store.read((state) =>
        [...state.linkAttempts.values()]
          .filter((a) => a.accountKey === accountKey)
          .map((a) => a.state),
      );
    expect(await mine()).toEqual(['waiting']);

    // 割符に確かめられないとき（受け口の時計が大きくずれて、企業の資格情報が通らない）は、申請を閉じない。
    clock += 73 * HOUR;
    demoSkew = 60 * 60_000;
    expect((await user.site.verifyLegacy()).status).toBe(200);
    await user.site.get('/legacy');
    expect(await mine()).toEqual(['waiting']);
    demoSkew = 0;

    // 期限の後：確定も取消もできず、企業の側の申請は、正本と同じ expired に閉じる。
    expect((await user.site.verifyLegacy()).status).toBe(200);
    expect((await user.site.post('/legacy/link/finalize')).location).toBe(
      '/legacy?n=link_not_ready',
    );
    expect(await mine()).toEqual(['expired']);
    expect((await user.site.post('/legacy/cancel')).location).toBe('/legacy?n=link_closed');
    const page = await user.site.get('/legacy');
    expect(page.text).toContain('割符で確認して、引き継ぎを申請する');
    expect(page.text).not.toContain('引き継ぐ申請が出ています');

    // 同じ旧会員と、同じ割符のアカウントで、申請し直せる。
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    expect(await mine()).toEqual(['expired', 'pending_notice']);
  });

  it('窓口：受付番号だけでは何も見えず、利用者が割符で承認した注文1件の状態だけを、担当者が1回だけ見られる', async () => {
    // 攻撃者が持っている情報：受付番号（窓口の担当者を装って聞き出した、または総当たり）と、他人の注文の ID
    // 試す経路：承認の前に担当者が照会する。他人の注文で許可しようとする。受付番号を何度も打ち間違える。承認の後に2回照会する
    // 期待する結果：承認の前と2回目は、固定の失敗の文。他人の注文は通らない。打ち間違いは5回で止まる。
    //               担当者の画面に、検索欄や連絡先の欄はない
    // plan 11章：テスト1・テスト2（RP-20〜RP-27）
    const user = await newUser();
    const other = await newUser();
    const staff = new DemoBrowser(demo, DEMO_ORIGIN_A);
    expect((await staff.post('/staff/login', { key: 'wrong' })).location).toBe('/staff?n=failed');
    expect((await staff.post('/staff/sessions')).location).toBe('/staff?n=failed');
    expect((await staff.post('/staff/login', { key: STAFF_KEY })).location).toBe('/staff');
    await staff.post('/staff/sessions');
    const staffPage = await staff.get('/staff');
    expect(staffPage.text).toContain('利用者ご自身の端末での確認が必要です');
    expect(staffPage.text).toContain('こちらからの電話やメッセージで承認を求めてはいけません。');
    expect(staffPage.text).not.toMatch(/type="search"|name="(email|phone|tel|name|q)"/);
    const receiptNo = /受付番号 (\d{8})/.exec(staffPage.text)?.[1] ?? '';
    expect(receiptNo).toMatch(/^\d{8}$/);

    // 承認の前は、受付番号を知っていても見えない。
    const before = await staff.post('/staff/read', { receiptNo });
    expect(before.text).toContain('本人確認ができませんでした。');

    const orders = await demo.store.read((state) => [...state.orders.values()]);
    const userKey = await demo.store.read(
      (state) => state.sessions.get([...user.site.cookies.values()][0] ?? '')?.accountKey,
    );
    const myOrder = orders.find((o) => o.accountKey === userKey);
    const otherKey = await demo.store.read(
      (state) => state.sessions.get([...other.site.cookies.values()][0] ?? '')?.accountKey,
    );
    const otherOrder = orders.find((o) => o.accountKey === otherKey);
    if (myOrder === undefined || otherOrder === undefined) throw new Error('準備に失敗した');
    // 他人の注文では、確認の画面に進めない（RP-08）。
    expect(
      (await user.site.post('/desk/confirm', { receiptNo, orderId: otherOrder.orderId })).location,
    ).toBe('/desk?n=desk_not_found');

    const confirm = await user.site.post('/desk/confirm', { receiptNo, orderId: myOrder.orderId });
    expect(confirm.status).toBe(200);
    expect(confirm.text).toContain(receiptNo);
    expect(confirm.text).toContain('デモ証券 お客さま窓口');
    expect(confirm.text).toContain('受付番号だけでは操作を許可しません。');
    const approve = await user.site.post('/desk/approve', { receiptNo, orderId: myOrder.orderId });
    const approved = await approveAtWarifu(user, String(approve.location), '/desk');
    expect((await user.site.openCallback(String(approved.back))).callback.location).toBe(
      '/desk?n=desk_granted',
    );

    const first = await staff.post('/staff/read', { receiptNo });
    expect(first.text).toContain('注文の状態：受付済み');
    expect(first.text).not.toContain(myOrder.label);
    const second = await staff.post('/staff/read', { receiptNo });
    expect(second.text).toContain('本人確認ができませんでした。');

    // 受付番号の打ち間違いは、利用者ごとに5回まで（総当たりをさせない）。
    const results: (string | undefined)[] = [];
    for (let i = 0; i < 6; i += 1) {
      results.push(
        (
          await other.site.post('/desk/confirm', {
            receiptNo: '00000000',
            orderId: otherOrder.orderId,
          })
        ).location,
      );
    }
    expect(results.slice(0, 5)).toEqual(Array(5).fill('/desk?n=desk_not_found'));
    expect(results[5]).toBe('/desk?n=desk_limited');
  });

  it('最終の承認の後、確定の前に旧会員の側の認証世代が変わっていたら、紐付けず、割符に not_linked を報告する', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー（持ち主は、待機の知らせを見落とした）
    // 試す経路：待機の後、最終の確かめと割符の最終の承認まで進める。企業が確定する前に、持ち主が旧会員の側で認証器を
    //           変える（認証世代が上がる。デモには、その画面がないので、企業の記録を直接変える）
    // 期待する結果：企業は紐付けず（旧会員は閉じない）、割符に not_linked を報告して申請を終える。割符の正本も
    //               not_linked になる（approved のまま残らない）。同じ旧会員で、新しい申請を出せる
    // plan 11章：テスト9（ADR 0028 の O-88・O-91）
    const user = await newUser();
    expect((await user.site.seedLegacy()).status).toBe(200);
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    await deliverSets();
    const accountKey = await demo.store.read(
      (state) => state.sessions.get([...user.site.cookies.values()][0] ?? '')?.accountKey,
    );
    const mine = () =>
      demo.store.read((state) =>
        [...state.linkAttempts.values()].filter((a) => a.accountKey === accountKey),
      );
    clock += 24 * HOUR + 1000;
    expect((await user.site.verifyLegacy()).status).toBe(200);
    const finalize = await user.site.post('/legacy/link/finalize');
    expect(finalize.status).toBe(303);
    const approved = await approveAtWarifu(user, String(finalize.location), '/initial-link');

    // 割符の最終の承認の後、企業が確定する前に、旧会員の側の認証世代が上がる。
    const memberId = (await mine())[0]?.memberId ?? '';
    await demo.store.transaction((state) => {
      const member = state.legacyMembers.get(memberId);
      if (member !== undefined) member.authEpoch += 1;
    });
    const done = await user.site.openCallback(String(approved.back));
    expect(done.callback.location).toBe('/legacy?n=failed');
    expect((await mine()).map((a) => a.state)).toEqual(['not_linked']);
    const after = await demo.store.read((state) => ({
      member: state.legacyMembers.get(memberId),
      account: state.accounts.get(accountKey ?? ''),
    }));
    expect(after.member?.closed).toBe(false);
    expect(after.member?.linkedAccountKey).toBeNull();
    expect(after.account?.legacyMemberId).toBeNull();
    // 割符の正本も not_linked で終わっている（企業の結果の報告が届いた）。
    await user.approval.approvalLogin();
    const items = (await user.approval.get('/api/initial-link-items')).json.items as {
      state: string;
    }[];
    expect(items.map((i) => i.state)).toEqual(['not_linked']);
    // 同じ旧会員で、新しい申請を出せる（新しい認証世代で）。
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    expect((await mine()).map((a) => a.state)).toEqual(['not_linked', 'pending_notice']);
  });

  it('確定の報告（linked）が届かないか、応答が失われても、送信待ちに残し、割符が 204 を返すまで送り直す', async () => {
    // 攻撃者が持っている情報：なし（障害。企業から割符への結果の報告が届かない。または、割符は受け取ったが応答が失われる）
    // 試す経路：割符の最終の承認の後、報告が届かない状態で確定し、送信待ちを送る（まだ届かない）。通信が戻ってから送る。
    //           別の利用者で、報告の応答だけが失われる状態で確定し、送信待ちを送る
    // 期待する結果：企業の側は確定し（linked）、報告は送信待ちに残る。届くまで、割符の正本は approved のまま（受信箱は
    //               finalizing）。送り直しは、間隔をあけてから行う。通信が戻ると、送り直しが 204 で、正本は linked に
    //               なり、送信待ちは空になる。応答が失われた報告の送り直しも 204 で、割符の紐付け済みの記録は1件だけ
    // plan 11章：テスト9（ADR 0028 の O-91。オーナーのレビュー、2026-11-16）
    const user = await newUser();
    const back = await untilFinalApproval(user);
    reportFault.mode = 'unavailable';
    expect((await user.site.openCallback(back)).callback.location).toBe('/?n=link_done');
    expect(await pendingReports()).toEqual([['linked', 1, false]]);
    expect(await warifuStates(user)).toEqual(['finalizing']);
    // 次に送ってよい時刻（30秒後）の前は、送らない。時刻が来ても、届かなければ残り、次の間隔は倍になる。
    expect(await demo.flushReports()).toEqual({ sent: 0, retry: 0, held: 0 });
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 0, retry: 1, held: 0 });
    expect(await pendingReports()).toEqual([['linked', 2, false]]);
    reportFault.mode = 'none';
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 0, retry: 0, held: 0 });
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 1, retry: 0, held: 0 });
    expect(await pendingReports()).toEqual([]);
    expect(await warifuStates(user)).toEqual(['linked']);
    expect(await linkRecords(user)).toBe(1);

    // 応答の喪失：割符は linked にしたが、企業には届いたかが分からない。送り直しも 204 で、記録は増えない。
    const other = await newUser();
    const back2 = await untilFinalApproval(other);
    reportFault.mode = 'lost';
    expect((await other.site.openCallback(back2)).callback.location).toBe('/?n=link_done');
    expect(await pendingReports()).toEqual([['linked', 1, false]]);
    expect(await warifuStates(other)).toEqual(['linked']);
    reportFault.mode = 'none';
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 1, retry: 0, held: 0 });
    expect(await pendingReports()).toEqual([]);
    expect(await linkRecords(other)).toBe(1);
  });

  it('取消の報告（cancelled）と、紐付けなかった報告（not_linked）も、届くまで送り直し、届いた後に申請し直せる', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー（取消は、本人が割符の受信箱から行う）
    // 試す経路：(1) 待機中に本人が割符で取り消し、企業が取消の SET を受けたとき、報告が届かない。(2) 最終の承認の後に
    //           旧会員の側の認証世代が変わり、企業が not_linked にしたとき、報告が届かない。通信が戻ってから送る
    // 期待する結果：SET の受け口は 202 を返し、企業の側は取消を適用する。報告は送信待ちに残り、割符の正本は
    //               cancel_requested（not_linked のときは approved）のまま。通信が戻ると、送り直しで正本が
    //               cancelled と not_linked で終わり、同じ割符のアカウントで新しい申請を出せる
    // plan 11章：テスト9（ADR 0028 の O-90・O-91。オーナーのレビュー、2026-11-16）
    const user = await newUser();
    expect((await user.site.seedLegacy()).status).toBe(200);
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');
    await deliverSets();
    await user.approval.approvalLogin();
    const [item] = (await user.approval.get('/api/initial-link-items')).json.items as {
      id: string;
    }[];
    const started = await user.approval.post('/api/initial-link-items/cancel/options', {
      id: item?.id,
    });
    const response = user.approval.authenticator.get(started.json.options as never, undefined, {
      origin: user.approval.origin,
    });
    const cancelled = await user.approval.post('/api/initial-link-items/cancel/verify', {
      ceremonyId: started.json.ceremonyId,
      response,
    });
    expect(cancelled.json).toEqual({ ok: true, state: 'cancel_requested' });
    reportFault.mode = 'unavailable';
    // 取消の SET の受け口は、報告が届かなくても 202（deliverSets が確かめる）。
    await deliverSets();
    expect(await pendingReports()).toEqual([['cancelled', 1, false]]);
    expect(await warifuStates(user)).toEqual(['cancel_requested']);
    reportFault.mode = 'none';
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 1, retry: 0, held: 0 });
    expect(await warifuStates(user)).toEqual(['cancelled']);
    // 割符の正本が終わったので、同じ割符のアカウントで新しい申請を出せる。
    expect((await startLink(user)).callback.location).toBe('/legacy?n=link_waiting');

    const other = await newUser();
    const back = await untilFinalApproval(other);
    const accountKey = await demo.store.read(
      (state) => state.sessions.get([...other.site.cookies.values()][0] ?? '')?.accountKey,
    );
    await demo.store.transaction((state) => {
      const attempt = [...state.linkAttempts.values()].find((a) => a.accountKey === accountKey);
      const member = state.legacyMembers.get(attempt?.memberId ?? '');
      if (member !== undefined) member.authEpoch += 1;
    });
    reportFault.mode = 'unavailable';
    expect((await other.site.openCallback(back)).callback.location).toBe('/legacy?n=failed');
    expect(await pendingReports()).toEqual([['not_linked', 1, false]]);
    expect(await warifuStates(other)).toEqual(['finalizing']);
    reportFault.mode = 'none';
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 1, retry: 0, held: 0 });
    expect(await warifuStates(other)).toEqual(['not_linked']);
    expect((await startLink(other)).callback.location).toBe('/legacy?n=link_waiting');
    expect(await pendingReports()).toEqual([]);
  });

  it('割符がレート制限（429）で断った報告は、保留にせず、間隔をあけて送り直す', async () => {
    // 攻撃者が持っている情報：なし（割符のレート制限。company-api の 429（rate_limited）を返す割符を模す）
    // 試す経路：確定の報告を、割符が 429 で断る。時刻を進めて送信待ちを送る（まだ 429）。制限が解けてから送る
    // 期待する結果：企業の側は確定し（linked）、報告は保留にならず、送信待ちに残る。間隔をあけて送り直し、制限が
    //               解けると 204 で、割符の正本は linked になる（429 を保留にすると、正本が approved のまま残り、
    //               その利用者の次の申請が断られ続ける）
    // plan 11章：テスト9（ADR 0028 の O-91）
    const user = await newUser();
    const back = await untilFinalApproval(user);
    reportFault.mode = 'rate_limited';
    expect((await user.site.openCallback(back)).callback.location).toBe('/?n=link_done');
    expect(await pendingReports()).toEqual([['linked', 1, false]]);
    clock += 30_000;
    expect(await demo.flushReports()).toEqual({ sent: 0, retry: 1, held: 0 });
    expect(await pendingReports()).toEqual([['linked', 2, false]]);
    reportFault.mode = 'none';
    clock += 60_000;
    expect(await demo.flushReports()).toEqual({ sent: 1, retry: 0, held: 0 });
    expect(await pendingReports()).toEqual([]);
    expect(await warifuStates(user)).toEqual(['linked']);
  });

  it('割符が 429 以外の 4xx で断った報告は、送り直しても変わらないので、保留にして送り直さない', async () => {
    // 攻撃者が持っている情報：なし（企業の記録と割符の正本の食い違い。409 を返す割符を模す）
    // 試す経路：確定の報告を、割符が 409 で断る。その後、時刻を進めて送信待ちを送る
    // 期待する結果：企業の側の確定は戻さない。報告は保留になり（held）、自動では送り直さない（企業が調べる）
    // plan 11章：テスト9（ADR 0028 の O-91）
    const user = await newUser();
    const back = await untilFinalApproval(user);
    reportFault.mode = 'reject';
    expect((await user.site.openCallback(back)).callback.location).toBe('/?n=link_done');
    expect(await pendingReports()).toEqual([['linked', 0, true]]);
    reportFault.mode = 'none';
    clock += 3600_000;
    expect(await demo.flushReports()).toEqual({ sent: 0, retry: 0, held: 0 });
    expect(await pendingReports()).toEqual([['linked', 0, true]]);
    expect(await warifuStates(user)).toEqual(['finalizing']);
  });
});
