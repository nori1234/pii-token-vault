// テスト9：demo-rp（A社のデモ証券）の旧会員の引き継ぎ（既存会員の初回紐付け）と窓口を、割符と端から端まで通す
// （plan 11章 テスト9・テスト1・テスト2、ADR 0028 の O-86〜O-91・O-103・O-104、spec 02 の RP-20〜RP-27・RP-30・RP-31）。
// 企業の側は demo-rp（rp-kit の SDK）。利用者の操作は、demo-rp の画面（DemoBrowser）と割符の画面（Browser）で行う。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { DemoRp } from '../../packages/demo-rp/src/app.ts';
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
});
