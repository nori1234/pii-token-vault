// テスト1：demo-rp（A社のデモ証券）の出金先の変更を、割符と端から端まで通す（plan 11章 テスト1、spec 02 の RP-09〜RP-12、
// ADR 0030 の O-115）。企業の3つの責務（全体の固定、変更のときの再承認、実行と使い済みの一括の確定）を、画面の流れで確かめる。
// 単体の検査は packages/demo-rp/test/payout.test.ts。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { DemoRp } from '../../packages/demo-rp/src/app.ts';
import { accountKeyOf } from '../../packages/demo-rp/src/state.ts';
import {
  approveAtWarifu,
  DEMO_ORIGIN_A,
  DemoBrowser,
  type DemoUser,
  demoSignIn,
  startDemoRp,
} from '../setup/demo-rp.ts';
import { type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import { Browser } from '../setup/idp.ts';

const clock = Date.now();
let world: DeskWorld;
let demo: DemoRp;
const FIRST = { bankCode: '9991', branchCode: '101', accountNumber: '1234567' };
/** 表示（金融機関、支店、末尾4桁）が FIRST と同じ、別の口座。 */
const SAME_LAST4 = { bankCode: '9991', branchCode: '101', accountNumber: '9994567' };

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [
      {
        tenant: 0,
        operationActions: ['payout_destination.change'],
        redirectUri: `${DEMO_ORIGIN_A}/callback`,
      },
    ],
    now: () => new Date(clock),
  });
  demo = await startDemoRp(world, {
    company: 'securities',
    origin: DEMO_ORIGIN_A,
    client: world.t.clients[0] as never,
    tenantIndex: 0,
    now: () => new Date(clock),
  });
});

afterAll(async () => {
  await demo?.close();
  await world?.stop();
});

async function newUser(): Promise<DemoUser> {
  const browser = new Browser(world.t.origin);
  const user: DemoUser = {
    site: new DemoBrowser(demo, DEMO_ORIGIN_A),
    browser,
    approval: new Browser(world.t.approvalOrigin, browser.authenticator),
  };
  const home = await demoSignIn(user, 'register');
  expect(home.text).toContain('ログインしました。');
  return user;
}

async function destinationOf(user: DemoUser) {
  const key = [...user.site.cookies.values()][0];
  return demo.store.read((state) => {
    const session = [...state.sessions.values()].find((s) => s.sessionId === key);
    return session?.accountKey
      ? state.accounts.get(session.accountKey)?.payoutDestination
      : undefined;
  });
}

describe('テスト1：demo-rp の出金先の変更（ADR 0030）', () => {
  it('割符の承認の後に、申請のときに固定した口座だけが出金先になり、同じ戻りの URL の再送と同時の実行では変わらない', async () => {
    // 攻撃者が持っている情報：承認済みの戻りの URL（認可コード付き。利用者のブラウザの履歴などから）
    // 試す経路：出金先を申請し、割符で承認して戻る。同じ戻りの URL を、同時に3回と、後からもう1回開く
    // 期待する結果：変更は1回だけ確定し、出金先は固定した口座。ほかは「完了できませんでした」。画面と割符の画面に全桁は出ない
    // plan 11章：テスト1（RP-09・RP-10・RP-12）
    const user = await newUser();
    const started = await user.site.post('/payout/request', FIRST);
    expect(started.status).toBe(303);
    const approved = await approveAtWarifu(user, String(started.location), '/operation');
    expect(JSON.stringify(approved.card)).toContain('わりふデモ銀行（9991）');
    expect(JSON.stringify(approved.card)).not.toContain(FIRST.accountNumber);
    const target = new URL(String(approved.back));
    const path = `${target.pathname}${target.search}`;
    const results = await Promise.all([
      user.site.get(path),
      user.site.get(path),
      user.site.get(path),
    ]);
    expect(results.map((r) => r.location).sort()).toEqual([
      '/?n=failed',
      '/?n=failed',
      '/?n=payout_changed',
    ]);
    expect((await user.site.get(path)).location).toBe('/?n=failed');
    expect(await destinationOf(user)).toEqual(FIRST);
    const home = await user.site.get('/');
    expect(home.text).toContain('口座番号の末尾 4567');
    expect(home.text).not.toContain(FIRST.accountNumber);
    const used = await demo.store.read((state) =>
      [...state.payoutRequests.values()].map((r) => r.state),
    );
    expect(used).toEqual(['used']);
  });

  it('承認の後に内容を変えると、前の承認では変更できず、新しい申請と再承認が要る（同じ末尾4桁の別の口座でも）', async () => {
    // 攻撃者が持っている情報：利用者のログイン中の画面を操れる立場（承認の後に、変更先を差し替えたい）
    // 試す経路：FIRST を申請して割符で承認させる。戻る前に、表示が同じになる別の口座（SAME_LAST4）で申請し直す。
    //           前の承認の戻りの URL を開く
    // 期待する結果：前の承認では変更されない（出金先は未登録のまま）。新しい申請を、もう一度承認すると、その口座になる
    // plan 11章：テスト1（RP-09）
    const user = await newUser();
    const first = await user.site.post('/payout/request', FIRST);
    const approvedFirst = await approveAtWarifu(user, String(first.location), '/operation');
    const second = await user.site.post('/payout/request', SAME_LAST4);
    expect(second.status).toBe(303);
    const stale = await user.site.openCallback(String(approvedFirst.back));
    expect(stale.callback.location).toBe('/?n=failed');
    expect(await destinationOf(user)).toBeNull();
    const states = await demo.store.read((state) =>
      [...state.payoutRequests.values()]
        .filter((r) => r.destination.accountNumber !== '0000000')
        .map((r) => [r.destination.accountNumber, r.state]),
    );
    expect(states).toContainEqual([FIRST.accountNumber, 'superseded']);
    // 新しい申請は、新しい承認で通る。
    const approvedSecond = await approveAtWarifu(user, String(second.location), '/operation');
    const done = await user.site.openCallback(String(approvedSecond.back));
    expect(done.callback.location).toBe('/?n=payout_changed');
    expect(await destinationOf(user)).toEqual(SAME_LAST4);
  });

  it('別の利用者の戻りの URL、ログインしていない要求、ほかのサイトからの POST、形の違う口座、対応表にない金融機関は通らない', async () => {
    // 攻撃者が持っている情報：自分の割符のアカウントと、被害者がログイン中のブラウザに要求を送らせる手段（CSRF）
    // 試す経路：攻撃者が承認した戻りの URL を被害者のセッションで開く。Origin の違う POST、ログインなしの POST を送る
    // 期待する結果：被害者の出金先は変わらない。POST は 403、ログインなしは「先にログイン」。形の違う口座は申請にならない
    // plan 11章：テスト1、テスト6（RP-08）
    const victim = await newUser();
    const attacker = await newUser();
    const started = await attacker.site.post('/payout/request', SAME_LAST4);
    const approved = await approveAtWarifu(attacker, String(started.location), '/operation');
    const opened = await victim.site.openCallback(String(approved.back));
    expect(opened.callback.location).toBe('/?n=failed');
    expect(await destinationOf(victim)).toBeNull();

    const csrf = await victim.site.request('POST', '/payout/request', {
      form: SAME_LAST4,
      origin: 'https://evil.example',
    });
    expect(csrf.status).toBe(403);
    expect(
      (await victim.site.request('POST', '/payout/request', { form: SAME_LAST4, origin: null }))
        .status,
    ).toBe(403);
    const anonymous = new DemoBrowser(demo, DEMO_ORIGIN_A);
    expect((await anonymous.post('/payout/request', FIRST)).location).toBe('/?n=login_required');
    expect(
      (await victim.site.post('/payout/request', { ...FIRST, accountNumber: '12' })).location,
    ).toBe('/payout?n=payout_invalid');
    // 割符の対応表にない金融機関は、割符が申請を断る（承認の画面を出さない）。
    expect(
      (await victim.site.post('/payout/request', { ...FIRST, bankCode: '0001' })).location,
    ).toBe('/payout?n=payout_invalid');
    expect(await destinationOf(victim)).toBeNull();
  });

  it('demo-rp のルートは一覧のものだけ。連絡先や番号で会員を探すルート、sub を書き換えるルート、申請を書き換えるルートがない', async () => {
    // 攻撃者が持っている情報：漏れたメールや予約番号（それで会員を探したり、手続きを進めたりできる入口を探す）
    // 試す経路：demo-rp（A社）のルートを一覧にする
    // 期待する結果：下の一覧と同じ。ゲスト照会、アカウントの統合、sub の書き換え、出金先の申請の更新のルートはない
    // plan 11章：テスト6、テスト9（RP-33・RP-40）
    const listed = new Set(demo.routes);
    expect([...listed].sort()).toEqual([
      'GET /',
      'GET /assets/demo.css',
      'GET /assets/demo.js',
      'GET /assets/webauthn.js',
      'GET /callback',
      'GET /desk',
      'GET /payout',
      'GET /staff',
      'POST /desk/approve',
      'POST /desk/confirm',
      'POST /login',
      'POST /logout',
      'POST /payout/request',
      'POST /staff/login',
      'POST /staff/read',
      'POST /staff/sessions',
      'POST /warifu/events',
    ]);
    // 識別は (iss, sub) の組だけ（アカウントの鍵に、別名や連絡先が入っていない）。
    const keys = await demo.store.read((state) => [...state.accounts.keys()]);
    for (const key of keys) {
      const [iss, sub] = key.split('|');
      expect(key).toBe(accountKeyOf(String(iss), String(sub)));
      expect(iss).toBe(world.t.issuer);
      expect(sub).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });
});
