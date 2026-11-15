// テスト12：2社（demo-rp の A社とB社）が受け取った SET の記録から、同じ利用者を突き合わせられない
// （plan 11章 テスト12、不変条件5、spec 02 の RP-50・RP-52〜RP-54）。企業の側は demo-rp（rp-kit の SDK で SET を確かめる）。
// 割符の側の送り方（時刻のずらし、送り直し）は、t03-recovery-companies と t12-desk-cancellation-set で確かめている。

import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { DemoRp } from '../../packages/demo-rp/src/app.ts';
import { createDeskClient } from '../../packages/warifu-core/src/desk/client.ts';
import { userIdOf } from '../setup/approvals.ts';
import {
  DEMO_ORIGIN_A,
  DEMO_ORIGIN_B,
  DemoBrowser,
  type DemoUser,
  demoSignIn,
  forwardSets,
  startDemoRp,
} from '../setup/demo-rp.ts';
import { type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import { Browser } from '../setup/idp.ts';

const DAY = 86_400_000;
let clock = Date.now();
const now = () => new Date(clock);
let world: DeskWorld;
let demoA: DemoRp;
let demoB: DemoRp;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [
      {
        tenant: 0,
        operationActions: ['payout_destination.change'],
        redirectUri: `${DEMO_ORIGIN_A}/callback`,
      },
      { tenant: 1, redirectUri: `${DEMO_ORIGIN_B}/callback` },
    ],
    now,
  });
  demoA = await startDemoRp(world, {
    company: 'securities',
    origin: DEMO_ORIGIN_A,
    client: world.t.clients[0] as never,
    tenantIndex: 0,
    now,
  });
  demoB = await startDemoRp(world, {
    company: 'reservations',
    origin: DEMO_ORIGIN_B,
    client: world.t.clients[1] as never,
    tenantIndex: 1,
    now,
  });
});

afterAll(async () => {
  await demoA?.close();
  await demoB?.close();
  await world?.stop();
});

const accountsOf = (demo: DemoRp) => demo.store.read((state) => [...state.accounts.values()]);

describe('テスト12：2社の SET の記録（demo-rp）', () => {
  it('同じ利用者の回復の知らせは、2社に別々の sub と jti で届き、A社は出金先の変更を保留する。他社あての SET は受け取らない', async () => {
    // 攻撃者が持っている情報：A社とB社の両方の、アカウントの一覧と、受け取った SET の記録（2社が結託した、または両方から漏れた）
    // 試す経路：同じ利用者が2社にログインし、割符で回復が成立する。2社の記録（sub、jti、SET の中身）を突き合わせる。
    //           B社あての SET を A社の受け口に送る。同じ SET をもう一度送る。署名を壊した SET を送る
    // 期待する結果：sub も jti も2社で違い、どちらの記録にも相手の値がない。A社は回復の後、出金先の変更を保留する。
    //               他社あてと壊れた SET は 400。再送は 202 で、記録は増えない
    // plan 11章：テスト12、テスト3（RP-53）
    const browser = new Browser(world.t.origin);
    const approval = new Browser(world.t.approvalOrigin, browser.authenticator);
    const atA: DemoUser = { site: new DemoBrowser(demoA, DEMO_ORIGIN_A), browser, approval };
    const atB: DemoUser = { site: new DemoBrowser(demoB, DEMO_ORIGIN_B), browser, approval };
    expect((await demoSignIn(atA, 'register')).text).toContain('ログインしました。');
    expect((await demoSignIn(atB, 'login')).text).toContain('ログインしました。');
    const [accountA] = await accountsOf(demoA);
    const [accountB] = await accountsOf(demoB);
    if (accountA === undefined || accountB === undefined) throw new Error('準備に失敗した');
    // 同じ人の sub は、企業ごとに別（不変条件5）。B社の予約サイトには、出金先のルートがない。
    expect(accountA.sub).not.toBe(accountB.sub);
    expect(demoB.routes.some((r) => r.includes('payout') || r.includes('legacy'))).toBe(false);

    // 回復の成立（idp が company-api に頼む内部 API を、同じ形で呼ぶ）。
    const desk = createDeskClient({
      socketPath: world.deskSocketPath,
      credential: world.deskCredential,
    });
    await desk.accountRecovered({
      userId: userIdOf(browser.authenticator),
      attemptId: randomUUID(),
      tenantIds: world.company.tenants.map((t) => t.tenantId),
      recoveredDay: Math.floor(clock / DAY) * 86_400,
    });
    clock += 6 * 3600_000 + 61_000;
    const from = world.sender.requests.length;
    await world.company.api.deliverDue();
    const demos = { '/set/0': demoA, '/set/1': demoB };
    expect(await forwardSets(world, demos, from)).toEqual([202, 202]);

    expect(demoA.setLog.map((l) => l.events)).toEqual([['urn:warifu:secevent:account-recovered']]);
    expect(demoB.setLog).toHaveLength(1);
    expect(demoA.setLog[0]?.jti).not.toBe(demoB.setLog[0]?.jti);
    // 届いた SET の原文にも、相手の企業の sub は入っていない。
    const sent = world.sender.requests.slice(from);
    const bodyOf = (url: string) => {
      const body = sent.find((r) => r.url === url)?.body ?? '';
      return Buffer.from(body.split('.')[1] ?? '', 'base64url').toString('utf8');
    };
    expect(bodyOf('/set/0')).toContain(accountA.sub);
    expect(bodyOf('/set/0')).not.toContain(accountB.sub);
    expect(bodyOf('/set/1')).not.toContain(accountA.sub);

    // A社は、回復の後8日の間、出金先の変更を受け付けない（RP-53）。連絡先での再確認には逃がさない。
    const held = await atA.site.post('/payout/request', {
      bankCode: '9991',
      branchCode: '101',
      accountNumber: '1234567',
    });
    expect(held.location).toBe('/payout?n=payout_hold');
    expect((await atA.site.get('/')).text).toContain('回復した後の8日間');
    expect((await accountsOf(demoB))[0]?.recoveredAt).toBe(
      Math.floor((clock - 6 * 3600_000 - 61_000) / DAY) * 86_400,
    );

    // B社あての SET を A社の受け口に送っても、受け取らない（aud が違う）。壊した SET も同じ。再送は記録を増やさない。
    const forB = sent.find((r) => r.url === '/set/1')?.body ?? '';
    const forA = sent.find((r) => r.url === '/set/0')?.body ?? '';
    const post = (demo: DemoRp, payload: string) =>
      demo.app.inject({
        method: 'POST',
        url: '/warifu/events',
        headers: { 'content-type': 'application/secevent+jwt' },
        payload,
      });
    expect((await post(demoA, forB)).statusCode).toBe(400);
    expect((await post(demoA, `${forA.slice(0, -4)}AAAA`)).statusCode).toBe(400);
    expect((await post(demoA, forA)).statusCode).toBe(202);
    expect(demoA.setLog).toHaveLength(1);
  });
});
