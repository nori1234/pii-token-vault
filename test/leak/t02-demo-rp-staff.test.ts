// テスト2：demo-rp（A社のデモ証券）の窓口担当者の画面と、窓口の承認の要求が断られたときの扱い（plan 11章 テスト2、
// spec 02 の RP-20〜RP-27）。割符の代わりに、rp-kit の適合テストキットの模擬 OP を使う（模擬 OP は、ログインには
// 答え、PAR の受け口には答えない。窓口の承認の要求は、必ず断られる）。

import { generateKeyPairSync } from 'node:crypto';
import { exportJWK } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDemoRp, type DemoRp } from '../../packages/demo-rp/src/app.ts';
import { createMockOp, type MockOp } from '../../packages/rp-kit/src/kit/index.ts';
import { DEMO_ORIGIN_A, DemoBrowser, STAFF_KEY } from '../setup/demo-rp.ts';

const CLIENT_ID = 'demo-rp-staff-test';
let mockOp: MockOp;
let demo: DemoRp;

beforeAll(async () => {
  mockOp = await createMockOp({ clientId: CLIENT_ID, redirectUri: `${DEMO_ORIGIN_A}/callback` });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demo = await createDemoRp({
    company: 'securities',
    displayName: 'デモ証券',
    origin: DEMO_ORIGIN_A,
    idpOrigin: mockOp.origin,
    oidc: { clientId: CLIENT_ID, kid: 'k1', privateKey: (await exportJWK(privateKey)) as never },
    desk: { name: 'デモ証券 お客さま窓口', staff: '担当 A' },
    staffKey: STAFF_KEY,
    send: mockOp.send,
  });
});

afterAll(async () => {
  await demo?.close();
});

/** 模擬 OP の固定の利用者で、demo-rp にログインする。 */
async function signIn(site: DemoBrowser): Promise<void> {
  const started = await site.post('/login');
  const back = new URL(mockOp.complete(String(started.location), 'alpha'));
  expect((await site.get(`${back.pathname}${back.search}`)).location).toBe('/?n=signed_in');
}

/** 担当者として、新しい応対を始め、その受付番号を返す。 */
async function newReceipt(staff: DemoBrowser): Promise<string> {
  const before = new Set(await demo.store.read((state) => [...state.deskSessions.keys()]));
  expect((await staff.post('/staff/sessions')).location).toBe('/staff');
  const added = await demo.store.read((state) =>
    [...state.deskSessions.keys()].filter((no) => !before.has(no)),
  );
  expect(added).toHaveLength(1);
  return added[0] ?? '';
}

describe('テスト2：demo-rp の窓口担当者の画面', () => {
  it('担当者の画面を開くと、セッションの ID が新しくなり、前もってブラウザに入れられた ID には担当者の権限が付かない', async () => {
    // 攻撃者が持っている情報：自分で作った demo-rp のセッションの ID（担当者のブラウザに、前もって入れておいた）
    // 試す経路：担当者が、その ID のまま、合言葉で担当者の画面を開く。攻撃者が、同じ ID で受付番号の発行と画面を試す
    // 期待する結果：担当者には新しい ID が渡る。攻撃者の ID では、担当者の操作はできない（/staff?n=failed）
    // plan 11章：テスト2（RP-20〜RP-27）
    const attacker = new DemoBrowser(demo, DEMO_ORIGIN_A);
    await attacker.get('/staff');
    const planted = [...attacker.cookies];
    expect(planted).toHaveLength(1);
    const [cookieName, plantedId] = planted[0] ?? ['', ''];

    const staff = new DemoBrowser(demo, DEMO_ORIGIN_A);
    staff.cookies.set(cookieName, plantedId);
    expect((await staff.post('/staff/login', { key: STAFF_KEY })).location).toBe('/staff');
    expect(staff.cookies.get(cookieName)).not.toBe(plantedId);

    expect((await attacker.post('/staff/sessions')).location).toBe('/staff?n=failed');
    expect((await attacker.get('/staff')).text).toContain('合言葉');
    await newReceipt(staff);
  });

  it('割符が窓口の承認の要求を断っても、500 にならず、応対に許可も付かない', async () => {
    // 攻撃者が持っている情報：なし（割符が要求を断った、または割符につながらない、ふつうの失敗）
    // 試す経路：利用者が、受付番号と自分の注文で、窓口への許可を求める。割符の PAR の受け口が、要求を断る
    // 期待する結果：/desk?n=failed に戻る（500 や、割符の応答を見せない）。応対には許可が付かない
    // plan 11章：テスト2（RP-20〜RP-27）
    const user = new DemoBrowser(demo, DEMO_ORIGIN_A);
    await signIn(user);
    const staff = new DemoBrowser(demo, DEMO_ORIGIN_A);
    expect((await staff.post('/staff/login', { key: STAFF_KEY })).location).toBe('/staff');
    const receiptNo = await newReceipt(staff);
    const accountKey = await demo.store.read(
      (state) => state.sessions.get([...user.cookies.values()][0] ?? '')?.accountKey,
    );
    const orderId = await demo.store.read(
      (state) => [...state.orders.values()].find((o) => o.accountKey === accountKey)?.orderId,
    );
    if (orderId === undefined) throw new Error('準備に失敗した');

    const approve = await user.post('/desk/approve', { receiptNo, orderId });
    expect(approve.status).toBe(303);
    expect(approve.location).toBe('/desk?n=failed');
    const desk = await demo.store.read((state) => state.deskSessions.get(receiptNo));
    expect(desk?.grant).toBeNull();
  });
});
