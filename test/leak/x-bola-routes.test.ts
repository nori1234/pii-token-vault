// 利用者どうしの BOLA の横断の検査（plan 11章 テスト6「利用者 U1 は U2 のものに触れない」、M10）。
// ほかのテストが呼んでいなかった idp のルートのうち、ログアウトと、ログインの途中の取りやめ（abort）を、利用者と
// ブラウザをまたいで確かめる。承認の画面の中身と拒否（初回紐付けと出金先の変更）は、t09-initial-link-idp と
// t01-operation-step-up で確かめる。全ルートがどれかのテストから呼ばれていることは、x-route-coverage で確かめる。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, startAuthorization, startTestIdp, type TestIdp } from '../setup/idp.ts';

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
});

afterAll(async () => {
  await t?.stop();
});

describe('テスト6：利用者どうしの BOLA（ログアウト、ログインの取りやめ）', () => {
  it('ログアウトは、自分のセッションだけを消し、セッションがなくても同じ応答を返す', async () => {
    // 攻撃者が持っている情報：別の利用者（U1）のアカウントとセッション
    // 試す経路：U1 と U2 がそれぞれログインした後、U1 がログアウトする。セッションのないブラウザもログアウトを呼ぶ
    // 期待する結果：U1 のセッションだけが消え（/api/me が 401）、U2 のセッションは残る（200）。セッションのない
    //               ログアウトも、同じ { ok: true } を返す（セッションの有無を区別しない）
    // plan 11章：テスト6
    const u1 = new Browser(t.origin);
    const u2 = new Browser(t.origin);
    expect((await u1.registerAccount()).status).toBe(200);
    expect((await u2.registerAccount()).status).toBe(200);
    const out = await u1.post('/api/logout', {});
    expect([out.status, out.json]).toEqual([200, { ok: true }]);
    expect((await u1.get('/api/me')).status).toBe(401);
    expect((await u2.get('/api/me')).status).toBe(200);
    const none = await new Browser(t.origin).post('/api/logout', {});
    expect([none.status, none.json]).toEqual([200, { ok: true }]);
  });

  it('ログインの途中の取りやめは、そのブラウザのインタラクションだけを終わらせる', async () => {
    // 攻撃者が持っている情報：被害者のインタラクションの uid（URL の一部として見えたもの）と、自分のブラウザ
    // 試す経路：被害者のブラウザが認可を始めた後、攻撃者のブラウザが、その uid で取りやめを呼ぶ。続いて、被害者の
    //           ブラウザが取りやめを呼ぶ
    // 期待する結果：攻撃者の取りやめは 400（インタラクションは、そのブラウザのクッキーに結び付く）。被害者の
    //               インタラクションは残り、被害者の取りやめは企業に access_denied で戻り、認可コードを出さない
    // plan 11章：テスト6
    const client = t.clients[0];
    if (client === undefined) throw new Error('準備に失敗した');
    const victim = new Browser(t.origin);
    const { followed } = await startAuthorization(victim, client);
    expect(followed.path.startsWith('/interaction/')).toBe(true);
    const uid = followed.path.split('/')[2] ?? '';

    const attacker = new Browser(t.origin);
    const forged = await attacker.post(`/interaction/${uid}/abort`, {});
    expect([forged.status, forged.json]).toEqual([400, { error: 'failed' }]);

    const aborted = await victim.post(`/interaction/${uid}/abort`, {});
    expect(aborted.status).toBe(200);
    const back = await victim.follow(String(aborted.json.redirectTo));
    expect(back.external?.searchParams.get('error')).toBe('access_denied');
    expect(back.external?.searchParams.get('code')).toBeNull();
  });
});
