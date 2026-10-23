// パスキーの追加と削除（plan 4章「予防」、DESIGN.md 2章「パスキーの管理」、ADR 0018）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, codeFlow, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { SoftAuthenticator } from '../setup/soft-authenticator.ts';

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock));
});

afterAll(async () => {
  await t.stop();
});

async function addPasskey(browser: Browser, authenticator: SoftAuthenticator) {
  const options = await browser.post('/api/passkeys/options');
  if (options.status !== 200) return options;
  const response = authenticator.create(options.json.options as never);
  return browser.post('/api/passkeys/verify', { ceremonyId: options.json.ceremonyId, response });
}

describe('漏えい：パスキーの追加と削除', () => {
  it('追加と削除には step-up が要り、別の利用者のチャレンジでは追加できない', async () => {
    // 攻撃者が持っている情報：利用者の PWA のセッション（認証から5分以上たったもの）と、自分の認証器
    // 試す経路：時計を進めてから、自分の認証器のパスキーを追加しようとする。削除もしようとする
    // 期待する結果：どちらも 401 { error: 'reauth_required' }。利用者が step-up した後は、追加できる
    // plan 11章：番号なし（plan 4章「パスキーの追加と削除には step-up」）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    clock += 6 * 60 * 1000;
    const second = new SoftAuthenticator(t.origin);
    const stale = await addPasskey(browser, second);
    expect(stale.status).toBe(401);
    expect(stale.json).toEqual({ error: 'reauth_required' });
    const me = await browser.get('/api/me');
    const id = (me.json.passkeys as { id: string }[])[0]?.id;
    const del = await browser.post('/api/passkeys/delete', { id });
    expect(del.status).toBe(401);
    expect((await browser.stepUp()).status).toBe(200);
    expect((await addPasskey(browser, second)).status).toBe(200);
    expect(((await browser.get('/api/me')).json.passkeys as unknown[]).length).toBe(2);
  });

  it('削除したパスキーではログインできず、その利用者のセッション（PWA と OIDC）はすべて消える', async () => {
    // 攻撃者が持っている情報：利用者が消したパスキー（なくした端末）と、その端末のブラウザのセッション
    // 試す経路：利用者が別の端末でパスキーを1つ消す。その後、消したパスキーでログインし、古いセッションで PWA と企業の認可を使う
    // 期待する結果：消したパスキーのログインは 401。古い PWA のセッションは 401。企業の認可は、ログインのインタラクションに戻る。
    //               最後の1つのパスキーは消せない
    // plan 11章：番号なし（plan 2章「パスキーを削除したときのセッション」、ADR 0018）
    const lost = new Browser(t.origin);
    await codeFlow(t, lost, t.clients[0] as (typeof t.clients)[0], { mode: 'register' });
    // なくした端末の PWA のセッション。
    const lostPwa = new Browser(t.origin, lost.authenticator);
    {
      const options = await lostPwa.post('/api/login/options');
      const response = lostPwa.authenticator.get(options.json.options as never);
      expect(
        (await lostPwa.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response }))
          .status,
      ).toBe(200);
    }
    // 利用者は、新しい端末を足し、なくした端末のパスキーを消す。
    const spare = new SoftAuthenticator(t.origin);
    expect((await addPasskey(lostPwa, spare)).status).toBe(200);
    const device = new Browser(t.origin, spare);
    const options = await device.post('/api/login/options');
    const response = spare.get(options.json.options as never);
    expect(
      (await device.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response }))
        .status,
    ).toBe(200);
    const lostId = Buffer.from(lost.authenticator.credentials[0]?.id ?? []).toString('base64url');
    const deleted = await device.post('/api/passkeys/delete', { id: lostId });
    expect(deleted.status).toBe(200);
    expect(deleted.json).toEqual({ ok: true, reloginRequired: true });

    expect((await lostPwa.get('/api/me')).status).toBe(401);
    const again = new Browser(t.origin, lost.authenticator);
    const loginOptions = await again.post('/api/login/options');
    const loginResponse = lost.authenticator.get(loginOptions.json.options as never);
    expect(
      (
        await again.post('/api/login/verify', {
          ceremonyId: loginOptions.json.ceremonyId,
          response: loginResponse,
        })
      ).status,
    ).toBe(401);
    // 古い OIDC のセッションでは、企業の認可が黙って通らない。
    const params = new URLSearchParams({
      client_id: t.clients[0]?.clientId ?? '',
      redirect_uri: t.clients[0]?.redirectUri ?? '',
      response_type: 'code',
      scope: 'openid',
      state: 's',
      nonce: 'n',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
    });
    const followed = await lost.follow(`/oidc/auth?${params}`);
    expect(followed.external).toBeUndefined();
    expect(followed.path.startsWith('/interaction/')).toBe(true);
    expect(followed.last.text).toContain('data-prompt="login"');

    // 残った1つは消せない。
    const relogin = new Browser(t.origin, spare);
    const o2 = await relogin.post('/api/login/options');
    const r2 = spare.get(o2.json.options as never);
    expect(
      (await relogin.post('/api/login/verify', { ceremonyId: o2.json.ceremonyId, response: r2 }))
        .status,
    ).toBe(200);
    const last = (await relogin.get('/api/me')).json.passkeys as { id: string }[];
    expect(last).toHaveLength(1);
    const refused = await relogin.post('/api/passkeys/delete', { id: last[0]?.id });
    expect(refused.status).toBe(400);
  });
});
