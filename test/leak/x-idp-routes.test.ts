// idp のルート一覧の固定（不変条件2、plan 11章 テスト6 の土台、ADR 0018）と、ブラウザ側の守り（plan 2章）。
// ルートを足すときは、同じ PR でこの一覧を直す（principle-review の観点2・12）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
});

afterAll(async () => {
  await t.stop();
});

// Fastify の HEAD は GET から自動で足される。承認用のオリジン（ADR 0023）だけのルートは、末尾に「 (approval)」。
const ROUTES = [
  'GET /',
  'GET / (approval)',
  'GET /api/approvals (approval)',
  'GET /api/desk-items (approval)',
  'GET /api/inbox',
  'GET /api/me',
  'GET /assets/app.css',
  'GET /assets/app.css (approval)',
  'GET /assets/app.js',
  'GET /assets/app.js (approval)',
  'GET /assets/webauthn.js',
  'GET /assets/webauthn.js (approval)',
  'GET /desk (approval)',
  'GET /interaction/:uid',
  'GET /interaction/:uid/desk/finish',
  'GET /op-approval/jwks',
  'POST /api/approvals/decide/options (approval)',
  'POST /api/approvals/decide/verify (approval)',
  'POST /api/approvals/login/options (approval)',
  'POST /api/approvals/login/verify (approval)',
  'POST /api/desk-items/cancel/options (approval)',
  'POST /api/desk-items/cancel/verify (approval)',
  'POST /api/desk/approve/options (approval)',
  'POST /api/desk/approve/verify (approval)',
  'POST /api/desk/decline (approval)',
  'POST /api/desk/view (approval)',
  'POST /api/email/confirm',
  'POST /api/email/start',
  'POST /api/inbox/read',
  'POST /api/login/options',
  'POST /api/login/verify',
  'POST /api/logout',
  'POST /api/passkeys/delete',
  'POST /api/passkeys/options',
  'POST /api/passkeys/verify',
  'POST /api/register/options',
  'POST /api/register/verify',
  'POST /api/stepup/options',
  'POST /api/stepup/verify',
  'POST /interaction/:uid/abort',
  'POST /interaction/:uid/consent',
  'POST /interaction/:uid/login/options',
  'POST /interaction/:uid/login/verify',
  'POST /interaction/:uid/register/options',
  'POST /interaction/:uid/register/verify',
];

describe('漏えい：idp のルート一覧と、ブラウザ側の守り', () => {
  it('ルートは一覧のものだけ。逆引き、管理用、連絡先を変える別の経路がない', () => {
    // 攻撃者が持っている情報：sub、別名、窓口コード（漏れた企業のデータ）
    // 試す経路：idp の Fastify に登録されたルートを、すべて列挙する
    // 期待する結果：一覧と完全に一致する。sub・別名から連絡先を返すルート、admin、users、lookup のようなルートはない。
    //               メールの変更は /api/email/*（PWA のセッションと step-up）だけ。受信箱は、自分の項目の一覧と既読だけ。
    //               承認と拒否は、承認用のオリジンだけ（ADR 0023）。窓口の承認と、窓口の作成の取消も、承認用の
    //               オリジンだけ。本来のオリジンには、窓口のインタラクションの完了と、操作ごとの承認の公開鍵だけ（ADR 0026）
    // plan 11章：テスト6（逆引きのルートがない。ルート一覧で固定）
    const routes = t.idp.routes().filter((route) => !route.startsWith('HEAD '));
    expect(routes).toEqual(ROUTES);
    for (const route of routes) {
      expect(route).not.toMatch(/admin|users?\b|lookup|resolve|search|alias|sub\b|contact/i);
    }
  });

  it('Host が違う要求は 421、別のオリジンからの POST は 403', async () => {
    // 攻撃者が持っている情報：利用者のブラウザに、自分のサイトを開かせられる（DNS リバインディング、CSRF）
    // 試す経路：Host を書き換えた GET と、Origin が別のサイトの POST
    // 期待する結果：421 と 403。/oidc の Host も同じに守る
    // plan 11章：番号なし（plan 2章「ブラウザ側」）
    const port = new URL(t.origin).port;
    for (const path of ['/', '/oidc/.well-known/openid-configuration']) {
      const response = await fetch(`http://127.0.0.1:${port}${path}`);
      expect(response.status).toBe(421);
    }
    const browser = new Browser(t.origin);
    const forged = await browser.request(
      'POST',
      '/api/register/options',
      {},
      { origin: 'http://attacker.invalid' },
    );
    expect(forged.status).toBe(403);
    const noOrigin = await fetch(`${t.origin}/api/register/options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(noOrigin.status).toBe(403);
  });

  it('画面は応答ごとの nonce の CSP と Trusted Types で配り、JSON 以外の本文は受け付けない', async () => {
    // 攻撃者が持っている情報：企業として登録簿に入れた企業名（テナント由来の文字列）。利用者に開かせる URL
    // 試す経路：画面を2回読み、CSP を比べる。text/plain の本文を POST する
    // 期待する結果：script-src は 'nonce-…' と 'strict-dynamic' で、nonce は毎回違う。Trusted Types は必須で、
    //               ポリシーは 'none'。inline の script はない。text/plain は 400 か 415
    // plan 11章：番号なし（plan 2章「ブラウザ側」、DESIGN.md 原則2）
    const first = await fetch(`${t.origin}/`);
    const second = await fetch(`${t.origin}/`);
    const csp1 = first.headers.get('content-security-policy') ?? '';
    const csp2 = second.headers.get('content-security-policy') ?? '';
    expect(csp1).toMatch(/script-src 'nonce-[A-Za-z0-9_-]{22}' 'strict-dynamic'/);
    expect(csp1).toContain("require-trusted-types-for 'script'");
    expect(csp1).toContain("trusted-types 'none'");
    expect(csp1).toContain("frame-ancestors 'none'");
    expect(csp1).not.toBe(csp2);
    const html = await first.text();
    const nonce = /'nonce-([^']+)'/.exec(csp1)?.[1];
    expect(html.match(/<script /g)).toHaveLength(2);
    expect(html.match(new RegExp(`<script nonce="${nonce}" src="/assets/`, 'g'))).toHaveLength(2);
    expect(first.headers.get('x-content-type-options')).toBe('nosniff');
    expect(first.headers.get('cache-control')).toBe('no-store');
    const text = await fetch(`${t.origin}/api/login/options`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain', origin: t.origin },
      body: 'x',
    });
    expect([400, 415]).toContain(text.status);
  });

  it('PWA のセッションのクッキーは HttpOnly と SameSite=Strict で、値は推測できない長さの乱数', async () => {
    // 攻撃者が持っている情報：利用者のブラウザで動くスクリプト（XSS を仮定）や、別のサイト
    // 試す経路：アカウントを作り、Set-Cookie を読む
    // 期待する結果：HttpOnly、SameSite=Strict、Path=/。値は43文字の base64url。クッキーの名前はアプリごとに一意
    // plan 11章：番号なし（CLAUDE.md「環境の注意」、ADR 0018）
    const browser = new Browser(t.origin);
    const options = await browser.post('/api/register/options');
    const response = browser.authenticator.create(options.json.options as never);
    const result = await fetch(`${t.origin}/api/register/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: t.origin },
      body: JSON.stringify({ ceremonyId: options.json.ceremonyId, response }),
    });
    const cookie = result.headers.getSetCookie().find((c) => c.startsWith('warifu_idp_pwa='));
    expect(cookie).toMatch(
      /^warifu_idp_pwa=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/,
    );
  });
});
