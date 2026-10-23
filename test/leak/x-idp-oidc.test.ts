// idp の OIDC の守り（不変条件1(a)・5・7・9、plan 3-1「step-up」、ADR 0006、ADR 0018）。

import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  Browser,
  clientAssertion,
  codeFlow,
  startAuthorization,
  startTestIdp,
  type TestIdp,
} from '../setup/idp.ts';

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 2, clients: [{ tenant: 0 }, { tenant: 1 }] });
});

afterAll(async () => {
  expect(t.outboundAttempts()).toBe(0);
  await t.stop();
});

const client = () => t.clients[0] as (typeof t.clients)[0];

describe('漏えい：idp の OIDC の守り', () => {
  it('discovery に出る方式は ES256、private_key_jwt、pairwise、code だけで、無効にした入口がない', async () => {
    // 攻撃者が持っている情報：なし（公開の discovery を読む）
    // 試す経路：/oidc/.well-known/openid-configuration を読む
    // 期待する結果：署名と企業の認証は ES256 と private_key_jwt だけ。sub は pairwise だけ。response_type は code だけ。
    //               userinfo、登録、introspection、revocation、ログアウト、CIBA、PAR の入口がない
    // plan 11章：テスト8（ライブラリに渡すアルゴリズムの設定）
    const discovery = (await (
      await fetch(`${t.issuer}/.well-known/openid-configuration`)
    ).json()) as Record<string, unknown>;
    expect(discovery.id_token_signing_alg_values_supported).toEqual(['ES256']);
    expect(discovery.token_endpoint_auth_methods_supported).toEqual(['private_key_jwt']);
    expect(discovery.token_endpoint_auth_signing_alg_values_supported).toEqual(['ES256']);
    expect(discovery.subject_types_supported).toEqual(['pairwise']);
    expect(discovery.response_types_supported).toEqual(['code']);
    expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
    expect(discovery.acr_values_supported).toEqual(['urn:warifu:acr:passkey']);
    for (const name of [
      'userinfo_endpoint',
      'registration_endpoint',
      'introspection_endpoint',
      'revocation_endpoint',
      'end_session_endpoint',
      'backchannel_authentication_endpoint',
      'pushed_authorization_request_endpoint',
      'device_authorization_endpoint',
    ]) {
      expect(discovery).not.toHaveProperty(name);
    }
    const jwks = (await (await fetch(`${t.issuer}/jwks`)).json()) as {
      keys: Record<string, unknown>[];
    };
    expect(jwks.keys).toHaveLength(1);
    expect(Object.keys(jwks.keys[0] ?? {}).sort()).toEqual([
      'alg',
      'crv',
      'kid',
      'kty',
      'use',
      'x',
      'y',
    ]);
  });

  it('step-up：max_age=0 と prompt=login では、セッションがあってもパスキーでの新しい認証を求める', async () => {
    // 攻撃者が持っている情報：利用者のブラウザの割符のセッション（席を外した端末など）
    // 試す経路：ログインの後、企業が max_age=0 で認可を求める。続けて prompt=login で求める
    // 期待する結果：どちらもログインのインタラクションが出る。新しい認証の後の auth_time は前より新しいか同じで、acr は passkey
    // plan 11章：番号なし（plan 3-1「step-up」、10章 M3）
    const browser = new Browser(t.origin);
    const first = await codeFlow(t, browser, client(), { mode: 'register' });
    const silent = await codeFlow(t, browser, client(), { mode: 'session' });
    expect(silent.interactionPaths).toHaveLength(0);
    const stepUp = await codeFlow(t, browser, client(), { mode: 'login', maxAge: 0 });
    expect(stepUp.interactionPaths).toHaveLength(1);
    expect(Number(stepUp.claims.auth_time)).toBeGreaterThanOrEqual(Number(first.claims.auth_time));
    expect(stepUp.claims.acr).toBe('urn:warifu:acr:passkey');
    const forced = await codeFlow(t, browser, client(), { mode: 'login', prompt: 'login' });
    expect(forced.interactionPaths).toHaveLength(1);
    expect(forced.claims.sub).toBe(first.claims.sub);
  });

  it.each([
    ['id_token_hint', 'x.y.z'],
    ['request', 'x.y.z'],
    ['request_uri', 'https://rp.invalid/req'],
    ['claims', '{"id_token":{"email":null}}'],
  ])('認可の要求に %s を付けると、入口で 400 にする', async (name, value) => {
    // 攻撃者が持っている情報：企業のクライアント ID（公開）
    // 試す経路：認可の要求に、受け付けない項目を付ける
    // 期待する結果：400。外へのつなぎは0件（request_uri を取りに行かない）
    // plan 11章：番号なし（不変条件7。ADR 0018）
    const browser = new Browser(t.origin);
    const { followed } = await startAuthorization(browser, client(), { extra: { [name]: value } });
    expect(followed.last.status).toBe(400);
    expect(followed.last.text).not.toContain(value);
  });

  it('PKCE がない要求と、plain の PKCE は受け付けない', async () => {
    // 攻撃者が持っている情報：企業のクライアント ID と redirect_uri（公開）
    // 試す経路：code_challenge を外した認可の要求と、code_challenge_method=plain の要求
    // 期待する結果：インタラクションに進まず、企業に invalid_request で戻すか、400 で止める
    // plan 11章：番号なし（ADR 0018）
    const c = client();
    const browser = new Browser(t.origin);
    for (const extra of [
      { code_challenge: '', code_challenge_method: '' },
      { code_challenge_method: 'plain' },
    ]) {
      const params = new URLSearchParams({
        client_id: c.clientId,
        redirect_uri: c.redirectUri,
        response_type: 'code',
        scope: 'openid',
        state: 's',
        nonce: 'n',
        code_challenge: 'x'.repeat(43),
        code_challenge_method: 'S256',
      });
      for (const [k, v] of Object.entries(extra)) {
        if (v === '') params.delete(k);
        else params.set(k, v);
      }
      const { external, path, last } = await browser.follow(`/oidc/auth?${params}`);
      expect(path.startsWith('/interaction/')).toBe(false);
      if (external !== undefined)
        expect(external.searchParams.get('error')).toBe('invalid_request');
      else expect(last.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('企業のクライアント認証は private_key_jwt（ES256、aud は issuer）だけ', async () => {
    // 攻撃者が持っている情報：企業のクライアント ID（公開）と、自分で作った鍵
    // 試す経路：トークンの入口に、client_secret_post、aud がトークンの入口の assertion、自分の鍵の assertion を送る
    // 期待する結果：どれも 401 invalid_client（認可コードの有無より前に、クライアント認証で止まる）
    // plan 11章：番号なし（不変条件9、ADR 0006）
    const c = client();
    const { generateKeyPair } = await import('jose');
    const other = await generateKeyPair('ES256');
    const wrongAud = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: c.kid })
      .setIssuer(c.clientId)
      .setSubject(c.clientId)
      .setAudience(`${t.issuer}/token`)
      .setIssuedAt()
      .setExpirationTime('2m')
      .setJti(randomUUID())
      .sign(c.privateKey);
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: c.kid })
      .setIssuer(c.clientId)
      .setSubject(c.clientId)
      .setAudience(t.issuer)
      .setIssuedAt()
      .setExpirationTime('2m')
      .setJti(randomUUID())
      .sign(other.privateKey);
    const bodies: Record<string, string>[] = [
      { client_id: c.clientId, client_secret: 'secret' },
      { client_assertion: wrongAud },
      { client_assertion: forged },
    ];
    for (const extra of bodies) {
      const response = await fetch(`${t.issuer}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'x',
          redirect_uri: c.redirectUri,
          code_verifier: 'y'.repeat(43),
          ...(extra.client_assertion === undefined
            ? {}
            : {
                client_id: c.clientId,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              }),
          ...extra,
        }),
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: string }).error).toBe('invalid_client');
    }
    // 正しい assertion なら、クライアント認証は通る（認可コードが無効なので invalid_grant）。
    const ok = await fetch(`${t.issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'x',
        redirect_uri: c.redirectUri,
        code_verifier: 'y'.repeat(43),
        client_id: c.clientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await clientAssertion(t, c),
      }),
    });
    expect(((await ok.json()) as { error: string }).error).toBe('invalid_grant');
  });

  it('接続しないを選ぶと、企業には access_denied が戻り、接続も別名も作られない', async () => {
    // 攻撃者が持っている情報：なし（利用者の選択の確認）
    // 試す経路：初めての企業で、同意の画面で「接続しない」を選ぶ。PWA で接続している企業を読む
    // 期待する結果：企業の redirect_uri に error=access_denied。接続している企業は0件
    // plan 11章：番号なし（plan 7章「27条の同意」）
    const browser = new Browser(t.origin);
    await expect(
      codeFlow(t, browser, client(), { mode: 'register', consent: 'decline' }),
    ).rejects.toThrow(/access_denied/);
    // PWA のセッションは別なので、PWA でログインし直して確かめる。
    const pwa = new Browser(t.origin, browser.authenticator);
    const options = await pwa.post('/api/login/options');
    const response = pwa.authenticator.get(options.json.options as never);
    expect(
      (await pwa.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response }))
        .status,
    ).toBe(200);
    expect((await pwa.get('/api/me')).json.companies).toEqual([]);
  });

  it('同意したテナントにも、別のテナントの同意は及ばない', async () => {
    // 攻撃者が持っている情報：A社に接続済みの利用者のブラウザ
    // 試す経路：A社で同意した後、B社で認可を求める
    // 期待する結果：B社では同意の画面が出る（A社の同意で自動的に接続しない）
    // plan 11章：テスト4
    const browser = new Browser(t.origin);
    await codeFlow(t, browser, client(), { mode: 'register' });
    const b = await codeFlow(t, browser, t.clients[1] as (typeof t.clients)[0], {
      mode: 'session',
    });
    expect(b.interactionPaths).toHaveLength(1);
  });
});
