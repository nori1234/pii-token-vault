// パスキーの検証で、ライブラリの手前と後に置く検査（ADR 0007 の決定1〜5、不変条件1(b)・7・9）。
// 受け付けるアルゴリズムと鍵の検査（ADR 0012 の決定6・10）は、x-webauthn-algorithms.test.ts で確かめる。
// ソフトウェアの認証器（test/setup/soft-authenticator.ts）で、わざと違えた応答を作って確かめる。

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { SoftAuthenticator } from '../setup/soft-authenticator.ts';
import { REPO_ROOT, stripComments } from '../setup/source.ts';

let t: TestIdp;
const realFetch = globalThis.fetch;
const outbound: string[] = [];

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
  // テストの中で、idp 以外への fetch が起きたら失敗させて数える（ADR 0007 の7、不変条件7）。
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (new URL(href).origin !== t.origin) {
      outbound.push(new URL(href).host);
      throw new Error('outbound blocked in test');
    }
    return realFetch(input, init);
  });
});

afterEach(() => {
  expect(outbound).toEqual([]);
  expect(t.outboundAttempts()).toBe(0);
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await t.stop();
});

async function registerWith(
  browser: Browser,
  overrides: Parameters<SoftAuthenticator['create']>[1],
) {
  const options = await browser.post('/api/register/options');
  expect(options.status).toBe(200);
  const response = browser.authenticator.create(options.json.options as never, overrides);
  return browser.post('/api/register/verify', { ceremonyId: options.json.ceremonyId, response });
}

async function loginWith(
  browser: Browser,
  overrides: Parameters<SoftAuthenticator['get']>[2] = {},
  credential = browser.authenticator.credentials.at(-1),
) {
  const options = await browser.post('/api/login/options');
  expect(options.status).toBe(200);
  const response = browser.authenticator.get(options.json.options as never, credential, overrides);
  return browser.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response });
}

describe('漏えい：パスキーの検証の守り（ADR 0007）', () => {
  it('1：attestation が none 以外（x5c 付きの packed）の登録は、ライブラリに渡さずに拒否する', async () => {
    // 攻撃者が持っている情報：なし（自分の認証器の応答を作れる）。証明書の CRL 配布点に、自分の決めた URL を入れられる
    // 試す経路：登録の応答の attestationObject を、x5c 付きの packed にして送る
    // 期待する結果：400 { error: 'failed' }。外へのつなぎは0件。アカウントもセッションもできない
    // plan 11章：番号なし（ADR 0007 の1。不変条件7）
    const browser = new Browser(t.origin);
    const result = await registerWith(browser, { fmt: 'packed' });
    expect(result.status).toBe(400);
    expect(result.json).toEqual({ error: 'failed' });
    expect((await browser.get('/api/me')).status).toBe(401);
  });

  it('2：同じアルゴリズムの一覧を、選択肢と検証の両方に渡している（片方だけに渡していない）', () => {
    // 攻撃者が持っている情報：なし（静的な固定。検証の側に渡し忘れると、ライブラリの既定（PQC に対応した実行環境では ML-DSA-44 を含む）で検証される）
    // 試す経路：packages/idp/src/webauthn.ts の、generateRegistrationOptions と verifyRegistrationResponse の呼び出しを読む
    // 期待する結果：SUPPORTED_ALGORITHM_IDS は [-7, -8, -257]。supportedAlgorithmIDs の指定はちょうど2か所で、どちらも同じ定数
    // plan 11章：テスト8（ライブラリに渡すアルゴリズムの設定）
    const code = stripComments(
      readFileSync(join(REPO_ROOT, 'packages/idp/src/webauthn.ts'), 'utf8'),
    );
    expect(code).toMatch(
      /SUPPORTED_ALGORITHM_IDS: readonly number\[\] = Object\.freeze\(\[-7, -8, -257\]\)/,
    );
    expect(code.match(/supportedAlgorithmIDs:/g)).toHaveLength(2);
    expect(code.match(/supportedAlgorithmIDs: \[\.\.\.SUPPORTED_ALGORITHM_IDS\]/g)).toHaveLength(2);
    expect(code).not.toMatch(/MetadataService/);
  });

  it('3：userHandle が持ち主と違う、または無いアサーションは拒否する（ほかの手がかりで探さない）', async () => {
    // 攻撃者が持っている情報：自分のパスキーと、別の利用者の userHandle（利用者 ID の16バイト）
    // 試す経路：自分の資格情報で署名したアサーションの userHandle を、別の利用者のものに差し替える。userHandle を外す
    // 期待する結果：どちらも 401 { error: 'failed' }。正しい userHandle では 200
    // plan 11章：番号なし（ADR 0007 の3。不変条件1(b)）
    const victim = new Browser(t.origin);
    expect((await victim.registerAccount()).status).toBe(200);
    const attacker = new Browser(t.origin);
    expect((await attacker.registerAccount()).status).toBe(200);
    const victimHandle = victim.authenticator.credentials[0]?.userHandle;
    const swapped = await loginWith(attacker, { userHandle: victimHandle });
    expect(swapped.status).toBe(401);
    expect(swapped.json).toEqual({ error: 'failed' });
    const missing = await loginWith(attacker, { userHandle: null });
    expect(missing.status).toBe(401);
    expect(missing.json).toEqual({ error: 'failed' });
    const fresh = new Browser(t.origin, attacker.authenticator);
    expect((await loginWith(fresh)).status).toBe(200);
  });

  it('4：UV のない登録とアサーションは、サーバーで拒否する', async () => {
    // 攻撃者が持っている情報：利用者の認証器に触れられるが、生体認証や PIN を通せない（UV が 0 の応答）
    // 試す経路：UV フラグが 0 の登録の応答と、UV フラグが 0 のアサーションを送る
    // 期待する結果：登録は 400、ログインは 401。どちらも { error: 'failed' }
    // plan 11章：番号なし（ADR 0007 の4。不変条件1(b)）
    const browser = new Browser(t.origin);
    const noUv = await registerWith(browser, { uv: false });
    expect(noUv.status).toBe(400);
    expect(noUv.json).toEqual({ error: 'failed' });
    expect((await browser.registerAccount()).status).toBe(200);
    const login = await loginWith(new Browser(t.origin, browser.authenticator), { uv: false });
    expect(login.status).toBe(401);
    expect(login.json).toEqual({ error: 'failed' });
  });

  it('5：失敗の理由を外に出さない（応答もログも同じ形）', async () => {
    // 攻撃者が持っている情報：自分の認証器
    // 試す経路：オリジンの違い、チャレンジの使い回し、知らない資格情報、壊れた本文で、ログインを試す
    // 期待する結果：どれも 401 { error: 'failed' }（壊れた本文も同じ）。ログにチャレンジや資格情報 ID が出ない
    // plan 11章：番号なし（ADR 0007 の5。不変条件4）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const credential = browser.authenticator.credentials[0];
    const results = [];
    results.push(await loginWith(browser, { origin: 'http://localhost:1' }));
    const options = await browser.post('/api/login/options');
    const response = browser.authenticator.get(options.json.options as never);
    results.push(
      await browser.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response }),
    );
    // 同じチャレンジの2回目。
    results.push(
      await browser.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response }),
    );
    const stranger = new SoftAuthenticator(t.origin);
    const other = new Browser(t.origin, stranger);
    await other.registerAccount();
    const unknown = stranger.credentials[0];
    if (unknown === undefined || credential === undefined) throw new Error('資格情報がない');
    // 他人の資格情報 ID と、自分の userHandle。
    results.push(await loginWith(browser, { userHandle: credential.userHandle }, unknown));
    results.push(
      await browser.post('/api/login/verify', { ceremonyId: 'x', response: 'not-an-object' }),
    );
    expect(results[1]?.status).toBe(200);
    for (const result of [results[0], results[2], results[3], results[4]]) {
      expect(result?.status).toBe(401);
      expect(result?.json).toEqual({ error: 'failed' });
    }
    const challenge = (options.json.options as { challenge: string }).challenge;
    const logs = t.logLines().join('\n');
    expect(logs).not.toContain(challenge);
    expect(logs).not.toContain(Buffer.from(credential.id).toString('base64url'));
  });

  it('チャレンジは目的と相手に結び付き、別の目的では使えない', async () => {
    // 攻撃者が持っている情報：PWA のログインのチャレンジ
    // 試す経路：PWA のログインのチャレンジで作ったアサーションを、PWA の step-up の検証に送る
    // 期待する結果：401 { error: 'failed' }
    // plan 11章：番号なし（ADR 0018。チャレンジの使い回し）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const options = await browser.post('/api/login/options');
    const response = browser.authenticator.get(options.json.options as never);
    const result = await browser.post('/api/stepup/verify', {
      ceremonyId: options.json.ceremonyId,
      response,
    });
    expect(result.status).toBe(401);
    expect(result.json).toEqual({ error: 'failed' });
  });
});
