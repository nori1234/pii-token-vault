// WebAuthn で受け付けるアルゴリズムと、登録した公開鍵の検査（不変条件9、ADR 0007 の決定2、ADR 0012 の決定6・10）。
// ソフトウェアの認証器（test/setup/soft-authenticator.ts）で、P-256、Ed25519、RSA の鍵と、わざと違えた鍵を作って確かめる。
// アカウントの作成の上限（IP ごと。ADR 0018）に掛からないよう、x-webauthn-guards.test.ts とは別の idp で動かす。

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { inspectPublicKey, userIdFromHandle } from '../../packages/idp/src/webauthn.ts';
import { rawRoleClient } from '../setup/db.ts';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { cbor, type SoftAuthenticator } from '../setup/soft-authenticator.ts';

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
});

afterEach(() => {
  expect(t.outboundAttempts()).toBe(0);
});

afterAll(async () => {
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

async function loginWith(browser: Browser) {
  const options = await browser.post('/api/login/options');
  expect(options.status).toBe(200);
  const response = browser.authenticator.get(options.json.options as never);
  return browser.post('/api/login/verify', { ceremonyId: options.json.ceremonyId, response });
}

describe('漏えい：WebAuthn のアルゴリズムと公開鍵（ADR 0012 の決定6・10）', () => {
  it('2：選択肢のアルゴリズムは ES256、EdDSA、RS256 の順で、どれも登録してログインできる', async () => {
    // 攻撃者が持っている情報：なし（自分の認証器の応答を作れる）
    // 試す経路：登録の選択肢の pubKeyCredParams を読む。P-256、Ed25519、2048 ビットの RSA の鍵で、それぞれ登録してログインする
    // 期待する結果：選択肢は [-7, -8, -257]。どれも登録とログインが 200。DB には alg と、RS256 だけ鍵長（2048）が残る
    // plan 11章：テスト8（ライブラリに渡すアルゴリズムの設定。ADR 0012 の決定6・10）
    const options = await new Browser(t.origin).post('/api/register/options');
    const params = (options.json.options as { pubKeyCredParams: { alg: number }[] })
      .pubKeyCredParams;
    expect(params.map((p) => p.alg)).toEqual([-7, -8, -257]);

    const recorded: unknown[] = [];
    for (const alg of ['ES256', 'EdDSA', 'RS256'] as const) {
      const browser = new Browser(t.origin);
      expect((await registerWith(browser, { alg })).status).toBe(200);
      expect((await loginWith(new Browser(t.origin, browser.authenticator))).status).toBe(200);
      const userId = userIdFromHandle(browser.authenticator.credentials.at(-1)?.userHandle);
      const client = await rawRoleClient('warifu_idp');
      try {
        await client.query('BEGIN');
        await client.query("SELECT pg_catalog.set_config('warifu.user_id', $1, true)", [userId]);
        const { rows } = await client.query('SELECT alg, rsa_bits FROM idp.credentials');
        recorded.push(...rows);
        await client.query('ROLLBACK');
      } finally {
        await client.end();
      }
    }
    expect(recorded).toEqual([
      { alg: -7, rsa_bits: null },
      { alg: -8, rsa_bits: null },
      { alg: -257, rsa_bits: 2048 },
    ]);
  });

  it('2：Ed25519 以外の EdDSA、P-256 以外の ES256、2048 ビット未満の RSA の鍵の登録は拒否する', async () => {
    // 攻撃者が持っている情報：なし（自分の認証器の応答を作れる）
    // 試す経路：Ed448 の鍵を -8、P-384 の鍵を -7、1024 ビットの RSA の鍵を -257 として、attestation は none で登録する
    //           （none では、ライブラリは公開鍵で署名を確かめない）
    // 期待する結果：どれも 400 { error: 'failed' }。アカウントもセッションもできない
    // plan 11章：テスト8（ADR 0012 の決定6・10。不変条件9）
    for (const overrides of [
      { alg: 'EdDSA', okpCurve: 'Ed448' },
      { alg: 'ES256', ecCurve: 'P-384' },
      { alg: 'RS256', rsaBits: 1024 },
    ] as const) {
      const browser = new Browser(t.origin);
      const result = await registerWith(browser, overrides);
      expect(result.status).toBe(400);
      expect(result.json).toEqual({ error: 'failed' });
      expect((await browser.get('/api/me')).status).toBe(401);
    }
  });

  it('2：公開鍵の検査は、鍵の種類と曲線をアルゴリズムと突き合わせ、RSA の鍵長を境界どおりに数える', () => {
    // 攻撃者が持っている情報：なし（自分の認証器の公開鍵を自由に作れる）
    // 試す経路：inspectPublicKey に、種類・曲線・アルゴリズムの組み合わせを違えた鍵と、2047・2048 ビットの RSA の鍵を渡す
    // 期待する結果：合う組み合わせだけを受け付ける。RSA は 2048 ビット以上だけで、先頭の0のバイトは鍵長に数えない
    // plan 11章：テスト8（ADR 0012 の決定6・10）
    const point = new Uint8Array(32).fill(1);
    const modulus = (first: number, leadingZero = false) =>
      new Uint8Array([...(leadingZero ? [0] : []), first, ...new Uint8Array(255).fill(0xff)]);
    const key = (entries: [number, number | Uint8Array][]) =>
      inspectPublicKey(cbor(new Map<number, number | Uint8Array>(entries)));
    expect(
      key([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, point],
        [-3, point],
      ]),
    ).toEqual({ alg: -7, rsaBits: null });
    expect(
      key([
        [1, 1],
        [3, -8],
        [-1, 6],
        [-2, point],
      ]),
    ).toEqual({ alg: -8, rsaBits: null });
    expect(
      key([
        [1, 3],
        [3, -257],
        [-1, modulus(0x80)],
        [-2, new Uint8Array([1, 0, 1])],
      ]),
    ).toEqual({
      alg: -257,
      rsaBits: 2048,
    });
    expect(
      key([
        [1, 3],
        [3, -257],
        [-1, modulus(0x80, true)],
        [-2, new Uint8Array([1, 0, 1])],
      ]),
    ).toEqual({ alg: -257, rsaBits: 2048 });
    expect(
      key([
        [1, 3],
        [3, -257],
        [-1, modulus(0x7f)],
        [-2, new Uint8Array([1, 0, 1])],
      ]),
    ).toBeUndefined();
    // 種類か曲線が、アルゴリズムと合わない。
    expect(
      key([
        [1, 1],
        [3, -8],
        [-1, 7],
        [-2, point],
      ]),
    ).toBeUndefined();
    expect(
      key([
        [1, 2],
        [3, -8],
        [-1, 6],
        [-2, point],
        [-3, point],
      ]),
    ).toBeUndefined();
    expect(
      key([
        [1, 1],
        [3, -7],
        [-1, 1],
        [-2, point],
      ]),
    ).toBeUndefined();
    expect(
      key([
        [1, 2],
        [3, -7],
        [-1, 2],
        [-2, point],
        [-3, point],
      ]),
    ).toBeUndefined();
    expect(
      key([
        [1, 2],
        [3, -35],
        [-1, 2],
        [-2, point],
        [-3, point],
      ]),
    ).toBeUndefined();
    expect(inspectPublicKey(new Uint8Array([0xff]))).toBeUndefined();
  });
});
