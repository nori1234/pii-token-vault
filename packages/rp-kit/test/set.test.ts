// rp-kit の SET の検証の単体検査（spec 02 の7章、RP-50、ADR 0026 の O-67）。署名、宛先、形式を確かめた後で鮮度を確かめ、
// 受け口が、割符の決めた理由（set_too_old、iat_in_future）を返せることを確かめる。割符の鍵の代わりに、テストの鍵で署名する。

import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { exportJWK, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { createCompanyApiClient, setRefusalOf } from '../src/company-api.ts';
import { RpKitError } from '../src/errors.ts';

const ORIGIN = 'https://api.warifu.example';
const TENANT = randomUUID();
const NOW = 1_800_000_000;
const setKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const otherKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });

async function sdk(clock: { now: number; fetches: number } = { now: NOW, fetches: 0 }) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwks = {
    keys: [{ ...(await exportJWK(setKey.publicKey)), kid: 'set', alg: 'ES256', use: 'sig' }],
  };
  return createCompanyApiClient({
    origin: ORIGIN,
    clientId: 'api-client',
    tenantId: TENANT,
    privateKey: (await exportJWK(privateKey)) as JWK,
    kid: 'k1',
    now: () => new Date(clock.now * 1000),
    send: async (request) => {
      if (request.url !== `${ORIGIN}/jwks`) throw new Error('予期しない宛先');
      clock.fetches += 1;
      return { status: 200, headers: {}, body: JSON.stringify(jwks) };
    },
  });
}

function signedSet(
  iat: number,
  options: { aud?: string; key?: typeof setKey.privateKey; kid?: string } = {},
) {
  return new SignJWT({
    events: { 'urn:warifu:secevent:initial-link-waiting': { initial_link_id: 'L'.repeat(43) } },
  })
    .setProtectedHeader({ alg: 'ES256', kid: options.kid ?? 'set', typ: 'secevent+jwt' })
    .setIssuer(ORIGIN)
    .setAudience(options.aud ?? TENANT)
    .setIssuedAt(iat)
    .setJti(randomBytes(16).toString('base64url'))
    .sign(options.key ?? setKey.privateKey);
}

async function refusalOf(promise: Promise<unknown>) {
  try {
    await promise;
    return undefined;
  } catch (error) {
    expect(error).toBeInstanceOf(RpKitError);
    return setRefusalOf(error);
  }
}

describe('rp-kit の SET の検証（spec 02 の7章）', () => {
  it('署名の正しい SET でも、300秒より古ければ set_too_old、30秒より先なら iat_in_future で断る', async () => {
    // 攻撃者が持っている情報：以前に送られた、署名の正しい SET（企業の受け口の記録や、通信の途中で手に入れた）
    // 試す経路：10分前、301秒前、31秒先の iat の SET を、受け口に送り直す
    // 期待する結果：古いものは 400 と set_too_old（割符は、新しい jti と iat で送り直す）。先の時刻は 400 と iat_in_future
    //               （割符は保留にする）。300秒前から30秒先までは受け取る
    // plan 11章：テスト12（RP-50）
    const client = await sdk();
    for (const age of [600, 301]) {
      expect(await refusalOf(client.verifySet(await signedSet(NOW - age)))).toEqual({
        status: 400,
        body: { err: 'invalid_request', warifu_reason: 'set_too_old' },
      });
    }
    for (const ahead of [31, 600]) {
      expect(await refusalOf(client.verifySet(await signedSet(NOW + ahead)))).toEqual({
        status: 400,
        body: { err: 'invalid_request', warifu_reason: 'iat_in_future' },
      });
    }
    for (const offset of [-300, -1, 0, 30]) {
      const set = await client.verifySet(await signedSet(NOW + offset));
      expect(set.iat).toBe(NOW + offset);
    }
  });

  it('署名、宛先、形式の違う SET には、鮮度の理由を返さない', async () => {
    // 攻撃者が持っている情報：別の企業あての SET、または自分の鍵で署名した SET
    // 試す経路：aud の違う古い SET、別の鍵で署名した古い SET、JWT でない本文を送る
    // 期待する結果：400 と err だけ（set_too_old を返して、割符に送り直させない。理由は、正しい SET にだけ返す）
    // plan 11章：テスト12（RP-50）
    const client = await sdk();
    const plain = { status: 400, body: { err: 'invalid_request' } };
    expect(
      await refusalOf(client.verifySet(await signedSet(NOW - 600, { aud: randomUUID() }))),
    ).toEqual(plain);
    expect(
      await refusalOf(client.verifySet(await signedSet(NOW - 600, { key: otherKey.privateKey }))),
    ).toEqual(plain);
    expect(await refusalOf(client.verifySet('not-a-jwt'))).toEqual(plain);
    expect(setRefusalOf(new Error('x'))).toEqual(plain);
  });

  it('知らない kid の SET を送り続けても、割符へ鍵を取りに行くのは30秒に1回まで', async () => {
    // 攻撃者が持っている情報：企業の SET の受け口の URL（公開の入口）
    // 試す経路：自分の鍵で署名し、割符にない kid を付けた SET を、受け口に何度も送る
    // 期待する結果：どれも 400 と err だけ。企業のサーバーが割符へ鍵を取りに行くのは、30秒に1回まで
    //               （受け口を、割符への要求を増やす踏み台にさせない）。30秒たてば、取り直して鍵の入れ替えに追いつく
    // plan 11章：テスト12（RP-50）
    const clock = { now: NOW, fetches: 0 };
    const client = await sdk(clock);
    const plain = { status: 400, body: { err: 'invalid_request' } };
    const forged = () => signedSet(clock.now, { key: otherKey.privateKey, kid: 'unknown' });
    for (let i = 0; i < 5; i += 1) {
      expect(await refusalOf(client.verifySet(await forged()))).toEqual(plain);
    }
    expect(clock.fetches).toBe(1);
    clock.now += 31;
    expect(await refusalOf(client.verifySet(await forged()))).toEqual(plain);
    expect(clock.fetches).toBe(2);
    // 正しい SET は、その間も受け取れる。
    await expect(client.verifySet(await signedSet(clock.now))).resolves.toBeDefined();
    expect(clock.fetches).toBe(2);
  });
});
