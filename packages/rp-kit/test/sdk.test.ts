// rp-kit の単体検査（spec 02 の 15-1「rp-kit の単体検査」、ADR 0029 の O-108・O-110）。
// 通信の守り（宛先、リダイレクト、大きさ）、エラーに値を入れないこと、PKCE、jti、承認の JWT の検証（用途、操作、
// 申請、sub、期限、使い回し）を、割符を立てずに確かめる。割符の鍵の代わりに、テストの中で作った鍵で署名する。

import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { exportJWK, type JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { RpKitError } from '../src/errors.ts';
import { memoryJtiStore } from '../src/jti.ts';
import {
  createWarifuClient,
  INITIAL_LINK_APPROVAL_TYP,
  OP_APPROVAL_TYP,
  type PendingAuthorization,
  type WarifuLogin,
} from '../src/oidc.ts';
import { newPkce } from '../src/pkce.ts';
import {
  guardedSend,
  type HttpRequest,
  type HttpResponse,
  MAX_RESPONSE_BYTES,
  parseOrigin,
} from '../src/transport.ts';

const IDP = 'https://idp.warifu.example';
const ISSUER = `${IDP}/oidc`;
const CLIENT_ID = 'demo-securities';
const SUB = 'S'.repeat(43);

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKey };
}

const op = keyPair();
const link = keyPair();

async function publicJwk(key: ReturnType<typeof keyPair>['publicKey'], kid: string) {
  return { ...(await exportJWK(key)), kid, alg: 'ES256', use: 'sig' };
}

/** 割符の公開鍵の URL だけに答える通信（固定の応答）。ほかの宛先は呼ばれたら失敗。 */
async function fakeIdp(calls: HttpRequest[] = []) {
  const jwks: Record<string, unknown> = {
    [`${IDP}/op-approval/jwks`]: { keys: [await publicJwk(op.publicKey, 'op')] },
    [`${IDP}/initial-link/jwks`]: { keys: [await publicJwk(link.publicKey, 'link')] },
  };
  return async (request: HttpRequest) => {
    calls.push(request);
    const body = jwks[request.url];
    if (body === undefined) throw new Error('予期しない宛先');
    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    };
  };
}

async function client(now = () => new Date()) {
  const { privateKey } = keyPair();
  return createWarifuClient({
    idpOrigin: IDP,
    clientId: CLIENT_ID,
    redirectUri: 'https://securities.example/callback',
    privateKey: (await exportJWK(privateKey)) as JWK,
    kid: 'k1',
    send: await fakeIdp(),
    now,
    jtiStore: memoryJtiStore(() => now().getTime()),
  });
}

async function approvalJwt(
  key: ReturnType<typeof keyPair>['privateKey'],
  kid: string,
  typ: string,
  claims: Record<string, unknown>,
  lifetime = 300,
) {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({ acr: 'urn:warifu:acr:passkey', auth_time: iat, ...claims })
    .setProtectedHeader({ alg: 'ES256', kid, typ })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setSubject(SUB)
    .setIssuedAt(iat)
    .setExpirationTime(iat + lifetime)
    .setJti(randomBytes(16).toString('base64url'))
    .sign(key);
}

function pendingFor(detail: Record<string, unknown>): PendingAuthorization {
  return { state: 's', nonce: 'n', verifier: 'v', maxAge: 0, startedAt: 0, detail };
}

function loginWith(granted: Record<string, unknown>): WarifuLogin {
  return {
    iss: ISSUER,
    sub: SUB,
    acr: 'urn:warifu:acr:passkey',
    authTime: 0,
    recoveredAt: null,
    contactAlias: null,
    authorizationDetails: [granted],
  };
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    expect(error).toBeInstanceOf(RpKitError);
    return (error as RpKitError).code;
  }
}

describe('rp-kit の単体検査（ADR 0029）', () => {
  it('通信：設定のオリジンの外、利用者情報付き、3xx、大きすぎる応答は失敗にする', async () => {
    // 攻撃者が持っている情報：企業のサーバーに渡る値（応答の中の URL など）を操れる立場
    // 試す経路：設定と違うオリジン、ユーザー名付きの URL へ送らせる。3xx と、上限を超える応答を返す
    // 期待する結果：forbidden_destination か unavailable。企業の通信の関数は、許したオリジンにだけ呼ばれる
    // plan 11章：テスト11（企業の側の SSRF の入り口にしない）
    const calls: HttpRequest[] = [];
    const send = guardedSend(
      async (request): Promise<HttpResponse> => {
        calls.push(request);
        if (request.url.endsWith('/redirect')) {
          return { status: 302, headers: { location: 'http://169.254.169.254/' }, body: '' };
        }
        if (request.url.endsWith('/huge')) {
          return { status: 200, headers: {}, body: 'x'.repeat(MAX_RESPONSE_BYTES + 1) };
        }
        return { status: 200, headers: {}, body: '{}' };
      },
      [IDP],
    );
    expect(await codeOf(send({ method: 'GET', url: 'https://evil.example/x', headers: {} }))).toBe(
      'forbidden_destination',
    );
    expect(
      await codeOf(send({ method: 'GET', url: 'https://user@idp.warifu.example/x', headers: {} })),
    ).toBe('forbidden_destination');
    expect(await codeOf(send({ method: 'GET', url: `${IDP}/redirect`, headers: {} }))).toBe(
      'unavailable',
    );
    expect(await codeOf(send({ method: 'GET', url: `${IDP}/huge`, headers: {} }))).toBe(
      'unavailable',
    );
    expect(calls.map((c) => c.url)).toEqual([`${IDP}/redirect`, `${IDP}/huge`]);
    for (const bad of [
      'https://idp.example/path',
      'ftp://idp.example',
      'https://a@b.example',
      // http（平文）は、ループバックだけ。
      'http://idp.example',
      'http://localhost.example',
      'http://169.254.169.254',
      'x',
    ]) {
      expect(() => parseOrigin(bad)).toThrow(RpKitError);
    }
    for (const ok of ['https://idp.example', 'http://localhost:3000', 'http://127.0.0.1:3000']) {
      expect(parseOrigin(ok)).toBe(ok);
    }
    expect(parseOrigin('http://[::1]:3000/')).toBe('http://[::1]:3000');
  });

  it('エラーには値を入れない。割符の error の値も、形の合うものだけ', () => {
    // 攻撃者が持っている情報：なし（企業の側のログに、トークンや ID を残させない。spec 02、不変条件4）
    // 試す経路：RpKitError に、トークンのような値を reason として渡す
    // 期待する結果：メッセージはコードだけ。reason は英小文字と _ だけのときに限る
    // plan 11章：テスト7
    const leaked = new RpKitError('rejected', 'eyJhbGciOiJFUzI1NiJ9.secret');
    expect(leaked.message).toBe('rp-kit: rejected');
    expect(leaked.reason).toBeUndefined();
    expect(new RpKitError('rejected', 'invalid_request').reason).toBe('invalid_request');
  });

  it('PKCE：verifier は43文字、challenge は S256（SHA-256 の base64url）', () => {
    // 攻撃者が持っている情報：認可コード（横取りした）
    // 試す経路：SDK が作った verifier と challenge を比べる
    // 期待する結果：challenge は verifier の SHA-256 の base64url で、毎回違う
    // plan 11章：番号なし（RFC 7636。ADR 0029 の O-110）
    const a = newPkce();
    const b = newPkce();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.challenge).toBe(createHash('sha256').update(a.verifier).digest('base64url'));
    expect(a.verifier).not.toBe(b.verifier);
  });

  it('窓口の承認：用途、操作、申請、sub、期限、鍵、typ が違えば断り、jti は一度だけ', async () => {
    // 攻撃者が持っている情報：別の操作や別の申請の承認の JWT、紐付けの承認の JWT（流用しようとする）
    // 試す経路：申請と違う操作や申請 ID の JWT、5分を超える JWT、別の鍵の JWT、同じ JWT の2回目を確かめさせる
    // 期待する結果：verification_failed。2回目は replayed。正しいものは1回だけ通る
    // plan 11章：テスト1（RP-10・RP-12・RP-21）
    const sdk = await client();
    const requestId = randomBytes(16).toString('base64url');
    const detail = {
      type: 'warifu_desk',
      actions: ['desk.case.status.read'],
      identifier: requestId,
      subject: SUB,
    };
    const good = { purpose: 'desk', action: 'desk.case.status.read', request_id: requestId };
    const cases: [
      Record<string, unknown>,
      ReturnType<typeof keyPair>['privateKey'],
      string,
      string,
      number,
    ][] = [
      [{ ...good, action: 'desk.order.status.read' }, op.privateKey, 'op', OP_APPROVAL_TYP, 300],
      [{ ...good, request_id: 'other-request-0001' }, op.privateKey, 'op', OP_APPROVAL_TYP, 300],
      [{ ...good, purpose: 'initial_link' }, op.privateKey, 'op', OP_APPROVAL_TYP, 300],
      [good, op.privateKey, 'op', OP_APPROVAL_TYP, 600],
      [good, link.privateKey, 'op', OP_APPROVAL_TYP, 300],
      [good, op.privateKey, 'op', INITIAL_LINK_APPROVAL_TYP, 300],
    ];
    for (const [claims, key, kid, typ, lifetime] of cases) {
      const jwt = await approvalJwt(key, kid, typ, claims, lifetime);
      expect(
        await codeOf(
          sdk.verifyDeskApproval(loginWith({ ...detail, approval: jwt }), pendingFor(detail)),
        ),
      ).toBe('verification_failed');
    }
    const jwt = await approvalJwt(op.privateKey, 'op', OP_APPROVAL_TYP, good);
    // 申請と違う detail（別の申請 ID）を Grant に入れても通らない。
    expect(
      await codeOf(
        sdk.verifyDeskApproval(
          loginWith({ ...detail, identifier: 'other-request-0001', approval: jwt }),
          pendingFor(detail),
        ),
      ),
    ).toBe('verification_failed');
    const ok = await sdk.verifyDeskApproval(
      loginWith({ ...detail, approval: jwt }),
      pendingFor(detail),
    );
    expect(ok).toMatchObject({ action: 'desk.case.status.read', requestId, changeId: null });
    expect(
      await codeOf(
        sdk.verifyDeskApproval(loginWith({ ...detail, approval: jwt }), pendingFor(detail)),
      ),
    ).toBe('replayed');
  });

  it('初回紐付け：最初の承認は状態だけを受け、JWT があれば断る。最終の承認は紐付けの鍵と用途だけ', async () => {
    // 攻撃者が持っている情報：窓口の承認の JWT（紐付けに流用しようとする）
    // 試す経路：最初の承認の結果に JWT を混ぜる。最終の承認に、窓口の鍵と typ の JWT や、別の移行専用ID の JWT を渡す
    // 期待する結果：verification_failed。正しい紐付けの承認だけが通り、移行専用ID を返す
    // plan 11章：テスト9（紐付けの攻撃）
    const sdk = await client();
    const id = 'L'.repeat(43);
    const approve = {
      type: 'warifu_initial_link',
      actions: ['initial_link.approve'],
      identifier: id,
      subject: SUB,
    };
    expect(
      await sdk.readInitialLink(
        loginWith({ ...approve, state: 'pending_notice' }),
        pendingFor(approve),
      ),
    ).toEqual({ stage: 'approve', state: 'pending_notice' });
    const desk = await approvalJwt(op.privateKey, 'op', OP_APPROVAL_TYP, { purpose: 'desk' });
    expect(
      await codeOf(
        sdk.readInitialLink(
          loginWith({ ...approve, state: 'pending_notice', approval: desk }),
          pendingFor(approve),
        ),
      ),
    ).toBe('verification_failed');
    const finalize = { ...approve, actions: ['initial_link.finalize'] };
    for (const jwt of [
      desk,
      await approvalJwt(op.privateKey, 'op', INITIAL_LINK_APPROVAL_TYP, {
        purpose: 'initial_link',
        initial_link_id: id,
      }),
      await approvalJwt(link.privateKey, 'link', INITIAL_LINK_APPROVAL_TYP, {
        purpose: 'initial_link',
        initial_link_id: 'M'.repeat(43),
      }),
    ]) {
      expect(
        await codeOf(
          sdk.readInitialLink(loginWith({ ...finalize, approval: jwt }), pendingFor(finalize)),
        ),
      ).toBe('verification_failed');
    }
    const jwt = await approvalJwt(link.privateKey, 'link', INITIAL_LINK_APPROVAL_TYP, {
      purpose: 'initial_link',
      initial_link_id: id,
    });
    const outcome = await sdk.readInitialLink(
      loginWith({ ...finalize, approval: jwt }),
      pendingFor(finalize),
    );
    expect(outcome).toMatchObject({ stage: 'finalize', initialLinkId: id });
  });

  it('使った承認は、exp を過ぎて時計のずれの許容の間も、もう一度は通らない', async () => {
    // 攻撃者が持っている情報：一度使われた承認の JWT（企業のサーバーの記録などから）
    // 試す経路：exp の前に1回使う。exp の1秒後（検証は、時計のずれの許容の30秒の間は通る）に、同じ JWT をもう一度確かめる。
    //           許容を過ぎた後にも確かめる
    // 期待する結果：exp の1秒後と29秒後は replayed（使い済みの記録を、exp では忘れない）。31秒後は期限切れで
    //               verification_failed。どの時刻でも、2回目は通らない
    // plan 11章：テスト1（RP-12、ADR 0030 の O-115）
    let offsetMs = 0;
    const base = Date.now();
    const sdk = await client(() => new Date(base + offsetMs));
    const requestId = randomBytes(16).toString('base64url');
    const detail = {
      type: 'warifu_desk',
      actions: ['desk.case.status.read'],
      identifier: requestId,
      subject: SUB,
    };
    const jwt = await approvalJwt(op.privateKey, 'op', OP_APPROVAL_TYP, {
      purpose: 'desk',
      action: 'desk.case.status.read',
      request_id: requestId,
    });
    const verify = () =>
      codeOf(sdk.verifyDeskApproval(loginWith({ ...detail, approval: jwt }), pendingFor(detail)));
    offsetMs = 299_000;
    expect(await verify()).toBeUndefined();
    expect(await verify()).toBe('replayed');
    for (const seconds of [301, 329]) {
      offsetMs = seconds * 1000;
      expect(await verify()).toBe('replayed');
      expect(await verify()).toBe('replayed');
    }
    offsetMs = 331_000;
    expect(await verify()).toBe('verification_failed');
    // 置き場所の単体でも、keepUntil を過ぎるまでは忘れない。
    let nowMs = 0;
    const store = memoryJtiStore(() => nowMs);
    expect(await store.use('j', 1000)).toBe(true);
    nowMs = 999;
    expect(await store.use('j', 1000)).toBe(false);
  });
});
