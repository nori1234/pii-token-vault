// 適合テストキットの模擬 OP（plan 3-3、spec 02 の 15-1、ADR 0029）。企業の手元だけで動かす（公開の試験用サーバーは
// 作らない。plan 10章の公開の順番）。ネットワークは使わず、SDK に渡す通信の関数（Send）として答える。
//
// - 割符の idp と同じ形（/oidc/auth、/oidc/token、/oidc/jwks）で答え、ES256 の ID トークンを出す。
// - 利用者は、固定の2人（alpha と beta）。sub は違い、email クレーム（別名）は同じにする（「同じ email で sub の違う2人」）。
//   どちらの値も固定で、入力によって変えない（plan 3-3。不変条件1 は、テストの補助にも適用する）。
// - 鍵はキットを動かすたびに作る。割符の本物の鍵、トークン、利用者の値は持たない。

import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { RpKitError } from '../errors.ts';
import { randomToken, s256 } from '../pkce.ts';
import type { HttpRequest, HttpResponse, Send } from '../transport.ts';

/** 模擬 OP のオリジン（どこにもつながない。SDK の宛先の検査を通すための名前）。 */
export const MOCK_OP_ORIGIN = 'https://mock-op.rp-kit.invalid';
export const MOCK_PERSONAS = Object.freeze(['alpha', 'beta'] as const);
export type MockPersona = (typeof MOCK_PERSONAS)[number];

/** 固定の値。alpha と beta は、sub が違い、別名（email クレーム）が同じ。 */
const PERSONA_SUBS: Readonly<Record<MockPersona, string>> = Object.freeze({
  alpha: 'alphaAlphaAlphaAlphaAlphaAlphaAlphaAlpha000',
  beta: 'betaBetaBetaBetaBetaBetaBetaBetaBetaBeta000',
});
const SHARED_ALIAS = 'same-alias@mock-op.rp-kit.invalid';

export interface MockOp {
  readonly origin: string;
  /** SDK の createWarifuClient に渡す通信の関数。 */
  readonly send: Send;
  /** SDK が作った認可の URL に、固定の利用者でログインしたことにして、企業の redirect_uri に戻る URL を返す。 */
  complete(authorizationUrl: string, persona: MockPersona): string;
  /** 模擬 OP の公開鍵（企業が SDK の設定に静的に渡すとき用）。 */
  readonly jwks: { readonly keys: readonly JWK[] };
}

interface CodeEntry {
  readonly persona: MockPersona;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly nonce: string;
  readonly challenge: string;
}

function json(status: number, body: unknown): HttpResponse {
  return { status, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
}

export async function createMockOp(options: {
  readonly clientId: string;
  readonly redirectUri: string;
}): Promise<MockOp> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const kid = randomToken(8);
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' };
  const issuer = `${MOCK_OP_ORIGIN}/oidc`;
  const codes = new Map<string, CodeEntry>();

  async function token(form: URLSearchParams): Promise<HttpResponse> {
    const code = form.get('code') ?? '';
    const entry = codes.get(code);
    codes.delete(code);
    if (
      entry === undefined ||
      form.get('grant_type') !== 'authorization_code' ||
      form.get('client_id') !== entry.clientId ||
      form.get('redirect_uri') !== entry.redirectUri ||
      s256(form.get('code_verifier') ?? '') !== entry.challenge ||
      form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    ) {
      return json(400, { error: 'invalid_grant' });
    }
    const iat = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
      nonce: entry.nonce,
      acr: 'urn:warifu:acr:passkey',
      auth_time: iat,
      email: SHARED_ALIAS,
      email_verified: false,
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .setIssuer(issuer)
      .setAudience(entry.clientId)
      .setSubject(PERSONA_SUBS[entry.persona])
      .setIssuedAt(iat)
      .setExpirationTime(iat + 300)
      .sign(privateKey);
    return json(200, {
      access_token: randomToken(16),
      token_type: 'Bearer',
      expires_in: 60,
      id_token: idToken,
    });
  }

  const send: Send = async (request: HttpRequest) => {
    const url = new URL(request.url);
    if (url.origin !== MOCK_OP_ORIGIN) throw new RpKitError('forbidden_destination');
    if (request.method === 'GET' && url.pathname === '/oidc/jwks')
      return json(200, { keys: [publicJwk] });
    if (request.method === 'POST' && url.pathname === '/oidc/token') {
      return token(new URLSearchParams(request.body ?? ''));
    }
    return json(404, { error: 'not_found' });
  };

  return {
    origin: MOCK_OP_ORIGIN,
    send,
    jwks: { keys: [publicJwk] },
    complete(authorizationUrl, persona) {
      const url = new URL(authorizationUrl);
      const params = url.searchParams;
      if (
        url.origin !== MOCK_OP_ORIGIN ||
        url.pathname !== '/oidc/auth' ||
        params.get('client_id') !== options.clientId ||
        params.get('redirect_uri') !== options.redirectUri ||
        params.get('code_challenge_method') !== 'S256' ||
        params.get('response_type') !== 'code'
      ) {
        throw new RpKitError('verification_failed');
      }
      const code = randomToken(16);
      codes.set(code, {
        persona,
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        nonce: params.get('nonce') ?? '',
        challenge: params.get('code_challenge') ?? '',
      });
      const back = new URL(options.redirectUri);
      back.searchParams.set('code', code);
      back.searchParams.set('state', params.get('state') ?? '');
      return back.href;
    },
  };
}
