// company-api（割符の企業向け API）のクライアント（ADR 0022、ADR 0028、ADR 0029 の O-108）。
//
// - テナントの JWT：POST /token に private_key_jwt の client assertion を出して受け取り、scope ごとに期限の少し前まで覚える。
//   企業向けの API には、この JWT を Bearer で送る（client assertion を直接渡さない）。
// - 初回紐付け：仮申請、証跡、企業の側の取消、結果の報告。証跡（移行証跡の JWS）を作る関数も持つ。
// - SET：company-api の鍵（/jwks）で、ES256 の署名、iss、aud（自分のテナント）、jti、iat を確かめる（RP-50）。
// 申請 ID、会員参照、移行専用 ID、証跡、トークンは、企業のサーバーの中だけに置き、ログや URL に出さない（spec 02、不変条件4）。

import { importJWK, type JWK, jwtVerify, SignJWT } from 'jose';
import { RpKitError } from './errors.ts';
import { jwksFetcher } from './keys.ts';
import { randomToken } from './pkce.ts';
import {
  failureOf,
  guardedSend,
  type HttpResponse,
  jsonOf,
  parseOrigin,
  type Send,
} from './transport.ts';

export const INITIAL_LINK_PROOF_TYP = 'warifu-initial-link-proof+jwt';
export const SET_TYP = 'secevent+jwt';
/** SET の iat の古さの上限（秒）と、先の時刻の許容（秒）。spec 02 の7章、ADR 0026 の O-67。 */
export const SET_MAX_AGE_SECONDS = 300;
export const SET_FUTURE_TOLERANCE_SECONDS = 30;
const CLOCK_TOLERANCE = 30;
const ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const REF_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export type CompanyApiScope = 'company_api' | 'desk' | 'initial_link';

export interface CompanyApiConfig {
  /** company-api のオリジン（issuer と同じ）。 */
  readonly origin: string;
  /** 企業向け API のクライアント ID。 */
  readonly clientId: string;
  /** 自分のテナント ID（SET の aud を確かめる）。 */
  readonly tenantId: string;
  readonly privateKey: JWK;
  readonly kid: string;
  readonly send: Send;
  readonly now?: () => Date;
}

export interface InitialLinkProofClaims {
  readonly initialLinkId: string;
  readonly memberRef: string;
  readonly stage: 'initial' | 'final' | 'cancel';
  readonly credentialKind: 'passkey' | 'fido2';
  readonly profileVersion: number;
  readonly authEpoch: number;
}

export interface VerifiedSet {
  readonly jti: string;
  /** 秒。 */
  readonly iat: number;
  /** この企業の sub（回復の SET の sub_id。ほかの SET にはない）。 */
  readonly subId: string | null;
  readonly events: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}

export interface CompanyApiClient {
  /** テナントの JWT（期限の少し前まで覚える）。 */
  accessToken(scope: CompanyApiScope): Promise<string>;
  /** 企業向けの API を、テナントの JWT で呼ぶ。成功なら本文（204 なら空のオブジェクト）、それ以外は RpKitError。 */
  call(
    scope: CompanyApiScope,
    path: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  readonly initialLink: {
    prepare(input: { readonly requestId: string; readonly memberRef: string }): Promise<string>;
    /**
     * 申請のいまの状態（割符の正本）を確かめる。同じ申請ID と会員参照の仮申請の再送で読む。正本の行が、終端の後の
     * 保存期間を過ぎて消えていれば、新しい仮申請として作られ、別の移行専用ID が返る（企業は、前の申請を終わったものとして扱う）。
     */
    status(input: {
      readonly requestId: string;
      readonly memberRef: string;
    }): Promise<{ readonly initialLinkId: string; readonly state: string }>;
    /** 旧会員の側の確かめの後の証跡（stage は initial か final）。 */
    submitProof(claims: InitialLinkProofClaims): Promise<void>;
    /** 企業の側の取消（証跡の stage は cancel）。 */
    cancel(claims: Omit<InitialLinkProofClaims, 'stage'>): Promise<string>;
    /**
     * 確定や取消の適用の結果の報告。自社の確定と同じトランザクションで送信待ちに残し、成功する（割符が 204 を返す）
     * まで送り直す。同じ報告の再送も成功する。rejected（4xx）は、送り直しても変わらない（自社の記録と割符の食い違い）。
     */
    report(input: {
      readonly initialLinkId: string;
      readonly result: 'linked' | 'not_linked' | 'cancelled';
    }): Promise<void>;
  };
  /**
   * 受け口に届いた SET（本文の文字列）を確かめる。署名、iss、aud、typ、形式を確かめた後、iat が300秒より古ければ
   * reason が set_too_old、30秒より先なら iat_in_future の RpKitError（verification_failed）にする。
   * 受け口は、失敗を setRefusalOf で応答にする。jti の重複の扱いは、企業が自分の記録で行う。
   */
  verifySet(body: string): Promise<VerifiedSet>;
}

/** SET の受け口の失敗の応答（spec 02 の7章）。 */
export type SetRefusal =
  | {
      readonly status: 400;
      readonly body: {
        readonly err: 'invalid_request';
        readonly warifu_reason?: 'set_too_old' | 'iat_in_future';
      };
    }
  | { readonly status: 503; readonly body: null };

/**
 * SET の受け口が、verifySet の失敗に返す応答（spec 02 の7章）。
 * - SET を確かめて通らなかった（verification_failed）：400 と RFC 8935 の形。割符は、warifu_reason が set_too_old なら
 *   新しい jti と iat で送り直し、それ以外は保留にする。description は付けない（割符は読まない）。
 * - SET を確かめられなかった（割符の公開鍵を取れない、応答の形が違う、そのほかの例外）：503。割符は、時間をおいて
 *   送り直す。400 を返すと、受け口が一時的に割符へつながらなかっただけで、SET が保留になる。
 */
export function setRefusalOf(error: unknown): SetRefusal {
  if (!(error instanceof RpKitError) || error.code !== 'verification_failed') {
    return { status: 503, body: null };
  }
  const reason = error.reason;
  return {
    status: 400,
    body:
      reason === 'set_too_old' || reason === 'iat_in_future'
        ? { err: 'invalid_request', warifu_reason: reason }
        : { err: 'invalid_request' },
  };
}

export async function createCompanyApiClient(config: CompanyApiConfig): Promise<CompanyApiClient> {
  const origin = parseOrigin(config.origin);
  if (typeof config.clientId !== 'string' || config.clientId.length === 0) {
    throw new RpKitError('invalid_config');
  }
  if (typeof config.tenantId !== 'string' || !/^[0-9a-f-]{36}$/.test(config.tenantId)) {
    throw new RpKitError('invalid_config');
  }
  const key = await importJWK(config.privateKey, 'ES256');
  const nowMs = () => (config.now?.() ?? new Date()).getTime();
  const send = guardedSend(config.send, [origin]);
  const setKeys = jwksFetcher(send, `${origin}/jwks`, nowMs);
  const tokens = new Map<CompanyApiScope, { readonly token: string; readonly until: number }>();

  async function signed(
    typ: string | undefined,
    audience: string,
    claims: Record<string, unknown>,
  ): Promise<string> {
    const iat = Math.floor(nowMs() / 1000);
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid: config.kid, ...(typ === undefined ? {} : { typ }) })
      .setIssuer(config.clientId)
      .setAudience(audience)
      .setIssuedAt(iat)
      .setExpirationTime(iat + 60)
      .setJti(randomToken(16))
      .sign(key);
  }

  async function accessToken(scope: CompanyApiScope): Promise<string> {
    const cached = tokens.get(scope);
    if (cached !== undefined && cached.until > nowMs()) return cached.token;
    const assertion = await signed(undefined, `${origin}/token`, { sub: config.clientId });
    const response = await send({
      method: 'POST',
      url: `${origin}/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      }).toString(),
    });
    if (response.status !== 200) throw failureOf(response);
    const body = jsonOf(response);
    if (
      typeof body.access_token !== 'string' ||
      body.token_type !== 'Bearer' ||
      typeof body.expires_in !== 'number' ||
      body.scope !== scope
    ) {
      throw new RpKitError('invalid_response');
    }
    // 期限の30秒前に取り直す。
    tokens.set(scope, {
      token: body.access_token,
      until: nowMs() + Math.max(0, body.expires_in - CLOCK_TOLERANCE) * 1000,
    });
    return body.access_token;
  }

  function okBody(response: HttpResponse): Record<string, unknown> {
    if (response.status === 204) return {};
    if (response.status === 200 || response.status === 202) return jsonOf(response);
    throw failureOf(response);
  }

  async function call(
    scope: CompanyApiScope,
    path: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (!/^\/v1\/[a-z0-9/-]+$/.test(path)) throw new RpKitError('invalid_config');
    const send1 = async () =>
      send({
        method: 'POST',
        url: `${origin}${path}`,
        headers: {
          authorization: `Bearer ${await accessToken(scope)}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify(body),
      });
    let response = await send1();
    // トークンの期限切れ（401）なら、1回だけ取り直す。
    if (response.status === 401) {
      tokens.delete(scope);
      response = await send1();
    }
    return okBody(response);
  }

  async function proof(claims: InitialLinkProofClaims): Promise<string> {
    if (
      !ID_PATTERN.test(claims.initialLinkId) ||
      !REF_PATTERN.test(claims.memberRef) ||
      !Number.isSafeInteger(claims.profileVersion) ||
      !Number.isSafeInteger(claims.authEpoch)
    ) {
      throw new RpKitError('invalid_config');
    }
    // クレームは許可リストのものだけ（ADR 0028 の O-88）。連絡先、属性、旧会員番号は入れられない形にする。
    return signed(INITIAL_LINK_PROOF_TYP, `${origin}/v1/initial-link`, {
      initial_link_id: claims.initialLinkId,
      member_ref: claims.memberRef,
      stage: claims.stage,
      eligibility: 'eligible',
      credential_kind: claims.credentialKind,
      profile_version: claims.profileVersion,
      auth_epoch: claims.authEpoch,
    });
  }

  async function prepared(input: { readonly requestId: string; readonly memberRef: string }) {
    if (!REQUEST_ID_PATTERN.test(input.requestId) || !REF_PATTERN.test(input.memberRef)) {
      throw new RpKitError('invalid_config');
    }
    const body = await call('initial_link', '/v1/initial-link/prepare', {
      request_id: input.requestId,
      member_ref: input.memberRef,
    });
    if (
      typeof body.initial_link_id !== 'string' ||
      !ID_PATTERN.test(body.initial_link_id) ||
      typeof body.state !== 'string'
    ) {
      throw new RpKitError('invalid_response');
    }
    return { initialLinkId: body.initial_link_id, state: body.state };
  }

  return {
    accessToken,
    call,
    initialLink: {
      async prepare(input) {
        return (await prepared(input)).initialLinkId;
      },
      status: prepared,
      async submitProof(claims) {
        if (claims.stage === 'cancel') throw new RpKitError('invalid_config');
        await call('initial_link', '/v1/initial-link/proofs', { proof: await proof(claims) });
      },
      async cancel(claims) {
        const body = await call('initial_link', '/v1/initial-link/cancel-requests', {
          proof: await proof({ ...claims, stage: 'cancel' }),
        });
        if (typeof body.state !== 'string') throw new RpKitError('invalid_response');
        return body.state;
      },
      async report(input) {
        if (!ID_PATTERN.test(input.initialLinkId)) throw new RpKitError('invalid_config');
        await call('initial_link', '/v1/initial-link/results', {
          initial_link_id: input.initialLinkId,
          result: input.result,
        });
      },
    },

    async verifySet(body) {
      if (typeof body !== 'string' || body.length > 16 * 1024) {
        throw new RpKitError('verification_failed');
      }
      for (const refresh of [false, true]) {
        try {
          const { payload } = await jwtVerify(body, (await setKeys(refresh)) as never, {
            issuer: origin,
            audience: config.tenantId,
            typ: SET_TYP,
            algorithms: ['ES256'],
            requiredClaims: ['jti', 'iat', 'events'],
            clockTolerance: CLOCK_TOLERANCE,
            currentDate: new Date(nowMs()),
          });
          const { jti, iat, events, sub_id: subIdClaim } = payload as Record<string, unknown>;
          const subject =
            typeof subIdClaim === 'object' && subIdClaim !== null
              ? (subIdClaim as { format?: unknown; id?: unknown })
              : undefined;
          if (
            subIdClaim !== undefined &&
            (subject?.format !== 'opaque' || typeof subject.id !== 'string')
          ) {
            throw new RpKitError('verification_failed');
          }
          if (
            typeof jti !== 'string' ||
            typeof iat !== 'number' ||
            events === null ||
            typeof events !== 'object' ||
            Array.isArray(events) ||
            // SET に sub や email を入れない（不変条件5）。入っていれば、割符のものではない。
            'sub' in payload ||
            'email' in payload
          ) {
            throw new RpKitError('verification_failed');
          }
          // 署名、宛先、形式が正しいと分かった後で、鮮度を確かめる（割符は、古くなった SET を新しい jti と iat で送り直す）。
          const nowSeconds = nowMs() / 1000;
          if (iat < nowSeconds - SET_MAX_AGE_SECONDS) {
            throw new RpKitError('verification_failed', 'set_too_old');
          }
          if (iat > nowSeconds + SET_FUTURE_TOLERANCE_SECONDS) {
            throw new RpKitError('verification_failed', 'iat_in_future');
          }
          return {
            jti,
            iat,
            subId: typeof subject?.id === 'string' ? subject.id : null,
            events: events as VerifiedSet['events'],
          };
        } catch (error) {
          if (error instanceof RpKitError) throw error;
          if (!refresh && (error as { code?: unknown }).code === 'ERR_JWKS_NO_MATCHING_KEY')
            continue;
          throw new RpKitError('verification_failed');
        }
      }
      throw new RpKitError('verification_failed');
    },
  };
}
