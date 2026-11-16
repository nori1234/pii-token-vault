// 割符の OIDC のクライアント（企業のサーバーで動かす。plan 3-1・3-3、spec 02、ADR 0029 の O-108）。
//
// - ログイン：認可コードと PKCE（S256）。ID トークンは ES256 で、iss・aud・nonce・acr を確かめる。根拠にしてよいのは
//   iss・sub・acr・auth_time だけ（不変条件1(a)。別名は連絡用で、識別子ではない。RP-01〜05）。
// - 窓口の操作別承認と初回紐付け：PAR（authorization_details を1件）→ 認可コード → トークンの応答の承認の JWT。
//   承認の JWT は、用途（purpose）・操作・申請の ID・sub・期限（5分）を確かめ、jti は一度しか使わせない（RP-10・12・21）。
// - 通信は、企業が渡す関数（transport.ts）で、設定した idp のオリジンの下にだけ送る。

import { importJWK, type JWK, type JWTPayload, jwtVerify, SignJWT } from 'jose';
import { RpKitError } from './errors.ts';
import { type JtiStore, memoryJtiStore } from './jti.ts';
import { jwksFetcher } from './keys.ts';
import { newPkce, randomToken } from './pkce.ts';
import { failureOf, guardedSend, jsonOf, parseOrigin, type Send } from './transport.ts';

export const ACR_PASSKEY = 'urn:warifu:acr:passkey';
export const OP_APPROVAL_TYP = 'warifu-op-approval+jwt';
export const INITIAL_LINK_APPROVAL_TYP = 'warifu-initial-link-approval+jwt';
export const OPERATION_APPROVAL_TYP = 'warifu-operation-approval+jwt';
/** 承認の JWT の有効期間の上限（秒）。 */
export const APPROVAL_MAX_SECONDS = 300;
/** 時計のずれの許容（秒）。 */
const CLOCK_TOLERANCE = 30;
/** 使い済みの jti を、JWT を受理しうる時刻（exp と時計のずれの許容）より長く覚えておくための余裕（秒）。 */
const JTI_KEEP_MARGIN = 60;
const SUB_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type DeskAction = 'desk.case.status.read' | 'desk.order.status.read' | 'desk.case.create';
export type InitialLinkAction = 'initial_link.approve' | 'initial_link.finalize';
/** 高リスクの操作（ADR 0030）。P0 は出金先の変更だけ。 */
export type OperationAction = 'payout_destination.change';

/** 出金先の変更で、利用者に見せる内容（数字だけ）。口座番号の全桁と名義は、企業のサーバーに置き、割符に渡さない。 */
export interface PayoutDestinationContent {
  readonly bankCode: string;
  readonly branchCode: string;
  readonly accountLast4: string;
}

export interface OperationApproval {
  readonly action: OperationAction;
  readonly requestId: string;
  /** ミリ秒。 */
  readonly expiresAt: number;
}

export interface WarifuClientConfig {
  /** idp のオリジン（例：https://idp.warifu.example）。issuer は `${idpOrigin}/oidc`。 */
  readonly idpOrigin: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** private_key_jwt の秘密鍵（P-256 の JWK）。 */
  readonly privateKey: JWK;
  readonly kid: string;
  readonly send: Send;
  readonly now?: () => Date;
  /** 承認の jti の置き場所。既定はプロセスの中だけ（複数のサーバーで動かすなら、共有のものを渡す）。 */
  readonly jtiStore?: JtiStore;
}

/** 認可の要求を始めたときに、企業のサーバーのセッションに置いておくもの（ブラウザに渡さない）。 */
export interface PendingAuthorization {
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  /** 秒。step-up のときだけ。 */
  readonly maxAge: number | null;
  /** 要求を始めた時刻（秒）。 */
  readonly startedAt: number;
  /** PAR で送った申請（なければ null）。 */
  readonly detail: Readonly<Record<string, unknown>> | null;
}

/** ID トークンから取り出すもの。根拠にしてよいのは iss・sub・acr・authTime だけ。 */
export interface WarifuLogin {
  readonly iss: string;
  readonly sub: string;
  readonly acr: string;
  /** 秒。 */
  readonly authTime: number;
  /** 回復した日（秒。日の始まり）。回復の後の制限を強める方向にだけ使う（不変条件1(e)）。 */
  readonly recoveredAt: number | null;
  /** 別名（連絡用。識別、統合、紐付け、再設定の宛先には使わない。RP-05）。 */
  readonly contactAlias: string | null;
  /** トークンの応答の authorization_details（PAR のときだけ。検証は verifyDeskApproval などで行う）。 */
  readonly authorizationDetails: readonly Record<string, unknown>[] | null;
}

export interface DeskApproval {
  readonly action: DeskAction;
  readonly requestId: string;
  /** 一般問い合わせの作成のときだけ。 */
  readonly changeId: string | null;
  /** ミリ秒。 */
  readonly expiresAt: number;
}

export type InitialLinkOutcome =
  | { readonly stage: 'approve'; readonly state: 'pending_notice' }
  | { readonly stage: 'finalize'; readonly initialLinkId: string; readonly expiresAt: number };

export interface WarifuClient {
  readonly issuer: string;
  /** ふだんのログイン（maxAge を渡すと step-up。0 なら新しい認証を求める）。 */
  authorize(options?: {
    readonly maxAge?: number;
    readonly scope?: 'openid' | 'openid email';
  }): Promise<{
    readonly url: string;
    readonly pending: PendingAuthorization;
  }>;
  /** 窓口の操作別承認の申請（PAR）。 */
  pushDesk(input: {
    readonly action: DeskAction;
    readonly requestId: string;
    readonly sub: string;
    readonly choices?: { readonly category: string; readonly language: string };
  }): Promise<{ readonly url: string; readonly pending: PendingAuthorization }>;
  /** 初回紐付けの申請（PAR）。 */
  pushInitialLink(input: {
    readonly action: InitialLinkAction;
    readonly initialLinkId: string;
    readonly sub: string;
  }): Promise<{ readonly url: string; readonly pending: PendingAuthorization }>;
  /** 企業の redirect_uri に戻ってきた URL で、認可コードをトークンに換え、ID トークンを確かめる。 */
  finish(callbackUrl: string, pending: PendingAuthorization): Promise<WarifuLogin>;
  /** 窓口の操作別承認の JWT を確かめる（用途 desk。高リスクの操作には使えない。RP-21）。 */
  verifyDeskApproval(login: WarifuLogin, pending: PendingAuthorization): Promise<DeskApproval>;
  /** 初回紐付けの結果を読む。最初の承認は状態だけ、最終の承認は紐付けの承認の JWT を確かめる。 */
  readInitialLink(login: WarifuLogin, pending: PendingAuthorization): Promise<InitialLinkOutcome>;
  /**
   * 高リスクの操作の申請（PAR。ADR 0030）。企業は、申請ID を作るときに変更の内容の全体を申請ID に結び付けて固定し、
   * 書き換えない（RP-09）。ここに渡すのは、申請ID と、利用者に見せる内容だけ。
   */
  pushOperation(input: {
    readonly action: OperationAction;
    readonly requestId: string;
    readonly sub: string;
    readonly content: PayoutDestinationContent;
  }): Promise<{ readonly url: string; readonly pending: PendingAuthorization }>;
  /**
   * 高リスクの操作の承認の JWT を確かめる。expected には、企業が申請ID で自社に固定した内容を渡す。割符が検出できるのは、
   * 申請ID と表示の項目の不一致だけ。表示が同じ別の口座への差し替えは、企業が RP-09 で防ぐ。
   * 変更の実行と、申請ID を使い済みにする更新は、企業が1つのトランザクションで確定させる。
   */
  verifyOperationApproval(
    login: WarifuLogin,
    pending: PendingAuthorization,
    expected: { readonly requestId: string; readonly content: PayoutDestinationContent },
  ): Promise<OperationApproval>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function createWarifuClient(config: WarifuClientConfig): Promise<WarifuClient> {
  const origin = parseOrigin(config.idpOrigin);
  const issuer = `${origin}/oidc`;
  if (typeof config.clientId !== 'string' || config.clientId.length === 0) {
    throw new RpKitError('invalid_config');
  }
  let redirect: URL;
  try {
    redirect = new URL(config.redirectUri);
  } catch {
    throw new RpKitError('invalid_config');
  }
  if (redirect.hash !== '') throw new RpKitError('invalid_config');
  const key = await importJWK(config.privateKey, 'ES256');
  const nowMs = () => (config.now?.() ?? new Date()).getTime();
  const jtis = config.jtiStore ?? memoryJtiStore(nowMs);
  const send = guardedSend(config.send, [origin]);
  const idTokenKeys = jwksFetcher(send, `${issuer}/jwks`, nowMs);
  const opApprovalKeys = jwksFetcher(send, `${origin}/op-approval/jwks`, nowMs);
  const initialLinkKeys = jwksFetcher(send, `${origin}/initial-link/jwks`, nowMs);
  const operationKeys = jwksFetcher(send, `${origin}/operation-approval/jwks`, nowMs);

  async function clientAssertion(): Promise<string> {
    const iat = Math.floor(nowMs() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: config.kid })
      .setIssuer(config.clientId)
      .setSubject(config.clientId)
      .setAudience(issuer)
      .setIssuedAt(iat)
      .setExpirationTime(iat + 60)
      .setJti(randomToken(16))
      .sign(key);
  }

  function pendingOf(maxAge: number | null, detail: Record<string, unknown> | null) {
    const pkce = newPkce();
    const pending: PendingAuthorization = {
      state: randomToken(16),
      nonce: randomToken(16),
      verifier: pkce.verifier,
      maxAge,
      startedAt: Math.floor(nowMs() / 1000),
      detail,
    };
    const params: Record<string, string> = {
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
      ...(maxAge === null ? {} : { max_age: String(maxAge) }),
    };
    return { pending, params };
  }

  async function verifyKeyed(
    jwt: string,
    keys: (refresh: boolean) => Promise<Parameters<typeof jwtVerify>[1]>,
    options: Parameters<typeof jwtVerify>[2],
  ): Promise<JWTPayload> {
    for (const refresh of [false, true]) {
      try {
        const { payload } = await jwtVerify(jwt, (await keys(refresh)) as never, {
          ...options,
          algorithms: ['ES256'],
          clockTolerance: CLOCK_TOLERANCE,
          currentDate: new Date(nowMs()),
        });
        return payload;
      } catch (error) {
        if (error instanceof RpKitError) throw error;
        const code = (error as { code?: unknown }).code;
        if (!refresh && code === 'ERR_JWKS_NO_MATCHING_KEY') continue;
        throw new RpKitError('verification_failed');
      }
    }
    throw new RpKitError('verification_failed');
  }

  async function push(detail: Record<string, unknown>) {
    const { pending, params } = pendingOf(0, detail);
    const response = await send({
      method: 'POST',
      url: `${issuer}/request`,
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        ...params,
        scope: 'openid',
        authorization_details: JSON.stringify([detail]),
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await clientAssertion(),
      }).toString(),
    });
    if (response.status !== 201 && response.status !== 200) throw failureOf(response);
    const body = jsonOf(response);
    if (
      typeof body.request_uri !== 'string' ||
      !body.request_uri.startsWith('urn:ietf:params:oauth:request_uri:')
    ) {
      throw new RpKitError('invalid_response');
    }
    const url = `${issuer}/auth?${new URLSearchParams({ client_id: config.clientId, request_uri: body.request_uri })}`;
    return { url, pending };
  }

  function grantedDetail(
    login: WarifuLogin,
    pending: PendingAuthorization,
  ): Record<string, unknown> {
    const [granted, ...rest] = login.authorizationDetails ?? [];
    if (granted === undefined || rest.length > 0 || pending.detail === null) {
      throw new RpKitError('verification_failed');
    }
    // 申請と同じ型・操作・ID・sub か（approval と state を除いて比べる）。
    const { approval: _approval, state: _state, ...withoutResult } = granted;
    if (JSON.stringify(withoutResult) !== JSON.stringify(pending.detail)) {
      throw new RpKitError('verification_failed');
    }
    if (pending.detail.subject !== login.sub) throw new RpKitError('verification_failed');
    return granted;
  }

  async function verifyApproval(
    jwt: unknown,
    typ: string,
    keys: typeof opApprovalKeys,
    login: WarifuLogin,
  ): Promise<JWTPayload & { exp: number; jti: string }> {
    if (typeof jwt !== 'string') throw new RpKitError('verification_failed');
    const payload = await verifyKeyed(jwt, keys, {
      issuer,
      audience: config.clientId,
      typ,
      subject: login.sub,
      requiredClaims: ['iat', 'exp', 'jti', 'purpose'],
    });
    const { iat, exp, jti } = payload;
    if (
      typeof iat !== 'number' ||
      typeof exp !== 'number' ||
      typeof jti !== 'string' ||
      exp - iat > APPROVAL_MAX_SECONDS ||
      payload.acr !== ACR_PASSKEY
    ) {
      throw new RpKitError('verification_failed');
    }
    // 検証は exp の後も CLOCK_TOLERANCE 秒は通る。使い済みの記録は、それより長く持つ（exp で忘れると、exp の直後に
    // 同じ承認がもう一度通ってしまう）。
    const keepUntil = (exp + CLOCK_TOLERANCE + JTI_KEEP_MARGIN) * 1000;
    if (!(await jtis.use(jti, keepUntil))) throw new RpKitError('replayed');
    return payload as JWTPayload & { exp: number; jti: string };
  }

  return {
    issuer,

    async authorize(options = {}) {
      const maxAge = options.maxAge ?? null;
      if (maxAge !== null && (!Number.isSafeInteger(maxAge) || maxAge < 0)) {
        throw new RpKitError('invalid_config');
      }
      const { pending, params } = pendingOf(maxAge, null);
      const url = `${issuer}/auth?${new URLSearchParams({ ...params, scope: options.scope ?? 'openid' })}`;
      return { url, pending };
    },

    async pushDesk(input) {
      if (!SUB_PATTERN.test(input.sub)) throw new RpKitError('invalid_config');
      return push({
        type: 'warifu_desk',
        actions: [input.action],
        identifier: input.requestId,
        subject: input.sub,
        ...(input.choices === undefined
          ? {}
          : { choices: { category: input.choices.category, language: input.choices.language } }),
      });
    },

    async pushInitialLink(input) {
      if (!SUB_PATTERN.test(input.sub)) throw new RpKitError('invalid_config');
      return push({
        type: 'warifu_initial_link',
        actions: [input.action],
        identifier: input.initialLinkId,
        subject: input.sub,
      });
    },

    async finish(callbackUrl, pending) {
      let callback: URL;
      try {
        callback = new URL(callbackUrl);
      } catch {
        throw new RpKitError('verification_failed');
      }
      if (`${callback.origin}${callback.pathname}` !== `${redirect.origin}${redirect.pathname}`) {
        throw new RpKitError('verification_failed');
      }
      if (callback.searchParams.get('state') !== pending.state) {
        throw new RpKitError('verification_failed');
      }
      const error = callback.searchParams.get('error');
      if (error !== null) throw new RpKitError('rejected', error);
      const code = callback.searchParams.get('code');
      if (code === null) throw new RpKitError('verification_failed');
      const response = await send({
        method: 'POST',
        url: `${issuer}/token`,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: config.redirectUri,
          code_verifier: pending.verifier,
          client_id: config.clientId,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await clientAssertion(),
        }).toString(),
      });
      if (response.status !== 200) throw failureOf(response);
      const body = jsonOf(response);
      if (typeof body.id_token !== 'string') throw new RpKitError('invalid_response');
      const claims = await verifyKeyed(body.id_token, idTokenKeys, {
        issuer,
        audience: config.clientId,
        requiredClaims: ['sub', 'iat', 'exp', 'auth_time'],
      });
      const { sub, acr, auth_time: authTime, nonce } = claims;
      if (
        nonce !== pending.nonce ||
        typeof sub !== 'string' ||
        !SUB_PATTERN.test(sub) ||
        acr !== ACR_PASSKEY ||
        typeof authTime !== 'number'
      ) {
        throw new RpKitError('verification_failed');
      }
      // step-up：要求を始めた時刻から見て max_age より古い認証は断る（max_age=0 なら、要求を始めた後の認証だけ）。
      if (
        pending.maxAge !== null &&
        authTime < pending.startedAt - pending.maxAge - CLOCK_TOLERANCE
      ) {
        throw new RpKitError('verification_failed');
      }
      const recovered = claims.recovered_at;
      const alias = claims.contact_alias ?? claims.email;
      const details = body.authorization_details;
      if (details !== undefined && (!Array.isArray(details) || !details.every(isRecord))) {
        throw new RpKitError('invalid_response');
      }
      if ((pending.detail === null) !== (details === undefined)) {
        throw new RpKitError('verification_failed');
      }
      return {
        iss: issuer,
        sub,
        acr,
        authTime,
        recoveredAt: typeof recovered === 'number' ? recovered : null,
        contactAlias: typeof alias === 'string' ? alias : null,
        authorizationDetails: details === undefined ? null : (details as Record<string, unknown>[]),
      };
    },

    async verifyDeskApproval(login, pending) {
      const granted = grantedDetail(login, pending);
      if (granted.type !== 'warifu_desk' || granted.state !== undefined) {
        throw new RpKitError('verification_failed');
      }
      const payload = await verifyApproval(
        granted.approval,
        OP_APPROVAL_TYP,
        opApprovalKeys,
        login,
      );
      const [action] = granted.actions as string[];
      if (
        payload.purpose !== 'desk' ||
        payload.action !== action ||
        payload.request_id !== granted.identifier
      ) {
        throw new RpKitError('verification_failed');
      }
      const changeId = payload.change_id;
      if ((action === 'desk.case.create') !== (typeof changeId === 'string')) {
        throw new RpKitError('verification_failed');
      }
      return {
        action: action as DeskAction,
        requestId: String(granted.identifier),
        changeId: typeof changeId === 'string' ? changeId : null,
        expiresAt: payload.exp * 1000,
      };
    },

    async readInitialLink(login, pending) {
      const granted = grantedDetail(login, pending);
      if (granted.type !== 'warifu_initial_link') throw new RpKitError('verification_failed');
      const [action] = granted.actions as string[];
      if (action === 'initial_link.approve') {
        if (granted.state !== 'pending_notice' || granted.approval !== undefined) {
          throw new RpKitError('verification_failed');
        }
        return { stage: 'approve', state: 'pending_notice' };
      }
      if (action !== 'initial_link.finalize' || granted.state !== undefined) {
        throw new RpKitError('verification_failed');
      }
      const payload = await verifyApproval(
        granted.approval,
        INITIAL_LINK_APPROVAL_TYP,
        initialLinkKeys,
        login,
      );
      if (payload.purpose !== 'initial_link' || payload.initial_link_id !== granted.identifier) {
        throw new RpKitError('verification_failed');
      }
      return {
        stage: 'finalize',
        initialLinkId: String(granted.identifier),
        expiresAt: payload.exp * 1000,
      };
    },

    async pushOperation(input) {
      const { bankCode, branchCode, accountLast4 } = input.content;
      if (
        !SUB_PATTERN.test(input.sub) ||
        !/^[A-Za-z0-9_-]{22,128}$/.test(input.requestId) ||
        !/^\d{4}$/.test(bankCode) ||
        !/^\d{3}$/.test(branchCode) ||
        !/^\d{4}$/.test(accountLast4)
      ) {
        throw new RpKitError('invalid_config');
      }
      return push({
        type: 'warifu_operation',
        actions: [input.action],
        identifier: input.requestId,
        subject: input.sub,
        content: { bank_code: bankCode, branch_code: branchCode, account_last4: accountLast4 },
      });
    },

    async verifyOperationApproval(login, pending, expected) {
      const granted = grantedDetail(login, pending);
      if (granted.type !== 'warifu_operation' || granted.state !== undefined) {
        throw new RpKitError('verification_failed');
      }
      const content = {
        bank_code: expected.content.bankCode,
        branch_code: expected.content.branchCode,
        account_last4: expected.content.accountLast4,
      };
      // 申請と、企業が固定した内容が同じか（PAR で送ったものと、照らす相手を取り違えていないか）。
      if (
        granted.identifier !== expected.requestId ||
        JSON.stringify(granted.content) !== JSON.stringify(content)
      ) {
        throw new RpKitError('verification_failed');
      }
      const payload = await verifyApproval(
        granted.approval,
        OPERATION_APPROVAL_TYP,
        operationKeys,
        login,
      );
      const [action] = granted.actions as string[];
      if (
        payload.purpose !== 'operation' ||
        payload.action !== action ||
        payload.request_id !== expected.requestId ||
        JSON.stringify(payload.content) !== JSON.stringify(content)
      ) {
        throw new RpKitError('verification_failed');
      }
      return {
        action: action as OperationAction,
        requestId: expected.requestId,
        expiresAt: payload.exp * 1000,
      };
    },
  };
}
