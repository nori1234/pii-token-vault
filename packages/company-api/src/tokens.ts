// 企業のトークン（RP-70、RP-73、CAP-39、ADR 0022）。
//
// トークンの発行（POST /token）：
// - grant_type は client_credentials だけ。クライアント認証は private_key_jwt（RFC 7523）だけ。
// - client assertion は ES256 で、登録した jwks の鍵で検証する。iss と sub は client_id、aud はトークンの
//   エンドポイントの URL、exp・iat・jti は必須、iat から5分まで。jti は期限まで覚えて、2回目を断る。
// - 失敗は、理由によらず同じ invalid_client（どの client_id が登録されているかを区別させない）。
// - 緊急停止したテナントのクライアントには出さない。
//
// アクセストークン（テナントの JWT）：
// - 鍵サービスの tenant_jwt の鍵で ES256 の署名をした JWT（typ は at+jwt。RFC 9068 の形）。有効期間は5分。
// - クレーム：iss と aud は company-api、sub と client_id はクライアント、tenant_id はテナント、scope は company_api、
//   jti は乱数。リフレッシュトークンは出さない。
// - 検証のたびに、テナントとクライアントが登録簿にあり、緊急停止していないことを確かめる。緊急停止の後に
//   発行済みのトークンが効かなくなるのは、設定を直して配備し直した時点（ADR 0022）。

import { randomBytesOf, toBase64Url } from '@pii-token-vault/warifu-core';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import type { ApiClient, CompanyApiConfig, CompanyTenant } from './config.ts';
import { PublicKeyCache, signJwt, verifyJwt } from './jwt.ts';

export const ACCESS_TOKEN_TTL_SECONDS = 300;
export const ASSERTION_MAX_AGE_SECONDS = 300;
export const TOKEN_SCOPE = 'company_api';
const CLOCK_TOLERANCE_SECONDS = 30;
const GRANT_TYPE = 'client_credentials';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const MAX_REPLAY_ENTRIES = 100_000;
const JTI_PATTERN = /^[\x21-\x7e]{16,128}$/;
const TOKEN_PARAMS: ReadonlySet<string> = new Set([
  'grant_type',
  'client_assertion_type',
  'client_assertion',
  'client_id',
  'scope',
]);

export type TokenError =
  | 'invalid_request'
  | 'invalid_client'
  | 'unsupported_grant_type'
  | 'invalid_scope';

export interface IssuedToken {
  readonly accessToken: string;
  readonly tenant: CompanyTenant;
  readonly clientId: string;
}

export interface Caller {
  readonly tenant: CompanyTenant;
  readonly client: ApiClient;
}

export class TokenService {
  readonly #config: CompanyApiConfig;
  readonly #keys: CompanyApiKeyClient;
  readonly #now: () => Date;
  readonly #cache: PublicKeyCache;
  readonly #seen = new Map<string, number>();
  readonly tokenEndpoint: string;

  constructor(deps: {
    readonly config: CompanyApiConfig;
    readonly keys: CompanyApiKeyClient;
    readonly now: () => Date;
  }) {
    this.#config = deps.config;
    this.#keys = deps.keys;
    this.#now = deps.now;
    this.#cache = new PublicKeyCache(deps.keys, () => deps.now().getTime());
    this.tokenEndpoint = `${deps.config.issuer}/token`;
  }

  /** フォームの本文から、client assertion を確かめてトークンを出す。 */
  async issue(
    params: URLSearchParams,
  ): Promise<
    | { readonly ok: true; readonly token: IssuedToken }
    | { readonly ok: false; readonly error: TokenError }
  > {
    for (const key of params.keys()) {
      if (!TOKEN_PARAMS.has(key) || params.getAll(key).length !== 1) {
        return { ok: false, error: 'invalid_request' };
      }
    }
    if (params.get('grant_type') !== GRANT_TYPE)
      return { ok: false, error: 'unsupported_grant_type' };
    const scope = params.get('scope');
    if (scope !== null && scope !== TOKEN_SCOPE) return { ok: false, error: 'invalid_scope' };
    const assertion = params.get('client_assertion');
    if (params.get('client_assertion_type') !== ASSERTION_TYPE || assertion === null) {
      return { ok: false, error: 'invalid_client' };
    }
    const verified = await this.#verifyAssertion(assertion, params.get('client_id'));
    if (verified === undefined) return { ok: false, error: 'invalid_client' };
    const { tenant, client } = verified;
    const iat = Math.floor(this.#now().getTime() / 1000);
    const accessToken = await signJwt(this.#keys, this.#cache, 'tenant_jwt', 'at+jwt', {
      iss: this.#config.issuer,
      aud: this.#config.issuer,
      sub: client.clientId,
      client_id: client.clientId,
      tenant_id: tenant.tenantId,
      scope: TOKEN_SCOPE,
      iat,
      exp: iat + ACCESS_TOKEN_TTL_SECONDS,
      jti: toBase64Url(randomBytesOf(16)),
    });
    return { ok: true, token: { accessToken, tenant, clientId: client.clientId } };
  }

  async #verifyAssertion(
    assertion: string,
    clientIdParam: string | null,
  ): Promise<{ tenant: CompanyTenant; client: ApiClient } | undefined> {
    let claimed: unknown;
    try {
      claimed = decodeJwt(assertion).iss;
    } catch {
      return undefined;
    }
    if (typeof claimed !== 'string') return undefined;
    if (clientIdParam !== null && clientIdParam !== claimed) return undefined;
    const entry = this.#config.clients.get(claimed);
    if (entry === undefined || entry.tenant.suspended) return undefined;
    const payload = await verifyJwt(assertion, entry.client.jwks.keys, {
      issuer: entry.client.clientId,
      subject: entry.client.clientId,
      audience: this.tokenEndpoint,
      maxTokenAge: ASSERTION_MAX_AGE_SECONDS,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      currentDate: this.#now(),
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti'],
    });
    if (payload === undefined) return undefined;
    const nowSeconds = Math.floor(this.#now().getTime() / 1000);
    const { jti, exp } = payload;
    if (
      typeof jti !== 'string' ||
      !JTI_PATTERN.test(jti) ||
      typeof exp !== 'number' ||
      exp > nowSeconds + ASSERTION_MAX_AGE_SECONDS + CLOCK_TOLERANCE_SECONDS
    ) {
      return undefined;
    }
    if (!this.#remember(`${entry.client.clientId}\u0000${jti}`, exp, nowSeconds)) return undefined;
    return entry;
  }

  /** jti を期限まで覚える。すでにあれば false。 */
  #remember(key: string, exp: number, nowSeconds: number): boolean {
    const until = this.#seen.get(key);
    if (until !== undefined && until >= nowSeconds) return false;
    if (this.#seen.size >= MAX_REPLAY_ENTRIES) {
      for (const [k, v] of this.#seen) if (v < nowSeconds) this.#seen.delete(k);
      // 覚えきれないときは、断る側に倒す（古いものを捨てると、再送を通してしまうため）。
      if (this.#seen.size >= MAX_REPLAY_ENTRIES) return false;
    }
    this.#seen.set(key, exp + CLOCK_TOLERANCE_SECONDS);
    return true;
  }

  /** Authorization のヘッダーから呼び出し元を確かめる。だめなら undefined（理由を区別しない）。 */
  async authenticate(header: string | undefined): Promise<Caller | undefined> {
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) return undefined;
    const token = header.slice('Bearer '.length);
    const options = {
      issuer: this.#config.issuer,
      audience: this.#config.issuer,
      typ: 'at+jwt',
      currentDate: this.#now(),
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ['iss', 'aud', 'sub', 'exp', 'iat', 'jti', 'client_id', 'tenant_id', 'scope'],
    };
    let keys = await this.#cache.get('tenant_jwt');
    // 鍵サービスの鍵が入れ替わった直後に備えて、知らない kid のときだけ公開鍵を引き直す（間隔に下限がある）。
    let kid: unknown;
    try {
      kid = decodeProtectedHeader(token).kid;
    } catch {
      return undefined;
    }
    if (typeof kid !== 'string') return undefined;
    if (!keys.some((key) => key.kid === kid)) keys = await this.#cache.get('tenant_jwt', true);
    const payload = await verifyJwt(token, keys, options);
    if (payload === undefined || payload.scope !== TOKEN_SCOPE) return undefined;
    const entry =
      typeof payload.client_id === 'string'
        ? this.#config.clients.get(payload.client_id)
        : undefined;
    if (
      entry === undefined ||
      entry.tenant.tenantId !== payload.tenant_id ||
      payload.sub !== entry.client.clientId ||
      entry.tenant.suspended
    ) {
      return undefined;
    }
    return entry;
  }
}
