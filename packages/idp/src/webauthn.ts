// パスキーの登録と検証（不変条件1(b)・9、ADR 0007、ADR 0018）。
//
// @simplewebauthn/server 14.0.3 の手前と後に、次の検査を置く（ADR 0007 の決定1〜6）。
// 1. attestation は受け取らない：選択肢で 'none' を求め、応答の fmt が none で attStmt が空でなければ、ライブラリに渡さない。
// 2. アルゴリズムは ES256、EdDSA、RS256 だけ：[-7, -8, -257] を、選択肢と検証の両方に渡す。登録した公開鍵の
//    種類・曲線・鍵長も確かめる（ES256 は P-256、EdDSA は Ed25519、RS256 は 2048 ビット以上。ADR 0012 の決定6・10）。
// 3. アカウントは資格情報 ID だけで引く：allowCredentials を出さず、userHandle（= 利用者 ID）の範囲の中で資格情報 ID が
//    一致するものだけを使う。見つからなければ、ほかの手がかりでは探さない。
// 4. UV はサーバーで確かめる：requireUserVerification と、結果の userVerified の両方。
// 5. 理由を外に出さない：失敗は種類によらず { ok: false }。ライブラリの例外は、応答にもログにも載せない。
// 6. AAGUID は保存しない。BE と BS のフラグは記録する。
//
// チャレンジ（ceremony）は使い捨てで、目的（作成、ログイン、step-up、追加、承認用のオリジンでのログイン、承認と拒否）と、
// 結び付く相手（インタラクションの uid、PWA や承認用のセッション）を持つ。別の目的や別の相手のチャレンジでは検証しない。
//
// オリジン（expectedOrigin）は目的ごとに固定する。承認用のオリジンでのログインと、承認と拒否は、承認用のオリジン
// だけで通す（DESIGN.md 原則8、ADR 0023）。PWA の画面から同じ RP ID で取ったアサーションでは、承認できない。
// 承認と拒否のチャレンジは乱数ではなく、要求の内容と決定から鍵サービスの MAC で作った値にする（inbox.ts）。

import {
  fromBase64Url,
  parseWarifuUserId,
  randomBytesOf,
  toBase64Url,
  uuidBytes,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { decodeAttestationObject, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import type { CredentialAlgorithm, NewCredential, StoredCredential } from './repo.ts';
import type { MacMemoryStore } from './storage.ts';

/**
 * COSE の ES256（-7）、EdDSA（-8）、RS256（-257）だけ（不変条件9）。選択肢にはこの順で出す
 * （RS256 は期限があるので最後。ADR 0012 の決定10）。
 */
export const SUPPORTED_ALGORITHM_IDS: readonly number[] = Object.freeze([-7, -8, -257]);
/** RS256 の鍵長の下限（ADR 0012 の決定6）。 */
export const RSA_MIN_BITS = 2048;
// COSE の鍵の種類（kty）と曲線（crv）。
const KTY_OKP = 1;
const KTY_EC2 = 2;
const KTY_RSA = 3;
const CRV_P256 = 1;
const CRV_ED25519 = 6;
export const WEBAUTHN_TIMEOUT_MS = 60_000;
/** チャレンジの有効期限。ブラウザ側の timeout に少しだけ余裕を足す。 */
const CEREMONY_TTL_SECONDS = 75;
const TRANSPORTS: ReadonlySet<string> = new Set([
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
]);
const CEREMONY_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface WebAuthnConfig {
  readonly rpId: string;
  readonly rpName: string;
  /** ポート込みで固定する（CLAUDE.md「環境の注意」）。 */
  readonly origin: string;
  /** 承認用のオリジン（DESIGN.md 原則8）。承認用のログインと、承認と拒否だけに使う。 */
  readonly approvalOrigin: string;
}

export type RegistrationPurpose = 'create' | 'add';
export type AuthenticationPurpose = 'login' | 'stepup' | 'approval_login';
export type ApprovalCeremonyDecision = 'approved' | 'denied';

interface RegistrationCeremony {
  readonly kind: 'registration';
  readonly purpose: RegistrationPurpose;
  readonly challenge: string;
  readonly userId: WarifuUserId;
  /** インタラクションの uid か、PWA のセッションの参照。空文字は結び付けなし。 */
  readonly bind: string;
}

interface AuthenticationCeremony {
  readonly kind: 'authentication';
  readonly purpose: AuthenticationPurpose;
  readonly challenge: string;
  readonly bind: string;
}

/** 承認か拒否。チャレンジは要求の内容と決定から作った値（base64url）。 */
interface ApprovalCeremony {
  readonly kind: 'approval';
  readonly challenge: string;
  readonly bind: string;
  readonly userId: WarifuUserId;
  readonly itemId: string;
  readonly decision: ApprovalCeremonyDecision;
  readonly nonce: string;
}

type Ceremony = RegistrationCeremony | AuthenticationCeremony | ApprovalCeremony;

export type RegistrationResult =
  | { readonly ok: true; readonly userId: WarifuUserId; readonly credential: NewCredential }
  | { readonly ok: false };

export type AuthenticationResult =
  | {
      readonly ok: true;
      readonly userId: WarifuUserId;
      readonly credentialId: Uint8Array;
      readonly newSignCount: number;
      readonly backedUp: boolean;
    }
  | { readonly ok: false };

export type ApprovalVerifyResult =
  | {
      readonly ok: true;
      readonly userId: WarifuUserId;
      readonly credentialId: Uint8Array;
      readonly newSignCount: number;
      readonly backedUp: boolean;
      readonly itemId: string;
      readonly decision: ApprovalCeremonyDecision;
    }
  | { readonly ok: false };

type CredentialFinder = (
  userId: WarifuUserId,
  credentialId: Uint8Array,
) => Promise<StoredCredential | undefined>;

const FAILED = Object.freeze({ ok: false }) as { readonly ok: false };

/** 16バイトを、小文字の UUID の文字列にする。 */
export function uuidFromBytes(bytes: Uint8Array): string {
  if (bytes.byteLength !== 16) throw new RangeError('UUID の長さが違う');
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** userHandle（base64url）から利用者 ID を得る。形が違えば undefined。 */
export function userIdFromHandle(handle: unknown): WarifuUserId | undefined {
  if (typeof handle !== 'string' || handle.length !== 22) return undefined;
  try {
    return parseWarifuUserId(uuidFromBytes(fromBase64Url(handle)));
  } catch {
    return undefined;
  }
}

/**
 * attestation が none で、attStmt が空か（ADR 0007 の1）。ライブラリに渡す前に確かめる。
 * x5c の証明書チェーンを検証すると、ライブラリは証明書の CRL 配布点へ fetch する（不変条件7）。
 */
export function isNoneAttestation(response: unknown): boolean {
  try {
    const encoded = (response as RegistrationResponseJSON).response.attestationObject;
    if (typeof encoded !== 'string') return false;
    const attestation = decodeAttestationObject(new Uint8Array(fromBase64Url(encoded)));
    const attStmt = attestation.get('attStmt');
    return attestation.get('fmt') === 'none' && attStmt instanceof Map && attStmt.size === 0;
  } catch {
    return false;
  }
}

/**
 * 登録した公開鍵（COSE）が、アルゴリズムに合う種類・曲線・鍵長か（不変条件9、ADR 0012 の決定6・10）。
 * attestation が none の登録では、ライブラリは公開鍵で署名を確かめないので、ここで確かめる。
 * - ES256 は P-256、EdDSA は Ed25519 の鍵だけ。
 * - RS256 は 2048 ビット以上。鍵長を返して、記録する。
 * 合わなければ undefined。
 */
export function inspectPublicKey(
  publicKey: Uint8Array,
): { readonly alg: CredentialAlgorithm; readonly rsaBits: number | null } | undefined {
  let key: ReadonlyMap<number, unknown>;
  try {
    key = decodeCredentialPublicKey(new Uint8Array(publicKey)) as unknown as ReadonlyMap<
      number,
      unknown
    >;
  } catch {
    return undefined;
  }
  const kty = key.get(1);
  const alg = key.get(3);
  if (alg === -7 && kty === KTY_EC2 && key.get(-1) === CRV_P256) return { alg: -7, rsaBits: null };
  if (alg === -8 && kty === KTY_OKP && key.get(-1) === CRV_ED25519) {
    return { alg: -8, rsaBits: null };
  }
  if (alg === -257 && kty === KTY_RSA) {
    const modulus = key.get(-1);
    if (!(modulus instanceof Uint8Array)) return undefined;
    const bits = bitLength(modulus);
    return bits >= RSA_MIN_BITS ? { alg: -257, rsaBits: bits } : undefined;
  }
  return undefined;
}

/** 符号なしの整数（ビッグエンディアン）のビット数。先頭の0のバイトは数えない。 */
function bitLength(bytes: Uint8Array): number {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i += 1;
  if (i === bytes.length) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i] ?? 0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class Ceremonies {
  readonly #store: MacMemoryStore;
  readonly #config: WebAuthnConfig;

  constructor(store: MacMemoryStore, config: WebAuthnConfig) {
    this.#store = store;
    this.#config = config;
  }

  async #put(ceremony: Ceremony): Promise<string> {
    const ceremonyId = toBase64Url(randomBytesOf(32));
    await this.#store.set('Ceremony', ceremonyId, ceremony, CEREMONY_TTL_SECONDS);
    return ceremonyId;
  }

  /** 使い捨て。検証の結果を問わず、取り出した時点で消す。 */
  async #take(ceremonyId: unknown): Promise<Ceremony | undefined> {
    if (typeof ceremonyId !== 'string' || !CEREMONY_ID_PATTERN.test(ceremonyId)) return undefined;
    return this.#store.take<Ceremony>('Ceremony', ceremonyId);
  }

  async registrationOptions(input: {
    readonly purpose: RegistrationPurpose;
    readonly userId: WarifuUserId;
    readonly bind: string;
    /** 追加のとき、同じ認証器に2つ目を作らせない。 */
    readonly excludeCredentialIds?: readonly Uint8Array[];
  }): Promise<{ ceremonyId: string; options: PublicKeyCredentialCreationOptionsJSON }> {
    // 認証器の画面に出る名前。個人を指す情報を入れず、乱数のラベルにする（不変条件1(d)、4）。
    const label = `warifu-${Buffer.from(randomBytesOf(3)).toString('hex')}`;
    const options = await generateRegistrationOptions({
      rpName: this.#config.rpName,
      rpID: this.#config.rpId,
      // userHandle は利用者 ID の16バイト（ADR 0018）。連絡先や属性からは作らない。
      userID: new Uint8Array(uuidBytes(input.userId)),
      userName: label,
      userDisplayName: label,
      timeout: WEBAUTHN_TIMEOUT_MS,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [...SUPPORTED_ALGORITHM_IDS],
      excludeCredentials: (input.excludeCredentialIds ?? []).map((id) => ({ id: toBase64Url(id) })),
    });
    const ceremonyId = await this.#put({
      kind: 'registration',
      purpose: input.purpose,
      challenge: options.challenge,
      userId: input.userId,
      bind: input.bind,
    });
    return { ceremonyId, options };
  }

  async verifyRegistration(input: {
    readonly ceremonyId: unknown;
    readonly response: unknown;
    readonly purpose: RegistrationPurpose;
    readonly bind: string;
  }): Promise<RegistrationResult> {
    const ceremony = await this.#take(input.ceremonyId);
    if (
      ceremony?.kind !== 'registration' ||
      ceremony.purpose !== input.purpose ||
      ceremony.bind !== input.bind
    ) {
      return FAILED;
    }
    if (!isRecord(input.response) || !isNoneAttestation(input.response)) return FAILED;
    try {
      const result = await verifyRegistrationResponse({
        response: input.response as unknown as RegistrationResponseJSON,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: this.#config.origin,
        expectedRPID: this.#config.rpId,
        expectedType: 'webauthn.create',
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: [...SUPPORTED_ALGORITHM_IDS],
      });
      if (!result.verified || !result.registrationInfo.userVerified) return FAILED;
      const info = result.registrationInfo;
      if (info.fmt !== 'none') return FAILED;
      const publicKey = new Uint8Array(info.credential.publicKey);
      const key = inspectPublicKey(publicKey);
      if (key === undefined) return FAILED;
      const credentialId = fromBase64Url(info.credential.id);
      return {
        ok: true,
        userId: ceremony.userId,
        credential: {
          credentialId,
          publicKey,
          alg: key.alg,
          rsaBits: key.rsaBits,
          signCount: info.credential.counter,
          transports: (info.credential.transports ?? []).filter((t) => TRANSPORTS.has(t)),
          // AAGUID は保存しない（ADR 0007 の6）。
          backupEligible: info.credentialDeviceType === 'multiDevice',
          backedUp: info.credentialBackedUp,
        },
      };
    } catch {
      return FAILED;
    }
  }

  async authenticationOptions(input: {
    readonly purpose: AuthenticationPurpose;
    readonly bind: string;
  }): Promise<{ ceremonyId: string; options: PublicKeyCredentialRequestOptionsJSON }> {
    const options = await generateAuthenticationOptions({
      rpID: this.#config.rpId,
      timeout: WEBAUTHN_TIMEOUT_MS,
      userVerification: 'required',
      // allowCredentials は渡さない。発見可能な資格情報だけで、誰かを決める（ADR 0007 の3）。
    });
    const ceremonyId = await this.#put({
      kind: 'authentication',
      purpose: input.purpose,
      challenge: options.challenge,
      bind: input.bind,
    });
    return { ceremonyId, options };
  }

  /** 目的ごとの expectedOrigin。承認用のログインだけ、承認用のオリジン。 */
  #originOf(purpose: AuthenticationPurpose): string {
    return purpose === 'approval_login' ? this.#config.approvalOrigin : this.#config.origin;
  }

  /**
   * アサーションを検証する。find は、userHandle の利用者の範囲で、資格情報 ID の資格情報を返す（repo.findCredential）。
   * expectedUserId を渡したとき（step-up）は、その利用者でなければ失敗にする。
   */
  async verifyAuthentication(input: {
    readonly ceremonyId: unknown;
    readonly response: unknown;
    readonly purpose: AuthenticationPurpose;
    readonly bind: string;
    readonly expectedUserId?: WarifuUserId;
    readonly find: CredentialFinder;
    /** userHandle の利用者が分かった時点で呼ぶ（利用者ごとのレート制限）。false なら失敗にする。 */
    readonly admit?: (userId: WarifuUserId) => boolean;
  }): Promise<AuthenticationResult> {
    const ceremony = await this.#take(input.ceremonyId);
    if (
      ceremony?.kind !== 'authentication' ||
      ceremony.purpose !== input.purpose ||
      ceremony.bind !== input.bind
    ) {
      return FAILED;
    }
    return this.#verifyAssertion({
      response: input.response,
      challenge: ceremony.challenge,
      origin: this.#originOf(ceremony.purpose),
      ...(input.expectedUserId === undefined ? {} : { expectedUserId: input.expectedUserId }),
      find: input.find,
      ...(input.admit === undefined ? {} : { admit: input.admit }),
    });
  }

  /**
   * 承認か拒否の選択肢。challenge は、要求の内容と決定から作った MAC（inbox.ts の approvalChallengeMessage）。
   * 発見可能な資格情報だけで、allowCredentials は出さない（ほかのアサーションと同じ）。
   */
  async approvalOptions(input: {
    readonly challenge: Uint8Array;
    readonly bind: string;
    readonly userId: WarifuUserId;
    readonly itemId: string;
    readonly decision: ApprovalCeremonyDecision;
    readonly nonce: string;
  }): Promise<{ ceremonyId: string; options: PublicKeyCredentialRequestOptionsJSON }> {
    if (input.challenge.byteLength < 32) throw new RangeError('チャレンジが短い');
    const options = await generateAuthenticationOptions({
      rpID: this.#config.rpId,
      timeout: WEBAUTHN_TIMEOUT_MS,
      userVerification: 'required',
      challenge: new Uint8Array(input.challenge),
    });
    const ceremonyId = await this.#put({
      kind: 'approval',
      challenge: options.challenge,
      bind: input.bind,
      userId: input.userId,
      itemId: input.itemId,
      decision: input.decision,
      nonce: input.nonce,
    });
    return { ceremonyId, options };
  }

  /**
   * 承認か拒否のアサーションを検証する。recompute は、選択肢を出したときと同じ材料（DB の要求の内容と、儀式に覚えた
   * 決定と乱数）から、チャレンジを作り直して返す（base64url）。要求が決まった後、期限切れ、ほかの利用者のもの
   * なら undefined を返す。作り直した値が儀式のチャレンジと違えば（内容が変わった）、検証しない。
   */
  async verifyApproval(input: {
    readonly ceremonyId: unknown;
    readonly response: unknown;
    readonly bind: string;
    readonly expectedUserId: WarifuUserId;
    readonly find: CredentialFinder;
    readonly admit?: (userId: WarifuUserId) => boolean;
    readonly recompute: (ceremony: {
      readonly itemId: string;
      readonly decision: ApprovalCeremonyDecision;
      readonly nonce: string;
    }) => Promise<string | undefined>;
  }): Promise<ApprovalVerifyResult> {
    const ceremony = await this.#take(input.ceremonyId);
    if (
      ceremony?.kind !== 'approval' ||
      ceremony.bind !== input.bind ||
      ceremony.userId !== input.expectedUserId
    ) {
      return FAILED;
    }
    const recomputed = await input.recompute({
      itemId: ceremony.itemId,
      decision: ceremony.decision,
      nonce: ceremony.nonce,
    });
    if (recomputed === undefined || recomputed !== ceremony.challenge) return FAILED;
    const result = await this.#verifyAssertion({
      response: input.response,
      challenge: recomputed,
      origin: this.#config.approvalOrigin,
      expectedUserId: input.expectedUserId,
      find: input.find,
      ...(input.admit === undefined ? {} : { admit: input.admit }),
    });
    if (!result.ok) return FAILED;
    return { ...result, itemId: ceremony.itemId, decision: ceremony.decision };
  }

  async #verifyAssertion(input: {
    readonly response: unknown;
    readonly challenge: string;
    readonly origin: string;
    readonly expectedUserId?: WarifuUserId;
    readonly find: CredentialFinder;
    readonly admit?: (userId: WarifuUserId) => boolean;
  }): Promise<AuthenticationResult> {
    if (!isRecord(input.response)) return FAILED;
    const response = input.response as unknown as AuthenticationResponseJSON;
    try {
      // 発見可能な資格情報なので、userHandle は必ず返る。返らなければ拒否する。
      const userId = userIdFromHandle(response.response?.userHandle);
      if (userId === undefined) return FAILED;
      if (input.expectedUserId !== undefined && input.expectedUserId !== userId) return FAILED;
      if (input.admit !== undefined && !input.admit(userId)) return FAILED;
      if (typeof response.id !== 'string' || response.id !== response.rawId) return FAILED;
      const credentialId = fromBase64Url(response.id);
      const stored = await input.find(userId, credentialId);
      if (stored === undefined || stored.userId !== userId) return FAILED;
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: input.challenge,
        expectedOrigin: input.origin,
        expectedRPID: this.#config.rpId,
        expectedType: 'webauthn.get',
        credential: {
          id: toBase64Url(stored.credentialId),
          publicKey: new Uint8Array(stored.publicKey),
          counter: stored.signCount,
          transports: [...stored.transports] as never,
        },
        requireUserVerification: true,
      });
      if (!result.verified || !result.authenticationInfo.userVerified) return FAILED;
      return {
        ok: true,
        userId,
        credentialId,
        newSignCount: result.authenticationInfo.newCounter,
        backedUp: result.authenticationInfo.credentialBackedUp,
      };
    } catch {
      return FAILED;
    }
  }
}
