// 旧会員の旧パスキーの確かめ（A社だけ。ADR 0020、ADR 0028 の O-86 の手順3・6）。
// - 使うのは、初回移行のときだけ（不変条件1(a)）。確かめた結果は5分だけ覚え、ログインのセッションにはしない
//   （完全な参加の企業は、ログインを割符の OIDC だけにする。RP-04）。
// - 企業の RP ID とオリジンで、UV 付きのアサーションを、毎回新しいチャレンジで検証する。方式は ES256 だけ（不変条件9）。
// - 引き継ぎの済んだ旧会員（closed）の旧パスキーは、受け付けない（RP-31）。

import { newRandomId } from '@pii-token-vault/rp-kit';
import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { LegacyMember } from './state.ts';

/** 旧パスキーの確かめの結果を覚えておく時間。 */
export const LEGACY_VERIFICATION_TTL_MS = 5 * 60_000;
const ES256 = -7;

export interface LegacyRp {
  readonly rpId: string;
  readonly rpName: string;
  readonly origin: string;
}

export async function legacyAuthenticationOptions(rp: LegacyRp) {
  return generateAuthenticationOptions({ rpID: rp.rpId, userVerification: 'required' });
}

/** アサーションを検証する。通れば、新しい署名カウンタを返す。 */
export async function verifyLegacyAssertion(
  rp: LegacyRp,
  member: LegacyMember,
  challenge: string,
  response: unknown,
): Promise<{ ok: true; counter: number } | { ok: false }> {
  if (member.closed) return { ok: false };
  try {
    const result = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      requireUserVerification: true,
      credential: {
        id: member.credentialId,
        publicKey: new Uint8Array(Buffer.from(member.publicKey, 'base64url')),
        counter: member.counter,
      },
    });
    if (!result.verified || !result.authenticationInfo.userVerified) return { ok: false };
    return { ok: true, counter: result.authenticationInfo.newCounter };
  } catch {
    return { ok: false };
  }
}

/** デモ用：旧会員と旧パスキーを用意する（本物の企業には、旧会員がすでにいる）。 */
export async function legacyRegistrationOptions(rp: LegacyRp) {
  return generateRegistrationOptions({
    rpName: rp.rpName,
    rpID: rp.rpId,
    userID: new TextEncoder().encode(newRandomId(16)),
    userName: '旧会員（デモ）',
    userDisplayName: '旧会員（デモ）',
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    supportedAlgorithmIDs: [ES256],
  });
}

export async function verifyLegacyRegistration(
  rp: LegacyRp,
  challenge: string,
  response: unknown,
): Promise<LegacyMember | undefined> {
  try {
    const result = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: [ES256],
    });
    if (!result.verified || !result.registrationInfo.userVerified) return undefined;
    const { credential } = result.registrationInfo;
    return {
      memberId: newRandomId(16),
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      authEpoch: 1,
      linkedAccountKey: null,
      closed: false,
      linkBlocked: false,
    };
  } catch {
    return undefined;
  }
}
