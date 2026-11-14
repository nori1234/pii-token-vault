// 初回紐付けのテストの補助（ADR 0028）。企業のサーバーの代わりに、初回紐付けの証跡（ES256 の JWS）を作る。

import { type KeyObject, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import {
  INITIAL_LINK_PROOF_TYP,
  proofAudience,
} from '../../packages/company-api/src/initial-link.ts';
import { ISSUER, type TestTenant } from './company-api.ts';

export const TEST_INITIAL_LINK = { profileVersion: 3, approvedOn: '2026-11-01' } as const;

const b64 = (bytes: Buffer) => bytes.toString('base64url');
export const newRequestId = () => b64(randomBytes(18));
export const newMemberRef = () => b64(randomBytes(18));

/** 証跡。claims で中身を変え、options で typ、鍵、有効期間を変える（攻撃の段で使う）。 */
export async function initialLinkProof(
  t: TestTenant,
  claims: Record<string, unknown>,
  options: {
    readonly nowMs: number;
    readonly typ?: string;
    readonly key?: KeyObject;
    readonly lifetime?: number;
  },
): Promise<string> {
  const iat = Math.floor(options.nowMs / 1000);
  return new SignJWT({
    jti: b64(randomBytes(16)),
    stage: 'initial',
    eligibility: 'eligible',
    credential_kind: 'passkey',
    profile_version: TEST_INITIAL_LINK.profileVersion,
    auth_epoch: 7,
    ...claims,
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: t.client.kid,
      typ: options.typ ?? INITIAL_LINK_PROOF_TYP,
    })
    .setIssuer(t.client.clientId)
    .setAudience(proofAudience(ISSUER))
    .setIssuedAt(iat)
    .setExpirationTime(iat + (options.lifetime ?? 120))
    .sign(options.key ?? t.client.privateKey);
}
