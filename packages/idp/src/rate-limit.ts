// 機能ごとのレート制限（plan 2章、CAP-34、ADR 0018）。窓の数え方は warifu-core の RateLimiter。
// キーは「アカウント」「送信元（IP）」の2つを、機能ごとに組み合わせる。値は ADR 0018 の表を正とする。

import { RateLimiter as BaseRateLimiter, type LimitRule } from '@pii-token-vault/warifu-core';

export type { LimitRule };

/** ADR 0018 の表。 */
export const RATE_LIMITS = Object.freeze({
  /** パスキーでアカウントを作る（IP ごと）。 */
  accountCreateByIp: { limit: 10, windowSeconds: 3600 },
  /** パスキーのアサーションの検証（IP ごと）。 */
  loginByIp: { limit: 20, windowSeconds: 60 },
  /** パスキーのアサーションの検証（userHandle の利用者ごと）。 */
  loginByUser: { limit: 10, windowSeconds: 60 },
  /** 確認コードの送信（利用者ごと）。 */
  emailSendByUser: { limit: 3, windowSeconds: 900 },
  /** 確認コードの送信（IP ごと）。 */
  emailSendByIp: { limit: 20, windowSeconds: 3600 },
  /** WebAuthn の選択肢の発行（IP ごと。チャレンジでメモリを埋めさせない）。 */
  ceremonyByIp: { limit: 60, windowSeconds: 60 },
} satisfies Record<string, LimitRule>);

export type LimitName = keyof typeof RATE_LIMITS;

/** idp の上限（ADR 0018 の表）。 */
export class RateLimiter extends BaseRateLimiter<LimitName> {
  constructor(
    now: () => number = Date.now,
    rules: Readonly<Record<LimitName, LimitRule>> = RATE_LIMITS,
  ) {
    super(rules, now);
  }
}
