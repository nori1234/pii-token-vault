// company-api のレート制限（plan 2章、CAP-34、ADR 0022）。値は ADR 0022 の表を正とする。
// キーは、送信元の IP（トークンの発行の前）と、テナント・クライアント（確かめた後）。

import { type LimitRule, RateLimiter } from '@pii-token-vault/warifu-core';

export const COMPANY_API_LIMITS = Object.freeze({
  /** トークンの要求（IP ごと。クライアントを確かめる前）。 */
  tokenByIp: { limit: 60, windowSeconds: 60 },
  /** トークンの発行（クライアントごと。確かめた後）。 */
  tokenByClient: { limit: 30, windowSeconds: 60 },
  /** 企業向け API の呼び出し（テナントごと）。 */
  apiByTenant: { limit: 600, windowSeconds: 60 },
  /** 別名の入れ替え（テナントごと）。 */
  rotateByTenant: { limit: 60, windowSeconds: 60 },
  /** 検証の SET の依頼（テナントごと）。 */
  verificationByTenant: { limit: 10, windowSeconds: 3600 },
} satisfies Record<string, LimitRule>);

export type CompanyApiLimitName = keyof typeof COMPANY_API_LIMITS;

export function companyApiLimiter(
  now: () => number,
  rules: Readonly<Record<CompanyApiLimitName, LimitRule>> = COMPANY_API_LIMITS,
): RateLimiter<CompanyApiLimitName> {
  return new RateLimiter(rules, now);
}
