// 機能ごとのレート制限（plan 2章、CAP-34、ADR 0018）。窓の数え方は warifu-core の RateLimiter。
// キーは「アカウント」「送信元（IP）」の2つを、機能ごとに組み合わせる。値は ADR 0018、ADR 0023、ADR 0026、ADR 0027 の表を正とする。

import { RateLimiter as BaseRateLimiter, type LimitRule } from '@pii-token-vault/warifu-core';

export type { LimitRule };

/** ADR 0018、ADR 0023、ADR 0026 の表。 */
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
  /** 受信箱と承認待ちの一覧、既読にする操作（利用者ごと。ポーリングの間隔は30秒。ADR 0023）。 */
  inboxByUser: { limit: 60, windowSeconds: 60 },
  /** 承認と拒否の選択肢の発行（利用者ごと。ADR 0023）。 */
  approvalByUser: { limit: 20, windowSeconds: 60 },
  /** PAR の受け口（IP ごと。クライアントを確かめる前。ADR 0026 の O-70）。 */
  parByIp: { limit: 120, windowSeconds: 60 },
  /** PAR の受け口（クライアントごと。受け付けた後）。 */
  parByClient: { limit: 60, windowSeconds: 60 },
  /** 窓口の引き継ぎを作る（クライアントごと）。 */
  deskByClient: { limit: 60, windowSeconds: 60 },
  /** 窓口の作成の取消の選択肢（利用者ごと）。 */
  deskCancelByUser: { limit: 10, windowSeconds: 60 },
  /** 初回紐付けの引き継ぎを作る（クライアントごと。ADR 0028 の O-101）。 */
  initialLinkByClient: { limit: 60, windowSeconds: 60 },
  /** 初回紐付けの項目の取消の選択肢（利用者ごと。窓口の取消と同じ）。 */
  initialLinkCancelByUser: { limit: 10, windowSeconds: 60 },
  /** 回復の開始（IP ごと。ADR 0027 の O-84）。 */
  recoveryStartByIp: { limit: 10, windowSeconds: 3600 },
  /** 回復の開始（回復コードの利用者 ID ごと）。 */
  recoveryStartByUser: { limit: 5, windowSeconds: 3600 },
  /** 回復コードの作成（利用者ごと）。 */
  recoveryCodeByUser: { limit: 5, windowSeconds: 3600 },
  /** 協力者の招待の作成（利用者ごと）。 */
  helperInviteByUser: { limit: 5, windowSeconds: 3600 },
  /** 招待のコードと、協力者の承認の結び付けのコードの入力（利用者ごと）。 */
  helperCodeByUser: { limit: 10, windowSeconds: 600 },
  /** 招待のコードと、協力者の承認の結び付けのコードの入力（IP ごと）。 */
  helperCodeByIp: { limit: 30, windowSeconds: 600 },
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
