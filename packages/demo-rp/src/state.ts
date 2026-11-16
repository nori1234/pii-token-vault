// demo-rp の状態（企業の側のデータ）。識別は (iss, sub) の組だけ（RP-01）。別名は連絡用で、鍵にも検索にも使わない（RP-05）。
// メール、電話、氏名、住所の欄は置かない（デモの企業は、本物の連絡先を持たない）。

/** 口座（出金先）の全体。企業のサーバーにだけ置き、割符には渡さない（ADR 0030）。 */
export interface PayoutDestination {
  readonly bankCode: string;
  readonly branchCode: string;
  /** 7桁。 */
  readonly accountNumber: string;
}

export interface Account {
  /** `${iss}|${sub}`。 */
  readonly key: string;
  readonly iss: string;
  readonly sub: string;
  readonly createdAt: number;
  payoutDestination: PayoutDestination | null;
  /** 回復した日（秒。ID トークンの recovered_at）。高リスクの操作を保留する方向にだけ使う（RP-53・RP-54）。 */
  recoveredAt: number | null;
  /** 初回紐付けで結び付いた旧会員（A社だけ）。1会員につき1回だけ（RP-30）。 */
  legacyMemberId: string | null;
}

/** 出金先の変更の申請（RP-09）。destination は、作ったときに固定し、書き換えない。 */
export interface PayoutRequest {
  readonly requestId: string;
  readonly accountKey: string;
  readonly destination: PayoutDestination;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** pending：承認待ち。used：変更に使った。superseded：新しい申請に置き換えた（もう使えない）。 */
  state: 'pending' | 'used' | 'superseded';
  usedAt: number | null;
}

/** 窓口の応対（受付番号は企業が発行する参照。認証や許可の根拠ではない。RP-22）。 */
export interface DeskSession {
  readonly receiptNo: string;
  readonly desk: string;
  readonly staff: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  /** 利用者が承認した、限定の許可（照会1件）。承認の前は null。 */
  grant: {
    readonly accountKey: string;
    readonly action: 'desk.case.status.read' | 'desk.order.status.read';
    readonly targetId: string;
    readonly grantedAt: number;
    readonly expiresAt: number;
    used: boolean;
  } | null;
}

export interface Order {
  readonly orderId: string;
  readonly accountKey: string;
  readonly label: string;
  readonly status: string;
}

/** 旧会員（A社だけ）。旧パスキーは、初回移行のときだけ確かめる（不変条件1(a)）。 */
export interface LegacyMember {
  readonly memberId: string;
  readonly credentialId: string;
  /** COSE の公開鍵（base64url）。 */
  readonly publicKey: string;
  counter: number;
  /** 認証世代。認証器の追加や削除、紐付けで上げる（ADR 0028 の O-88）。 */
  authEpoch: number;
  linkedAccountKey: string | null;
  /** 紐付けの完了と同時に閉じる（RP-31）。閉じたら、旧パスキーの確かめを受け付けない。 */
  closed: boolean;
  /**
   * 旧会員の側から取消があった（不正の疑い）。新しい引き継ぎの申請を受け付けない。解くのは、企業の調査の後
   * （デモには、解く手段を作っていない）。
   */
  linkBlocked: boolean;
}

export type LinkAttemptState =
  | 'proof_submitted'
  | 'pending_notice'
  | 'waiting'
  | 'final_proof_submitted'
  | 'linked'
  | 'cancelled'
  | 'expired'
  /** 割符の最終の承認の後、企業が紐付けなかった（認証世代が変わっていた。割符に not_linked を報告した）。 */
  | 'not_linked';

/** 初回紐付けの申請（企業の側の記録）。申請ID、会員参照、移行専用ID は、ここにだけ置く（ログ、URL、画面に出さない）。 */
export interface LinkAttempt {
  readonly requestId: string;
  readonly memberRef: string;
  readonly initialLinkId: string;
  readonly memberId: string;
  readonly accountKey: string;
  readonly authEpoch: number;
  readonly createdAt: number;
  state: LinkAttemptState;
  /** 待機の知らせの SET を受けた時刻（旧会員の側の知らせを出した時刻）。 */
  noticeAt: number | null;
}

export interface Session {
  readonly sessionId: string;
  accountKey: string | null;
  /** 進行中の認可の要求（rp-kit の PendingAuthorization と、何のための要求か）。 */
  pending: { readonly kind: string; readonly value: unknown; readonly ref: string | null } | null;
  /** 旧パスキーの確かめの結果（5分だけ。ログインではない）。 */
  legacy: { readonly memberId: string; readonly verifiedAt: number } | null;
  /** WebAuthn のチャレンジ（旧パスキーの確かめ）。 */
  challenge: string | null;
  /** 窓口担当者の画面を開いたか（デモの合言葉で確かめる。従業員の認証は、企業の既存の仕組みの代わり）。 */
  staff: boolean;
  readonly createdAt: number;
}

export interface DemoState {
  accounts: Map<string, Account>;
  sessions: Map<string, Session>;
  payoutRequests: Map<string, PayoutRequest>;
  deskSessions: Map<string, DeskSession>;
  orders: Map<string, Order>;
  legacyMembers: Map<string, LegacyMember>;
  linkAttempts: Map<string, LinkAttempt>;
  /** 受け取った SET の jti（重複を捨てる）。 */
  seenSetJtis: Set<string>;
  /** 受付番号の入力の時刻（利用者ごと。試行の上限のため。plan 2章のレート制限）。 */
  deskAttempts: Map<string, number[]>;
}

export function emptyState(): DemoState {
  return {
    accounts: new Map(),
    sessions: new Map(),
    payoutRequests: new Map(),
    deskSessions: new Map(),
    orders: new Map(),
    legacyMembers: new Map(),
    linkAttempts: new Map(),
    seenSetJtis: new Set(),
    deskAttempts: new Map(),
  };
}

export function accountKeyOf(iss: string, sub: string): string {
  return `${iss}|${sub}`;
}
