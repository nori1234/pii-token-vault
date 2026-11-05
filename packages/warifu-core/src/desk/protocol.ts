// 窓口の操作別承認の約束（ADR 0019、ADR 0026）。idp と company-api が共有する。
//
// - 操作の名前は、割符の製品の中の識別子（RAR の標準の名前ではない）。DESIGN.md 3章の3つだけ。
// - 作成（desk.case.create）の正本は company-api の desk_changes。idp は company-api の内部 API（Unix ドメイン
//   ソケットの HTTP。呼べるのは idp だけ）で、承認の記録、状態の照会、取消の受理を頼む。逆向きの API はない。
// - 申請ID は企業が作る値。変更ID と取消要求ID は、company-api が内部のレコード ID から MAC で導く値。どれも
//   不変条件4の値で、DB とログに平文で書かない。内部 API の本文（メモリ）にだけ載る。

import type { TenantId, WarifuUserId } from '../ids.ts';

/** RAR の型の名前（ADR 0026 の O-60）。 */
export const DESK_DETAIL_TYPE = 'warifu_desk';

/** P0 の窓口の操作（DESIGN.md 3章、仕様案 v0.7 の 2.1）。 */
export type DeskAction = 'desk.case.status.read' | 'desk.order.status.read' | 'desk.case.create';
export const DESK_ACTIONS: readonly DeskAction[] = Object.freeze([
  'desk.case.status.read',
  'desk.order.status.read',
  'desk.case.create',
]);

/** 書き込み（変更を払い出し、知らせと取消の対象になる）操作。P0 は一般問い合わせの作成だけ（ADR 0019）。 */
export type DeskWriteAction = 'desk.case.create';
export function isDeskWriteAction(action: DeskAction): action is DeskWriteAction {
  return action === 'desk.case.create';
}

/** 一般問い合わせの作成で選べる種別と言語（固定の列挙。ADR 0026 の O-60）。 */
export type DeskCaseCategory = 'general' | 'order' | 'account' | 'other';
export const DESK_CASE_CATEGORIES: readonly DeskCaseCategory[] = Object.freeze([
  'general',
  'order',
  'account',
  'other',
]);
export type DeskCaseLanguage = 'ja' | 'en';
export const DESK_CASE_LANGUAGES: readonly DeskCaseLanguage[] = Object.freeze(['ja', 'en']);

/** 申請ID（企業が作る128ビット以上の乱数の base64url）。 */
export const DESK_REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
/** 変更ID と取消要求ID（割符が MAC で導く32バイトの base64url）。 */
export const DESK_EXTERNAL_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** 正本の状態（ADR 0026 の O-66）。後ろの3つは終端。 */
export type DeskChangeState =
  | 'awaiting_notice'
  | 'created'
  | 'cancel_requested'
  | 'cancelled'
  | 'not_created'
  | 'closed';
export const DESK_CHANGE_STATES: readonly DeskChangeState[] = Object.freeze([
  'awaiting_notice',
  'created',
  'cancel_requested',
  'cancelled',
  'not_created',
  'closed',
]);
export function isTerminalDeskState(state: DeskChangeState): boolean {
  return state === 'cancelled' || state === 'not_created' || state === 'closed';
}

/** 承認から操作ごとの承認が効く時間、申請の期限、取消の期間（ADR 0019 の仮置き）。 */
export const DESK_TIMES = Object.freeze({
  approvalTtlSeconds: 300,
  requestTtlSeconds: 300,
  cancelWindowSeconds: 24 * 3600,
  /** 終端の後に残す日数。 */
  keepAfterTerminalDays: 7,
} as const);

// ---- company-api の内部 API（idp だけが呼ぶ） ----

/** 内部 API のソケットのファイル名。 */
export const DESK_SOCKET_NAME = 'company-api.sock';
export type DeskOp = 'approve' | 'status' | 'cancel';
export const DESK_PATHS: Readonly<Record<DeskOp, string>> = Object.freeze({
  approve: '/v1/desk_approve',
  status: '/v1/desk_status',
  cancel: '/v1/desk_cancel',
});
/** 内部 API を呼べるのは idp だけ。 */
export type DeskCaller = 'idp';

export interface DeskApproveRequest {
  readonly tenantId: TenantId;
  readonly userId: WarifuUserId;
  /** idp が作った内部のレコード ID（乱数の UUID）。同じ値の再送は、同じ変更ID を返す。 */
  readonly changeRef: string;
  readonly requestId: string;
  readonly action: DeskWriteAction;
}

export interface DeskStatusRequest {
  readonly userId: WarifuUserId;
  readonly items: readonly { readonly tenantId: TenantId; readonly changeRef: string }[];
}

export interface DeskStatusItem {
  readonly changeRef: string;
  /** unknown は、正本にない（承認の記録の前に失敗した、別の利用者のもの、消した後）。 */
  readonly state: DeskChangeState | 'unknown';
  readonly cancelDeadline: string | null;
}

export interface DeskCancelRequest {
  readonly tenantId: TenantId;
  readonly userId: WarifuUserId;
  readonly changeRef: string;
}

export const DESK_LIMITS = Object.freeze({
  requestBodyBytes: 8192,
  responseBodyBytes: 16_384,
  clientTimeoutMs: 5000,
  /** 1回の状態の照会で頼める項目の数。 */
  statusItems: 50,
} as const);

/** エラーの本文。理由によらず、同じ種類のエラーはバイト単位で同じ本文にする。 */
export const DESK_ERROR_BODY = Object.freeze({
  forbidden: '{"error":"forbidden"}',
  invalid_request: '{"error":"invalid_request"}',
  not_found: '{"error":"not_found"}',
  conflict: '{"error":"conflict"}',
  closed: '{"error":"closed"}',
  unavailable: '{"error":"unavailable"}',
} as const);
