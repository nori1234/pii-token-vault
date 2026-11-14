// company-api の監査の事象（ADR 0016、ADR 0022）。属性は UUID、整数、真偽値、列挙だけ（不変条件4）。
// sub や別名は入れない（自由な文字列は入れられない）。テナントの範囲（withTenant）で残す。

import { defineAuditEvent } from '@pii-token-vault/warifu-core/audit';

/** 企業の頼みで、別名を次の世代にした（前の世代は廃番になり、二度と割り当てない）。 */
export const ALIAS_ROTATED = defineAuditEvent('company_api.alias.rotated', {
  generation: 'int',
});

// 窓口の作成の正本（ADR 0026 の O-71）。申請ID、変更ID、取消要求ID は入れない。テナントの範囲で残す。

/** 承認した作成を記録した（idp の内部 API から）。 */
export const DESK_CHANGE_RECORDED = defineAuditEvent('company_api.desk.change_recorded', {});

/** 企業から作成の知らせを受け、取消期限を決めた。 */
export const DESK_NOTICE_RECORDED = defineAuditEvent('company_api.desk.notice_recorded', {});

/** 利用者の取消を受理した（idp の内部 API から）。 */
export const DESK_CANCEL_ACCEPTED = defineAuditEvent('company_api.desk.cancel_accepted', {});

/** 企業から、取消を適用したと報告を受けた。 */
export const DESK_CANCEL_APPLIED = defineAuditEvent('company_api.desk.cancel_applied', {});

/** 企業から、承認を受けたのに作らなかったと報告を受けた。 */
export const DESK_NOT_CREATED = defineAuditEvent('company_api.desk.not_created', {});

/** 取消期限を過ぎ、取消なしで受付を終えた。 */
export const DESK_CLOSED = defineAuditEvent('company_api.desk.closed', {});

/** 利用者の回復の成立を、このテナントへの送信待ちに入れた（idp の内部 API から。ADR 0027 の O-81）。 */
export const RECOVERY_NOTIFIED = defineAuditEvent('company_api.recovery.notified', {});

// 参加の状態（ADR 0028 の O-95）。期限は、1970-01-01 からの日数（期限がなければ 0）。

/** テナントの参加の状態の版が、監査ログに最後に残した版と違った（起動のときに残す）。 */
export const PARTICIPATION_CHANGED = defineAuditEvent('company_api.participation.changed', {
  revision: 'int',
  participation: { enum: ['full', 'migrating'] },
  deadline_day: 'int',
});

// 初回紐付けの正本（ADR 0028 の O-102）。申請ID、移行専用ID、会員参照、証跡、承認の JWT は入れない。テナントの範囲で残す。

/** 企業から仮申請を受けた。 */
export const INITIAL_LINK_PREPARED = defineAuditEvent('company_api.initial_link.prepared', {});

/** 企業の証跡を受理した。 */
export const INITIAL_LINK_PROOF_ACCEPTED = defineAuditEvent(
  'company_api.initial_link.proof_accepted',
  {
    stage: { enum: ['initial', 'final'] },
  },
);

/** 本人の承認を記録し、待機の知らせの SET を送信待ちに入れた（idp の内部 API から）。 */
export const INITIAL_LINK_NOTICE_QUEUED = defineAuditEvent(
  'company_api.initial_link.notice_queued',
  {},
);

/** 待機の知らせの SET が届き（202）、待機の時間が進み始めた。 */
export const INITIAL_LINK_WAITING = defineAuditEvent('company_api.initial_link.waiting', {});

/** 紐付けの承認を出した（idp の内部 API から）。 */
export const INITIAL_LINK_APPROVED = defineAuditEvent('company_api.initial_link.approved', {});

/** 企業から、紐付けたと報告を受けた。 */
export const INITIAL_LINK_LINKED = defineAuditEvent('company_api.initial_link.linked', {});

/** 取消を受理した。 */
export const INITIAL_LINK_CANCEL_ACCEPTED = defineAuditEvent(
  'company_api.initial_link.cancel_accepted',
  {
    source: { enum: ['user', 'company'] },
  },
);

/** 取消で申請が終わった。 */
export const INITIAL_LINK_CANCELLED = defineAuditEvent('company_api.initial_link.cancelled', {});

/** 期限を過ぎて、または参加の状態か移行プロファイルの版が変わって、申請が終わった。 */
export const INITIAL_LINK_EXPIRED = defineAuditEvent('company_api.initial_link.expired', {});

/** 企業から、紐付けなかったと報告を受けた。 */
export const INITIAL_LINK_NOT_LINKED = defineAuditEvent('company_api.initial_link.not_linked', {});
