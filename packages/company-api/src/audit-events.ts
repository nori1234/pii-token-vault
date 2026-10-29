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
