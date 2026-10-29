// idp の監査の事象（ADR 0016、ADR 0018）。属性は UUID、整数、真偽値、列挙だけ（不変条件4）。

import { defineAuditEvent } from '@pii-token-vault/warifu-core/audit';

/** 割符のアカウントを作った（最初のパスキーの登録と同時）。 */
export const ACCOUNT_CREATED = defineAuditEvent('idp.account.created', {
  backup_eligible: 'bool',
});

/** パスキーを足した（step-up の後）。 */
export const PASSKEY_ADDED = defineAuditEvent('idp.passkey.added', {
  backup_eligible: 'bool',
  count: 'int',
});

/** パスキーを消した（step-up の後）。 */
export const PASSKEY_REMOVED = defineAuditEvent('idp.passkey.removed', {
  count: 'int',
});

/** 企業（テナント）への接続に同意した（個人情報保護法27条の記録。同意の文面の版は法務の確認の後に足す）。 */
export const CONNECTION_CONSENTED = defineAuditEvent('idp.connection.consented', {
  tenant_id: 'uuid',
});

/** 宛先確認を始めた。アドレスそのものは残さない。 */
export const EMAIL_VERIFICATION_STARTED = defineAuditEvent('idp.email.verification_started', {
  change: 'bool',
});

/** 宛先確認が終わり、本物のメールを登録または変更した。 */
export const EMAIL_VERIFIED = defineAuditEvent('idp.email.verified', {
  change: 'bool',
});

/** 承認待ちを作った（M7 の CIBA などが呼ぶ。ADR 0023）。中身は残さない。 */
export const APPROVAL_REQUESTED = defineAuditEvent('idp.approval.requested', {
  // M6 は端末での承認だけ。窓口での承認（desk）は M7 で足す。
  channel: { enum: ['device'] },
  tenant_id: 'uuid',
});

/** 承認待ちを、利用者がパスキー（UV）で承認または拒否した（ADR 0023）。 */
export const APPROVAL_DECIDED = defineAuditEvent('idp.approval.decided', {
  decision: { enum: ['approved', 'denied'] },
  channel: { enum: ['device'] },
  tenant_id: 'uuid',
});

// 窓口の操作別承認（ADR 0026 の O-71）。申請ID、変更ID、JWT は入れない。

/** 窓口の申請を、利用者がパスキー（UV）で承認した（利用者の範囲）。 */
export const DESK_APPROVED = defineAuditEvent('idp.desk.approved', {
  tenant_id: 'uuid',
  action: { enum: ['case_status_read', 'order_status_read', 'case_create'] },
});

/** 窓口の申請を承認しなかった（テナントの範囲。利用者はまだ分からない）。 */
export const DESK_DECLINED = defineAuditEvent('idp.desk.declined', {
  tenant_id: 'uuid',
  reason: { enum: ['denied', 'unrecognized', 'incoming_call'] },
});

/** 窓口の作成の取消を頼んだ（利用者の範囲）。 */
export const DESK_CANCEL_REQUESTED = defineAuditEvent('idp.desk.cancel_requested', {
  tenant_id: 'uuid',
});
