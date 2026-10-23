// 監査ログ（CAP-17、ADR 0016）。M2 では本番の事象を定義しない（M3 以降で、使うマイルストーンが定義する）。

export type { AuditMacClient } from './append.ts';
export { AUDIT_LOCK_KEY, appendAudit } from './append.ts';
export type { AuditAttrKind, AuditAttrs, AuditEventDef } from './events.ts';
export { AuditAttrError, defineAuditEvent } from './events.ts';
export type {
  AuditChainRow,
  AuditEventRow,
  AuditFailureReason,
  AuditVerification,
} from './verify.ts';
export { readAuditRows, verifyAuditChain, verifyAuditRows } from './verify.ts';
