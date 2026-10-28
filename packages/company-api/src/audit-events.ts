// company-api の監査の事象（ADR 0016、ADR 0022）。属性は UUID、整数、真偽値、列挙だけ（不変条件4）。
// sub や別名は入れない（自由な文字列は入れられない）。テナントの範囲（withTenant）で残す。

import { defineAuditEvent } from '@pii-token-vault/warifu-core/audit';

/** 企業の頼みで、別名を次の世代にした（前の世代は廃番になり、二度と割り当てない）。 */
export const ALIAS_ROTATED = defineAuditEvent('company_api.alias.rotated', {
  generation: 'int',
});
