// 能力の表（不変条件3、spec 04 2章、ADR 0013）。この1か所だけに書く。
// ここにない (サービス, 操作, 対象) は、すべて 403 にする。
//
// 表の性質（keysvc/test/acl.test.ts と t08-keysvc-acl で固定する）：
// - decrypt を持つのは relay だけ。
// - relay は derive_alias を持たない。relay の sign と public_keys は dkim の鍵だけ（DKIM と ARC。ADR 0021）。
//   relay の encrypt は relay_queue だけ（連絡先の暗号文を作れない）。
// - company-api は encrypt と decrypt を持たない。company-api の sign と public_keys は、tenant_jwt と set の鍵だけ（ADR 0022）。
// - sender、rp-kit、demo-rp の行はない（資格情報もない）。
// - sub の導出（pairwise_sub）、idp の保存の id（oidc_storage_id）、確認コード（email_verify_code）の MAC は idp だけ（ADR 0018）。
//   承認のチャレンジ（approval_challenge）の MAC も idp だけ（ADR 0023）。
//
// 行を足すときは、warifu-core の keys/protocol.ts、各クライアントの型、t08-keysvc-acl と t08-key-client-surface の
// 期待の表を同じ PR で直す。

import type {
  EncryptionKeyId,
  KeysvcCaller,
  KeysvcOp,
  MacPurpose,
  SigningKeyId,
} from '@pii-token-vault/warifu-core/keys/protocol';

/** 操作の対象。derive_alias の対象は、別名を導く鍵（alias_derive）。 */
export type AclTarget = EncryptionKeyId | MacPurpose | SigningKeyId | 'alias_derive';

export const ACL: ReadonlyArray<readonly [KeysvcCaller, KeysvcOp, AclTarget]> = Object.freeze([
  ['idp', 'encrypt', 'contact'],
  ['idp', 'mac', 'alias_lookup'],
  ['idp', 'mac', 'audit_chain'],
  ['idp', 'mac', 'pairwise_sub'],
  ['idp', 'mac', 'oidc_storage_id'],
  ['idp', 'mac', 'email_verify_code'],
  ['idp', 'mac', 'approval_challenge'],
  ['idp', 'derive_alias', 'alias_derive'],
  ['idp', 'sign', 'id_token'],
  ['idp', 'public_keys', 'id_token'],

  ['company-api', 'mac', 'alias_lookup'],
  ['company-api', 'mac', 'audit_chain'],
  ['company-api', 'derive_alias', 'alias_derive'],
  ['company-api', 'sign', 'tenant_jwt'],
  ['company-api', 'public_keys', 'tenant_jwt'],
  ['company-api', 'sign', 'set'],
  ['company-api', 'public_keys', 'set'],

  ['relay', 'encrypt', 'relay_queue'],
  ['relay', 'decrypt', 'contact'],
  ['relay', 'decrypt', 'relay_queue'],
  ['relay', 'mac', 'alias_lookup'],
  ['relay', 'mac', 'audit_chain'],
  ['relay', 'mac', 'relay_replay'],
  ['relay', 'mac', 'relay_thread'],
  ['relay', 'mac', 'message_id'],
  ['relay', 'sign', 'dkim'],
  ['relay', 'public_keys', 'dkim'],
] as const);

/** (サービス, 操作) が表にあるか。未知の操作の名前も false。 */
export function allowedOp(caller: KeysvcCaller, op: string): boolean {
  return ACL.some(([c, o]) => c === caller && o === op);
}

/** (サービス, 操作, 対象) が表にあるか。未知の対象も false。 */
export function allowedTarget(caller: KeysvcCaller, op: KeysvcOp, target: unknown): boolean {
  return ACL.some(([c, o, t]) => c === caller && o === op && t === target);
}
