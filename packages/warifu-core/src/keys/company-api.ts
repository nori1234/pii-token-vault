// company-api の鍵のクライアント（不変条件3、ADR 0013、ADR 0022）。照合用の MAC、別名の導出、
// テナントの JWT と SET の署名（ES256）だけ。暗号化と復号のメソッドはない（鍵サービスも 403 を返す）。
// 窓口の ID（変更ID と取消要求ID の導出、申請ID と変更ID の照合の索引）の MAC は ADR 0026。

import type { TenantId, WarifuUserId } from '../ids.ts';
import { deriveAliasWith, macWith, publicKeysWith, signEs256With } from './common.ts';
import type { Es256PublicJwk, KeysvcConnection } from './protocol.ts';
import { createKeysvcTransport } from './transport.ts';

export type CompanyApiMacPurpose = 'alias_lookup' | 'audit_chain' | 'desk_id' | 'desk_lookup';
const MAC_PURPOSES: readonly CompanyApiMacPurpose[] = [
  'alias_lookup',
  'audit_chain',
  'desk_id',
  'desk_lookup',
];

/** tenant_jwt：企業向け API のアクセストークン。set：企業に送る SET（ADR 0022）。 */
export type CompanyApiSigningKeyId = 'tenant_jwt' | 'set';
const SIGNING_KEY_IDS: readonly CompanyApiSigningKeyId[] = ['tenant_jwt', 'set'];

export interface CompanyApiKeyClient {
  mac(purpose: CompanyApiMacPurpose, message: Uint8Array): Promise<Uint8Array>;
  deriveAlias(input: {
    readonly tenantId: TenantId;
    readonly userId: WarifuUserId;
    readonly generation: number;
  }): Promise<string>;
  sign(
    keyId: CompanyApiSigningKeyId,
    message: Uint8Array,
  ): Promise<{ readonly kid: string; readonly signature: Uint8Array }>;
  publicKeys(keyId: CompanyApiSigningKeyId): Promise<readonly Es256PublicJwk[]>;
}

export function createCompanyApiKeyClient(connection: KeysvcConnection): CompanyApiKeyClient {
  const call = createKeysvcTransport(connection, 'company-api');
  return Object.freeze({
    mac(purpose: CompanyApiMacPurpose, message: Uint8Array) {
      return macWith(call, MAC_PURPOSES, purpose, message);
    },
    deriveAlias(input: {
      readonly tenantId: TenantId;
      readonly userId: WarifuUserId;
      readonly generation: number;
    }) {
      return deriveAliasWith(call, input);
    },
    sign(keyId: CompanyApiSigningKeyId, message: Uint8Array) {
      return signEs256With(call, SIGNING_KEY_IDS, keyId, message);
    },
    publicKeys(keyId: CompanyApiSigningKeyId) {
      return publicKeysWith(call, SIGNING_KEY_IDS, keyId);
    },
  });
}
