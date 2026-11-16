// company-api の鍵のクライアント（不変条件3、ADR 0013、ADR 0022）。照合用の MAC、別名の導出、
// テナントの JWT と SET の署名（ES256）だけ。暗号化と復号のメソッドはない（鍵サービスも 403 を返す）。
// 窓口の ID（変更ID と取消要求ID の導出、申請ID と変更ID の照合の索引）の MAC は ADR 0026。
// 初回紐付けの移行専用 ID の導出と照合の MAC は、版を持つ（ADR 0028 の O-87）。macVersioned と macAllVersions で呼ぶ。

import type { TenantId, WarifuUserId } from '../ids.ts';
import {
  deriveAliasWith,
  macAllVersionsWith,
  macVersionedWith,
  macWith,
  publicKeysWith,
  signEs256With,
  type VersionedMac,
} from './common.ts';
import type { Es256PublicJwk, KeysvcConnection, VersionedMacPurpose } from './protocol.ts';
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
  /** 版を持つ用途の MAC。version を省くと最新の版で作る。使った版を返す。 */
  macVersioned(
    purpose: VersionedMacPurpose,
    message: Uint8Array,
    version?: number,
  ): Promise<VersionedMac>;
  /** 版を持つ用途の、鍵サービスが持つすべての版での MAC（古い順）。照合と、起動のときの版の確かめに使う。 */
  macAllVersions(
    purpose: VersionedMacPurpose,
    message: Uint8Array,
  ): Promise<readonly VersionedMac[]>;
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
    macVersioned(purpose: VersionedMacPurpose, message: Uint8Array, version?: number) {
      return macVersionedWith(call, purpose, message, version);
    },
    macAllVersions(purpose: VersionedMacPurpose, message: Uint8Array) {
      return macAllVersionsWith(call, purpose, message);
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
