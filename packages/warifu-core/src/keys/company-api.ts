// company-api の鍵のクライアント（不変条件3、ADR 0012）。照合用の MAC と、別名の導出だけ。
// 暗号化と復号のメソッドはない（鍵サービスも 403 を返す）。

import type { TenantId, WarifuUserId } from '../ids.ts';
import { deriveAliasWith, macWith } from './common.ts';
import type { KeysvcConnection } from './protocol.ts';
import { createTransport } from './transport.ts';

export type CompanyApiMacPurpose = 'alias_lookup' | 'audit_chain';
const MAC_PURPOSES: readonly CompanyApiMacPurpose[] = ['alias_lookup', 'audit_chain'];

export interface CompanyApiKeyClient {
  mac(purpose: CompanyApiMacPurpose, message: Uint8Array): Promise<Uint8Array>;
  deriveAlias(input: {
    readonly tenantId: TenantId;
    readonly userId: WarifuUserId;
    readonly generation: number;
  }): Promise<string>;
}

export function createCompanyApiKeyClient(connection: KeysvcConnection): CompanyApiKeyClient {
  const call = createTransport(connection, 'company-api');
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
  });
}
