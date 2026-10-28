// idp の鍵のクライアント（不変条件3「型には許した操作のメソッドだけ」、ADR 0013）。
// 連絡先を暗号化できるが、復号はできない（メソッドがない。鍵サービスも 403 を返す）。

import { parseWarifuUserId, type TenantId, type WarifuUserId } from '../ids.ts';
import { deriveAliasWith, macWith, publicKeysWith, signEs256With } from './common.ts';
import { type Es256PublicJwk, type KeysvcConnection, LIMITS } from './protocol.ts';
import { bytesFrom, createKeysvcTransport, encodeBytes } from './transport.ts';

export type IdpMacPurpose =
  | 'alias_lookup'
  | 'audit_chain'
  | 'pairwise_sub'
  | 'oidc_storage_id'
  | 'email_verify_code'
  | 'approval_challenge';
const MAC_PURPOSES: readonly IdpMacPurpose[] = [
  'alias_lookup',
  'audit_chain',
  'pairwise_sub',
  'oidc_storage_id',
  'email_verify_code',
  'approval_challenge',
];

export interface IdpKeyClient {
  encryptContact(input: {
    readonly userId: WarifuUserId;
    readonly plaintext: Uint8Array;
  }): Promise<Uint8Array>;
  mac(purpose: IdpMacPurpose, message: Uint8Array): Promise<Uint8Array>;
  deriveAlias(input: {
    readonly tenantId: TenantId;
    readonly userId: WarifuUserId;
    readonly generation: number;
  }): Promise<string>;
  sign(
    keyId: 'id_token',
    message: Uint8Array,
  ): Promise<{ readonly kid: string; readonly signature: Uint8Array }>;
  publicKeys(keyId: 'id_token'): Promise<readonly Es256PublicJwk[]>;
}

export function createIdpKeyClient(connection: KeysvcConnection): IdpKeyClient {
  const call = createKeysvcTransport(connection, 'idp');
  return Object.freeze({
    async encryptContact(input: { readonly userId: WarifuUserId; readonly plaintext: Uint8Array }) {
      const response = await call('encrypt', {
        keyId: 'contact',
        plaintext: encodeBytes(input.plaintext, LIMITS.plaintextBytes),
        context: { field: 'email', user_id: parseWarifuUserId(input.userId) },
      });
      return bytesFrom(response, 'ciphertext');
    },
    mac(purpose: IdpMacPurpose, message: Uint8Array) {
      return macWith(call, MAC_PURPOSES, purpose, message);
    },
    deriveAlias(input: {
      readonly tenantId: TenantId;
      readonly userId: WarifuUserId;
      readonly generation: number;
    }) {
      return deriveAliasWith(call, input);
    },
    sign(keyId: 'id_token', message: Uint8Array) {
      return signEs256With(call, ['id_token'], keyId, message);
    },
    publicKeys(keyId: 'id_token') {
      return publicKeysWith(call, ['id_token'], keyId);
    },
  });
}
