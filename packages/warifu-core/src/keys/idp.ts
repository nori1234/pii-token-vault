// idp の鍵のクライアント（不変条件3「型には許した操作のメソッドだけ」、ADR 0013）。
// 連絡先を暗号化できるが、復号はできない（メソッドがない。鍵サービスも 403 を返す）。

import { parseWarifuUserId, type TenantId, type WarifuUserId } from '../ids.ts';
import { deriveAliasWith, macWith } from './common.ts';
import { KeysvcError } from './errors.ts';
import { type Es256PublicJwk, type KeysvcConnection, LIMITS } from './protocol.ts';
import {
  arrayFrom,
  assertOneOf,
  bytesFrom,
  createKeysvcTransport,
  ES256_SIGNATURE_BYTES,
  encodeBytes,
  stringFrom,
} from './transport.ts';

export type IdpMacPurpose =
  | 'alias_lookup'
  | 'audit_chain'
  | 'pairwise_sub'
  | 'oidc_storage_id'
  | 'email_verify_code';
const MAC_PURPOSES: readonly IdpMacPurpose[] = [
  'alias_lookup',
  'audit_chain',
  'pairwise_sub',
  'oidc_storage_id',
  'email_verify_code',
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

const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function toJwk(value: unknown): Es256PublicJwk {
  if (value === null || typeof value !== 'object') throw new KeysvcError('internal');
  const jwk = value as Record<string, unknown>;
  if (
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    jwk.alg !== 'ES256' ||
    jwk.use !== 'sig' ||
    Object.hasOwn(jwk, 'd') ||
    typeof jwk.kid !== 'string' ||
    !KID_PATTERN.test(jwk.kid) ||
    typeof jwk.x !== 'string' ||
    !COORDINATE_PATTERN.test(jwk.x) ||
    typeof jwk.y !== 'string' ||
    !COORDINATE_PATTERN.test(jwk.y)
  ) {
    throw new KeysvcError('internal');
  }
  return Object.freeze({
    kid: jwk.kid,
    kty: 'EC',
    crv: 'P-256',
    x: jwk.x,
    y: jwk.y,
    alg: 'ES256',
    use: 'sig',
  });
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
    async sign(keyId: 'id_token', message: Uint8Array) {
      const response = await call('sign', {
        keyId: assertOneOf(keyId, ['id_token']),
        message: encodeBytes(message, LIMITS.signMessageBytes),
      });
      return {
        kid: stringFrom(response, 'kid', KID_PATTERN),
        signature: bytesFrom(response, 'signature', ES256_SIGNATURE_BYTES),
      };
    },
    async publicKeys(keyId: 'id_token') {
      const response = await call('public_keys', { keyId: assertOneOf(keyId, ['id_token']) });
      return Object.freeze(arrayFrom(response, 'keys').map(toJwk));
    },
  });
}
