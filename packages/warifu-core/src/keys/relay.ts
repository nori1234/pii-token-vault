// relay の鍵のクライアント（不変条件3、ADR 0013）。連絡先を復号できる唯一のクライアント。
// relay だけが import する（t08-key-client-surface で固定する）。
// 連絡先の暗号化と別名の導出のメソッドはない（鍵サービスも 403 を返す）。署名は DKIM と ARC の鍵（dkim）だけ（ADR 0021）。

import { isUuid, parseWarifuUserId, type WarifuUserId } from '../ids.ts';
import { macWith } from './common.ts';
import { KeysvcError } from './errors.ts';
import { type KeysvcConnection, LIMITS, RSA2048_SIGNATURE_BYTES } from './protocol.ts';
import {
  arrayFrom,
  bytesFrom,
  createKeysvcTransport,
  encodeBytes,
  stringFrom,
} from './transport.ts';

/**
 * relay の MAC の用途。relay_replay は DKIM の b= の照合用、relay_thread は返信用のアドレスの照合用、
 * message_id は配送ログの Message-ID（ADR 0021）。
 */
export type RelayMacPurpose =
  | 'alias_lookup'
  | 'audit_chain'
  | 'relay_replay'
  | 'relay_thread'
  | 'message_id';
const MAC_PURPOSES: readonly RelayMacPurpose[] = [
  'alias_lookup',
  'audit_chain',
  'relay_replay',
  'relay_thread',
  'message_id',
];
const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** RSA 2048 の SubjectPublicKeyInfo の DER は 294 バイト。 */
const DKIM_SPKI_BYTES = 294;
// 暗号文の上限：頭の6バイト、IV の12バイト、平文、タグの16バイト。
const MAX_CIPHERTEXT_BYTES = 6 + 12 + LIMITS.plaintextBytes + 16;

export interface RelayKeyClient {
  decryptContact(input: {
    readonly userId: WarifuUserId;
    readonly ciphertext: Uint8Array;
  }): Promise<Uint8Array>;
  encryptQueueItem(input: {
    readonly queueItemId: string;
    readonly plaintext: Uint8Array;
  }): Promise<Uint8Array>;
  decryptQueueItem(input: {
    readonly queueItemId: string;
    readonly ciphertext: Uint8Array;
  }): Promise<Uint8Array>;
  mac(purpose: RelayMacPurpose, message: Uint8Array): Promise<Uint8Array>;
  /** DKIM と ARC の署名（rsa-sha256）。message は正規化したヘッダーの列。 */
  signDkim(message: Uint8Array): Promise<{ readonly kid: string; readonly signature: Uint8Array }>;
  /** DNS の p= に載せる公開鍵（SubjectPublicKeyInfo の DER）。 */
  dkimPublicKey(): Promise<{ readonly kid: string; readonly spki: Uint8Array }>;
}

function queueItemId(value: string): string {
  if (!isUuid(value)) throw new KeysvcError('invalid_request');
  return value;
}

export function createRelayKeyClient(connection: KeysvcConnection): RelayKeyClient {
  const call = createKeysvcTransport(connection, 'relay');
  return Object.freeze({
    async decryptContact(input: {
      readonly userId: WarifuUserId;
      readonly ciphertext: Uint8Array;
    }) {
      const response = await call('decrypt', {
        keyId: 'contact',
        ciphertext: encodeBytes(input.ciphertext, MAX_CIPHERTEXT_BYTES),
        context: { field: 'email', user_id: parseWarifuUserId(input.userId) },
      });
      return bytesFrom(response, 'plaintext');
    },
    async encryptQueueItem(input: {
      readonly queueItemId: string;
      readonly plaintext: Uint8Array;
    }) {
      const response = await call('encrypt', {
        keyId: 'relay_queue',
        plaintext: encodeBytes(input.plaintext, LIMITS.plaintextBytes),
        context: { queue_item_id: queueItemId(input.queueItemId) },
      });
      return bytesFrom(response, 'ciphertext');
    },
    async decryptQueueItem(input: {
      readonly queueItemId: string;
      readonly ciphertext: Uint8Array;
    }) {
      const response = await call('decrypt', {
        keyId: 'relay_queue',
        ciphertext: encodeBytes(input.ciphertext, MAX_CIPHERTEXT_BYTES),
        context: { queue_item_id: queueItemId(input.queueItemId) },
      });
      return bytesFrom(response, 'plaintext');
    },
    mac(purpose: RelayMacPurpose, message: Uint8Array) {
      return macWith(call, MAC_PURPOSES, purpose, message);
    },
    async signDkim(message: Uint8Array) {
      const response = await call('sign', {
        keyId: 'dkim',
        message: encodeBytes(message, LIMITS.signMessageBytes),
      });
      return {
        kid: stringFrom(response, 'kid', KID_PATTERN),
        signature: bytesFrom(response, 'signature', RSA2048_SIGNATURE_BYTES),
      };
    },
    async dkimPublicKey() {
      const response = await call('public_keys', { keyId: 'dkim' });
      const keys = arrayFrom(response, 'keys');
      const key = keys[0];
      if (keys.length !== 1 || typeof key !== 'object' || key === null) {
        throw new KeysvcError('internal');
      }
      const kid = stringFrom(key, 'kid', KID_PATTERN);
      if ((key as { kty?: unknown }).kty !== 'RSA') throw new KeysvcError('internal');
      return { kid, spki: bytesFrom(key, 'spki', DKIM_SPKI_BYTES) };
    },
  });
}
