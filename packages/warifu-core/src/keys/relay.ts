// relay の鍵のクライアント（不変条件3、ADR 0013）。連絡先を復号できる唯一のクライアント。
// relay だけが import する（t08-key-client-surface で固定する）。
// 連絡先の暗号化、別名の導出、署名のメソッドはない（鍵サービスも 403 を返す）。

import { isUuid, parseWarifuUserId, type WarifuUserId } from '../ids.ts';
import { macWith } from './common.ts';
import { KeysvcError } from './errors.ts';
import { type KeysvcConnection, LIMITS } from './protocol.ts';
import { bytesFrom, createKeysvcTransport, encodeBytes } from './transport.ts';

export type RelayMacPurpose = 'alias_lookup' | 'audit_chain';
const MAC_PURPOSES: readonly RelayMacPurpose[] = ['alias_lookup', 'audit_chain'];
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
  });
}
