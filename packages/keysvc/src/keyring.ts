// 鍵の束。起動のたびに keysvc の中で作り、メモリの中だけに置く（ADR 0013）。
// ファイル、DB、ログ、応答のどれにも書かない。鍵を返す操作はない。
// 鍵は用途ごとに独立に作る。1つの鍵から導く方式（HKDF など）は許可リストにないので使わない（不変条件9）。

import { toBase64Url } from '@pii-token-vault/warifu-core';
import {
  type DkimPublicKey,
  ENCRYPTION_KEY_IDS,
  type EncryptionKeyId,
  type Es256PublicJwk,
  MAC_PURPOSES,
  type MacPurpose,
  type SigningKeyId,
} from '@pii-token-vault/warifu-core/keys/protocol';
import {
  type Es256KeyPair,
  generateEs256KeyPair,
  generateRsa2048KeyPair,
  HMAC_BYTES,
  newSymmetricKey,
  randomId,
} from './crypto.ts';

/** 暗号文の頭に入れる鍵の番号。番号は変えない（変えると、前の暗号文を読めなくなる）。 */
export const ENCRYPTION_KEY_NUMBER: Readonly<Record<EncryptionKeyId, number>> = Object.freeze({
  contact: 1,
  relay_queue: 2,
});

export interface EncryptionKey {
  readonly version: number;
  readonly key: Uint8Array;
}

export type SigningKey =
  | {
      readonly alg: 'ES256';
      readonly kid: string;
      readonly privateKey: Es256KeyPair['privateKey'];
      readonly publicKey: Es256PublicJwk;
    }
  | {
      readonly alg: 'RS256';
      readonly kid: string;
      readonly privateKey: Es256KeyPair['privateKey'];
      readonly publicKey: DkimPublicKey;
    };

export interface Keyring {
  /** いま暗号化に使う版。 */
  primary(keyId: EncryptionKeyId): EncryptionKey;
  /** 復号は、暗号文の頭の版で鍵を選ぶ。なければ undefined。 */
  byVersion(keyId: EncryptionKeyId, version: number): EncryptionKey | undefined;
  macKey(purpose: MacPurpose): Uint8Array;
  aliasDeriveKey(): Uint8Array;
  signingKey(keyId: SigningKeyId): SigningKey;
  publicKeys(keyId: SigningKeyId): readonly (Es256PublicJwk | DkimPublicKey)[];
}

export function createKeyring(): Keyring {
  const encryption = new Map<EncryptionKeyId, readonly EncryptionKey[]>();
  for (const keyId of ENCRYPTION_KEY_IDS) {
    encryption.set(keyId, [{ version: 1, key: newSymmetricKey() }]);
  }
  const mac = new Map<MacPurpose, Uint8Array>();
  for (const purpose of MAC_PURPOSES) mac.set(purpose, randomId(HMAC_BYTES));
  // 別名を導く鍵は、どの MAC の用途の鍵とも別にする（CAP-05、ADR 0005）。
  const aliasDerive = randomId(HMAC_BYTES);
  const pair = generateEs256KeyPair();
  const kid = toBase64Url(randomId(16));
  const idToken: SigningKey = {
    alg: 'ES256',
    kid,
    privateKey: pair.privateKey,
    publicKey: Object.freeze({
      kid,
      kty: 'EC',
      crv: 'P-256',
      x: pair.publicJwk.x,
      y: pair.publicJwk.y,
      alg: 'ES256',
      use: 'sig',
    }),
  };
  // relay の DKIM と ARC の鍵（ADR 0021）。ID トークンの鍵とは別に作る。
  const rsa = generateRsa2048KeyPair();
  const dkimKid = toBase64Url(randomId(16));
  const dkim: SigningKey = {
    alg: 'RS256',
    kid: dkimKid,
    privateKey: rsa.privateKey,
    publicKey: Object.freeze({ kid: dkimKid, kty: 'RSA', spki: toBase64Url(rsa.spki) }),
  };
  const signing: Readonly<Record<SigningKeyId, SigningKey>> = Object.freeze({
    id_token: idToken,
    dkim,
  });

  const versions = (keyId: EncryptionKeyId): readonly EncryptionKey[] => {
    const list = encryption.get(keyId);
    if (list === undefined || list.length === 0) throw new Error('鍵がない');
    return list;
  };

  return Object.freeze({
    primary(keyId: EncryptionKeyId) {
      const list = versions(keyId);
      return list[list.length - 1] as EncryptionKey;
    },
    byVersion(keyId: EncryptionKeyId, version: number) {
      return versions(keyId).find((k) => k.version === version);
    },
    macKey(purpose: MacPurpose) {
      const key = mac.get(purpose);
      if (key === undefined) throw new Error('鍵がない');
      return key;
    },
    aliasDeriveKey() {
      return aliasDerive;
    },
    signingKey(keyId: SigningKeyId) {
      const key = signing[keyId];
      if (key === undefined) throw new Error('鍵がない');
      return key;
    },
    publicKeys(keyId: SigningKeyId) {
      const key = signing[keyId];
      if (key === undefined) throw new Error('鍵がない');
      return Object.freeze([key.publicKey]);
    },
  });
}
