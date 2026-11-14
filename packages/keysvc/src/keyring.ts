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
  MAX_MAC_KEY_VERSIONS,
  type MacPurpose,
  type SigningKeyId,
  VERSIONED_MAC_PURPOSES,
  type VersionedMacPurpose,
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

export interface VersionedMacKey {
  readonly version: number;
  readonly key: Uint8Array;
}

export function isVersionedMacPurpose(purpose: unknown): purpose is VersionedMacPurpose {
  return VERSIONED_MAC_PURPOSES.some((known) => known === purpose);
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
  /** 版を持たない用途の鍵。版を持つ用途には使わない（throw する）。 */
  macKey(purpose: MacPurpose): Uint8Array;
  /** 版を持つ用途の、いまの版（最新）。 */
  latestMacKey(purpose: VersionedMacPurpose): VersionedMacKey;
  /** 版を持つ用途の、指定した版。なければ undefined。 */
  macKeyByVersion(purpose: VersionedMacPurpose, version: number): VersionedMacKey | undefined;
  /** 版を持つ用途の、持っているすべての版（古い順）。 */
  macKeyVersions(purpose: VersionedMacPurpose): readonly VersionedMacKey[];
  /**
   * 版を持つ用途に、新しい版を足す（入れ替え。ADR 0028 の O-87）。古い版は消さない。
   * 上限（MAX_MAC_KEY_VERSIONS）に達していれば足さずに false を返す。鍵を返す操作ではない。
   */
  rotateVersionedMacKeys(): boolean;
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
  const versionedMac = new Map<VersionedMacPurpose, VersionedMacKey[]>();
  for (const purpose of MAC_PURPOSES) {
    if (isVersionedMacPurpose(purpose)) {
      versionedMac.set(purpose, [{ version: 1, key: randomId(HMAC_BYTES) }]);
    } else {
      mac.set(purpose, randomId(HMAC_BYTES));
    }
  }
  // 別名を導く鍵は、どの MAC の用途の鍵とも別にする（CAP-05、ADR 0005）。
  const aliasDerive = randomId(HMAC_BYTES);
  // ES256 の鍵は用途ごとに別に作る（ID トークン、テナントの JWT、SET、操作ごとの承認。ADR 0014、ADR 0022、ADR 0026）。
  const es256 = (): SigningKey => {
    const pair = generateEs256KeyPair();
    const kid = toBase64Url(randomId(16));
    return {
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
  };
  const idToken = es256();
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
    tenant_jwt: es256(),
    set: es256(),
    op_approval: es256(),
    initial_link: es256(),
  });

  const macVersions = (purpose: VersionedMacPurpose): VersionedMacKey[] => {
    const list = versionedMac.get(purpose);
    if (list === undefined || list.length === 0) throw new Error('鍵がない');
    return list;
  };

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
    latestMacKey(purpose: VersionedMacPurpose) {
      const list = macVersions(purpose);
      return list[list.length - 1] as VersionedMacKey;
    },
    macKeyByVersion(purpose: VersionedMacPurpose, version: number) {
      return macVersions(purpose).find((k) => k.version === version);
    },
    macKeyVersions(purpose: VersionedMacPurpose) {
      return Object.freeze([...macVersions(purpose)]);
    },
    rotateVersionedMacKeys() {
      // 用途ごとに版の数は同じにそろえる（上限の判定を1つにする）。
      const first = macVersions(VERSIONED_MAC_PURPOSES[0] as VersionedMacPurpose);
      if (first.length >= MAX_MAC_KEY_VERSIONS) return false;
      for (const purpose of VERSIONED_MAC_PURPOSES) {
        const list = macVersions(purpose);
        const last = list[list.length - 1] as VersionedMacKey;
        list.push({ version: last.version + 1, key: randomId(HMAC_BYTES) });
      }
      return true;
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
