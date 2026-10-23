// テスト用のソフトウェアの認証器（WebAuthn）。ブラウザなしで、登録とログインの応答を作る。
// ADR 0007 の検査を確かめるために、attestation の形式、アルゴリズム、UV、userHandle を、わざと違えた応答も作れる。
// テストの中だけで使う（本体のコードから import しない）。

import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto';

type CborValue = number | string | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  if (length < 0x10000) return Buffer.from([(major << 5) | 25, length >> 8, length & 0xff]);
  const out = Buffer.alloc(5);
  out[0] = (major << 5) | 26;
  out.writeUInt32BE(length, 1);
  return out;
}

/** 必要な分だけの CBOR の符号化（整数、文字列、バイト列、配列、Map）。 */
export function cbor(value: CborValue): Buffer {
  if (typeof value === 'number') {
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.byteLength), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  const parts: Buffer[] = [head(5, value.size)];
  for (const [k, v] of value) parts.push(cbor(k), cbor(v));
  return Buffer.concat(parts);
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest();

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

export interface SoftCredential {
  readonly id: Uint8Array;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly userHandle: string;
  readonly rpId: string;
  signCount: number;
  readonly backupEligible: boolean;
}

export interface CreateOverrides {
  /** 'none' 以外にすると、x5c 付きの packed を作る（ADR 0007 の1）。 */
  readonly fmt?: 'none' | 'packed';
  /** 'EdDSA' にすると、Ed25519 の鍵（COSE -8）を登録しようとする（ADR 0007 の2）。 */
  readonly alg?: 'ES256' | 'EdDSA';
  readonly uv?: boolean;
  readonly backupEligible?: boolean;
  readonly origin?: string;
}

export interface GetOverrides {
  readonly uv?: boolean;
  /** userHandle を差し替える（持ち主と違う利用者を名乗る。ADR 0007 の3）。 */
  readonly userHandle?: string | null;
  readonly origin?: string;
}

interface CreationOptions {
  readonly challenge: string;
  readonly rp: { readonly id?: string };
  readonly user: { readonly id: string };
}

interface RequestOptions {
  readonly challenge: string;
  readonly rpId?: string;
}

export class SoftAuthenticator {
  readonly credentials: SoftCredential[] = [];
  readonly #origin: string;

  constructor(origin: string) {
    this.#origin = origin;
  }

  /** 登録の応答（RegistrationResponseJSON）。 */
  create(options: CreationOptions, overrides: CreateOverrides = {}): Record<string, unknown> {
    const rpId = options.rp.id ?? new URL(this.#origin).hostname;
    const alg = overrides.alg ?? 'ES256';
    const pair =
      alg === 'EdDSA'
        ? generateKeyPairSync('ed25519')
        : generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const coseKey =
      alg === 'EdDSA'
        ? new Map<CborValue, CborValue>([
            [1, 1],
            [3, -8],
            [-1, 6],
            [-2, Buffer.from(String(jwk.x), 'base64url')],
          ])
        : new Map<CborValue, CborValue>([
            [1, 2],
            [3, -7],
            [-1, 1],
            [-2, Buffer.from(String(jwk.x), 'base64url')],
            [-3, Buffer.from(String(jwk.y), 'base64url')],
          ]);
    const id = randomBytes(32);
    const backupEligible = overrides.backupEligible ?? true;
    const flags =
      FLAG_UP |
      (overrides.uv === false ? 0 : FLAG_UV) |
      (backupEligible ? FLAG_BE | FLAG_BS : 0) |
      FLAG_AT;
    const credLength = Buffer.alloc(2);
    credLength.writeUInt16BE(id.length);
    const authData = Buffer.concat([
      sha256(rpId),
      Buffer.from([flags]),
      Buffer.alloc(4),
      Buffer.alloc(16),
      credLength,
      id,
      cbor(coseKey),
    ]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin: overrides.origin ?? this.#origin,
        crossOrigin: false,
      }),
    );
    let attStmt = new Map<CborValue, CborValue>();
    let fmt = 'none';
    if (overrides.fmt === 'packed') {
      // 中身は検証に通らなくてよい（ライブラリに渡る前に拒否されることを確かめる）。
      fmt = 'packed';
      attStmt = new Map<CborValue, CborValue>([
        ['alg', -7],
        ['sig', randomBytes(64)],
        ['x5c', [randomBytes(64)]],
      ]);
    }
    const attestationObject = cbor(
      new Map<CborValue, CborValue>([
        ['fmt', fmt],
        ['attStmt', attStmt],
        ['authData', authData],
      ]),
    );
    if (alg === 'ES256') {
      this.credentials.push({
        id,
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
        userHandle: options.user.id,
        rpId,
        signCount: 0,
        backupEligible,
      });
    }
    return {
      id: b64(id),
      rawId: b64(id),
      type: 'public-key',
      response: {
        clientDataJSON: b64(clientDataJSON),
        attestationObject: b64(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  /** ログインの応答（AuthenticationResponseJSON）。credential を省くと、最後に作ったものを使う。 */
  get(
    options: RequestOptions,
    credential: SoftCredential | undefined = this.credentials.at(-1),
    overrides: GetOverrides = {},
  ): Record<string, unknown> {
    if (credential === undefined) throw new Error('資格情報がない');
    credential.signCount += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(credential.signCount);
    const flags =
      FLAG_UP |
      (overrides.uv === false ? 0 : FLAG_UV) |
      (credential.backupEligible ? FLAG_BE | FLAG_BS : 0);
    const authData = Buffer.concat([
      sha256(options.rpId ?? credential.rpId),
      Buffer.from([flags]),
      counter,
    ]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin: overrides.origin ?? this.#origin,
        crossOrigin: false,
      }),
    );
    const signature = sign(
      'sha256',
      Buffer.concat([authData, sha256(clientDataJSON)]),
      credential.privateKey,
    );
    const userHandle =
      overrides.userHandle === undefined ? credential.userHandle : overrides.userHandle;
    return {
      id: b64(credential.id),
      rawId: b64(credential.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64(clientDataJSON),
        authenticatorData: b64(authData),
        signature: b64(signature),
        ...(userHandle === null ? {} : { userHandle }),
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}
