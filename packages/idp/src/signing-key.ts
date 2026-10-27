// ID トークンの署名を、鍵サービスで行う外部鍵（ADR 0014、ADR 0018）。
//
// oidc-provider 9.12.2 の ExternalSigningKey（features.externalSigningSupport、experimental-01）を使う。
// - 秘密鍵は鍵サービスの外に出さない。idp は sign('id_token', …) を呼ぶだけ。
// - 公開鍵の座標（kty、crv、x、y）は getter で返す。基底クラスは keyObject() から作るが、それには node:crypto の
//   KeyObject が要る（idp では import できない。不変条件9の lint）。keyObject() を呼ぶのは、自分が出した JWT を
//   検証する経路（id_token_hint、ログアウト）だけで、M3 ではどれも無効にしている。
// - 鍵は oidc-provider を作るときに固定される。鍵サービスの鍵を入れ替えたら、idp を作り直す（再起動する）。
//   署名の直前に入れ替わっていたら、JWS のヘッダーの kid と食い違うので、署名を返さずに止める。

import type { Es256PublicJwk } from '@pii-token-vault/warifu-core/keys/protocol';
import { ExternalSigningKey } from 'oidc-provider';

export interface IdTokenSigner {
  sign(
    keyId: 'id_token',
    message: Uint8Array,
  ): Promise<{ readonly kid: string; readonly signature: Uint8Array }>;
  publicKeys(keyId: 'id_token'): Promise<readonly Es256PublicJwk[]>;
}

export class KeyRotatedError extends Error {
  override name = 'KeyRotatedError';
}

export class KeysvcSigningKey extends ExternalSigningKey {
  readonly #jwk: Es256PublicJwk;
  readonly #signer: IdTokenSigner;

  constructor(jwk: Es256PublicJwk, signer: IdTokenSigner) {
    super();
    this.#jwk = jwk;
    this.#signer = signer;
    // @types/oidc-provider では読み取り専用だが、実装（lib/helpers/keystore.js）には setter がある。
    (this as { kid: string }).kid = jwk.kid;
    (this as { alg: string }).alg = 'ES256';
  }

  override get kty(): string {
    return this.#jwk.kty;
  }

  override get crv(): string {
    return this.#jwk.crv;
  }

  override get x(): string {
    return this.#jwk.x;
  }

  override get y(): string {
    return this.#jwk.y;
  }

  // EC の鍵には e、n、pub がない。基底クラスの getter は keyObject() を呼ぶので、ここで止める。
  override get e(): string {
    return undefined as unknown as string;
  }

  override get n(): string {
    return undefined as unknown as string;
  }

  override get pub(): string {
    return undefined as unknown as string;
  }

  override keyObject(): never {
    throw new Error('この鍵では検証しない');
  }

  override async sign(data: Buffer): Promise<Buffer> {
    const { kid, signature } = await this.#signer.sign('id_token', new Uint8Array(data));
    if (kid !== this.kid) throw new KeyRotatedError();
    return Buffer.from(signature);
  }
}

/**
 * 鍵サービスのいまの署名の鍵から、署名の鍵を作る。起動のときに1回呼ぶ。
 * 入れ替えの後は、公開鍵が複数返る（ADR 0014）。どれが署名に使われるかは、試しに署名して kid で確かめる。
 */
export async function loadSigningKey(signer: IdTokenSigner): Promise<KeysvcSigningKey> {
  const { kid } = await signer.sign('id_token', new Uint8Array([0]));
  const jwk = (await signer.publicKeys('id_token')).find((key) => key.kid === kid);
  if (jwk === undefined) throw new Error('署名に使う鍵の公開鍵がない');
  return new KeysvcSigningKey(jwk, signer);
}
