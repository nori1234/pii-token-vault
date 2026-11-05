// 鍵サービス（packages/keysvc）とクライアントが共有する約束：操作、鍵、用途の名前、要求と応答の型、上限、エラーの本文。
// 名前を足すときは、keysvc の acl.ts、各クライアントの型、t08-keysvc-acl と t08-key-client-surface の期待の表を
// 同じ PR で直す（ADR 0013）。

/** 鍵サービスの資格情報を持つサービス。sender、rp-kit、demo-rp は持たない（plan 8章）。 */
export type KeysvcCaller = 'idp' | 'relay' | 'company-api';
export const KEYSVC_CALLERS: readonly KeysvcCaller[] = Object.freeze([
  'idp',
  'relay',
  'company-api',
]);

export type KeysvcOp = 'encrypt' | 'decrypt' | 'mac' | 'derive_alias' | 'sign' | 'public_keys';
export const KEYSVC_OPS: readonly KeysvcOp[] = Object.freeze([
  'encrypt',
  'decrypt',
  'mac',
  'derive_alias',
  'sign',
  'public_keys',
]);

/** 保存用の鍵（AES-256-GCM）。 */
export type EncryptionKeyId = 'contact' | 'relay_queue';
export const ENCRYPTION_KEY_IDS: readonly EncryptionKeyId[] = Object.freeze([
  'contact',
  'relay_queue',
]);

/** MAC の用途。用途ごとに独立した鍵を持つ（HMAC-SHA-256）。使うマイルストーンで足す。 */
export type MacPurpose =
  | 'alias_lookup'
  | 'audit_chain'
  | 'pairwise_sub'
  | 'oidc_storage_id'
  | 'email_verify_code'
  | 'approval_challenge'
  | 'desk_id'
  | 'desk_lookup'
  | 'relay_replay'
  | 'relay_thread'
  | 'message_id';
export const MAC_PURPOSES: readonly MacPurpose[] = Object.freeze([
  'alias_lookup',
  'audit_chain',
  'pairwise_sub',
  'oidc_storage_id',
  'email_verify_code',
  'approval_challenge',
  'desk_id',
  'desk_lookup',
  'relay_replay',
  'relay_thread',
  'message_id',
]);

/**
 * 署名の鍵。id_token は ES256。dkim は relay の DKIM と ARC の署名の鍵（RSA 2048、rsa-sha256。不変条件9の
 * プロトコルの例外。ADR 0021）。tenant_jwt（企業向け API のアクセストークン）と set（企業に送る SET）は
 * company-api の ES256 の鍵（ADR 0022）。op_approval は idp の操作ごとの承認の ES256 の鍵（ADR 0026）。
 */
export type SigningKeyId = 'id_token' | 'dkim' | 'tenant_jwt' | 'set' | 'op_approval';
export const SIGNING_KEY_IDS: readonly SigningKeyId[] = Object.freeze([
  'id_token',
  'dkim',
  'tenant_jwt',
  'set',
  'op_approval',
]);

/** RSA 2048 の署名の長さ（バイト）。 */
export const RSA2048_SIGNATURE_BYTES = 256;

/** 利用者 U の本物のメール。U の文脈でしか復号できない（AAD に入れる）。 */
export interface ContactContext {
  readonly field: 'email';
  readonly user_id: string;
}

/** 配送キューの1件（M4 で見直す）。 */
export interface QueueContext {
  readonly queue_item_id: string;
}

export interface EncryptionContextOf {
  readonly contact: ContactContext;
  readonly relay_queue: QueueContext;
}

export interface Es256PublicJwk {
  readonly kid: string;
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly alg: 'ES256';
  readonly use: 'sig';
}

/** DKIM の公開鍵。spki は SubjectPublicKeyInfo の DER を base64url にしたもの（DNS の p= に載せる値の元）。 */
export interface DkimPublicKey {
  readonly kid: string;
  readonly kty: 'RSA';
  readonly spki: string;
}

/** 鍵サービスのソケットのファイル名。 */
export const KEYSVC_SOCKET_NAME = 'keysvc.sock';

/** サービスの資格情報の秘密の長さ（バイト）。 */
export const CREDENTIAL_SECRET_BYTES = 32;

export const LIMITS = Object.freeze({
  requestBodyBytes: 16_384,
  plaintextBytes: 4096,
  macMessageBytes: 4096,
  signMessageBytes: 8192,
  clientTimeoutMs: 2000,
  responseBodyBytes: 16_384,
} as const);

export type KeysvcErrorBody =
  | 'not_found'
  | 'too_large'
  | 'forbidden'
  | 'invalid_request'
  | 'decrypt_failed'
  | 'internal';

/** エラーの本文。理由によらず、同じ種類のエラーはバイト単位で同じ本文にする（入力の値を入れない）。 */
export const ERROR_BODY: Readonly<Record<KeysvcErrorBody, string>> = Object.freeze({
  not_found: '{"error":"not_found"}',
  too_large: '{"error":"too_large"}',
  forbidden: '{"error":"forbidden"}',
  invalid_request: '{"error":"invalid_request"}',
  decrypt_failed: '{"error":"decrypt_failed"}',
  internal: '{"error":"internal"}',
});

// 要求と応答（本文は JSON。バイト列は base64url）。
export interface EncryptRequest<K extends EncryptionKeyId = EncryptionKeyId> {
  readonly keyId: K;
  readonly plaintext: string;
  readonly context: EncryptionContextOf[K];
}
export interface EncryptResponse {
  readonly ciphertext: string;
}
export interface DecryptRequest<K extends EncryptionKeyId = EncryptionKeyId> {
  readonly keyId: K;
  readonly ciphertext: string;
  readonly context: EncryptionContextOf[K];
}
export interface DecryptResponse {
  readonly plaintext: string;
}
export interface MacRequest {
  readonly purpose: MacPurpose;
  readonly message: string;
}
export interface MacResponse {
  readonly mac: string;
}
export interface DeriveAliasRequest {
  readonly tenantId: string;
  readonly userId: string;
  readonly generation: number;
}
export interface DeriveAliasResponse {
  readonly localPart: string;
}
export interface SignRequest {
  readonly keyId: SigningKeyId;
  readonly message: string;
}
export interface SignResponse {
  readonly kid: string;
  readonly signature: string;
}
export interface PublicKeysRequest {
  readonly keyId: SigningKeyId;
}
export interface PublicKeysResponse {
  readonly keys: readonly Es256PublicJwk[];
}

/** 別名の世代の上限（PostgreSQL の integer）。 */
export const MAX_ALIAS_GENERATION = 2_147_483_647;

/** 鍵サービスへのつなぎ方。起動時の設定からだけ渡す（要求の中身から作らない）。 */
export interface KeysvcConnection {
  /** 絶対パス。basename は KEYSVC_SOCKET_NAME。 */
  readonly socketPath: string;
  /** `<service>.<32バイトの base64url>`。工場関数は service の部分が自分と一致することを確かめる。 */
  readonly credential: string;
}
