// 鍵サービスのクライアントの例外。メッセージは code ごとの固定文にし、応答の本文や入力の値を入れない（不変条件4）。

export type KeysvcErrorCode =
  | 'forbidden'
  | 'invalid_request'
  | 'decrypt_failed'
  | 'unavailable'
  | 'internal';

const MESSAGES: Readonly<Record<KeysvcErrorCode, string>> = Object.freeze({
  forbidden: '鍵サービスが操作を拒否した',
  invalid_request: '鍵サービスへの要求の形が違う',
  decrypt_failed: '復号できなかった',
  unavailable: '鍵サービスにつながらない',
  internal: '鍵サービスの内部のエラー',
});

export class KeysvcError extends Error {
  readonly code: KeysvcErrorCode;

  constructor(code: KeysvcErrorCode) {
    super(MESSAGES[code]);
    this.name = 'KeysvcError';
    this.code = code;
  }
}
