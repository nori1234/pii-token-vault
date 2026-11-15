// rp-kit のエラー（ADR 0029 の O-108）。メッセージにも属性にも、受け取った値（トークン、ID、URL）を入れない
// （不変条件4 を、企業の側のコードにも当てる。spec 02 の「企業側のログ」）。

export type RpKitErrorCode =
  /** 設定が違う（起動のときに分かる）。 */
  | 'invalid_config'
  /** 送る先が、設定した割符のオリジンではない。 */
  | 'forbidden_destination'
  /** 通信の関数が失敗した、または 3xx などの、扱わない応答が返った。 */
  | 'unavailable'
  /** 割符が要求を断った（4xx）。reason に、割符が返した固定の理由（error の値）だけを入れる。 */
  | 'rejected'
  /** 応答の形が違う。 */
  | 'invalid_response'
  /** state、nonce、署名、iss、aud、typ、期限、用途、対象などの検証に通らない。 */
  | 'verification_failed'
  /** 同じ jti の承認を、もう一度使おうとした。 */
  | 'replayed';

export class RpKitError extends Error {
  readonly code: RpKitErrorCode;
  /** 割符が返した error の値（英小文字と _ だけのときに限る）。 */
  readonly reason: string | undefined;

  constructor(code: RpKitErrorCode, reason?: string) {
    super(`rp-kit: ${code}`);
    this.name = 'RpKitError';
    this.code = code;
    this.reason = reason !== undefined && /^[a-z_]{1,64}$/.test(reason) ? reason : undefined;
  }
}
