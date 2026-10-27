// relay の内部配送 API の約束（不変条件3、ADR 0021）。idp と relay が共有する。
//
// idp は本物のアドレスを持たない。送り先は利用者 ID と種類で指定し、relay がその利用者の範囲で暗号文を読み、
// 復号して送る。文面は relay の固定の文で、idp が渡すのは種類と、確認コード（宛先確認のときだけ）だけ。
// 旧アドレスへの知らせには、操作のリンクもコードも入れない（plan 4章）。

import type { WarifuUserId } from '../ids.ts';

/** relay の内部配送 API のソケットのファイル名。 */
export const RELAY_SOCKET_NAME = 'relay.sock';
export const RELAY_DELIVER_PATH = '/v1/deliver';

/** 内部配送 API を呼べるのは idp だけ（CAP-38）。 */
export type RelayCaller = 'idp';
export const RELAY_CALLERS: readonly RelayCaller[] = Object.freeze(['idp']);

export type DeliveryRequest =
  | {
      readonly kind: 'email_verification';
      readonly userId: WarifuUserId;
      /** 確認中のアドレス（contacts.email_pending）に送る8桁のコード。 */
      readonly code: string;
    }
  | {
      readonly kind: 'email_changed_notice';
      readonly userId: WarifuUserId;
    };

export const VERIFY_CODE_PATTERN = /^[0-9]{8}$/;

export const DELIVERY_LIMITS = Object.freeze({
  requestBodyBytes: 1024,
  responseBodyBytes: 256,
  clientTimeoutMs: 5000,
} as const);

/** エラーの本文。理由によらず、同じ種類のエラーはバイト単位で同じ本文にする。 */
export const DELIVERY_ERROR_BODY = Object.freeze({
  forbidden: '{"error":"forbidden"}',
  invalid_request: '{"error":"invalid_request"}',
  unavailable: '{"error":"unavailable"}',
  not_found: '{"error":"not_found"}',
} as const);
