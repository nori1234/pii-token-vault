// relay の内部配送 API のクライアント（ADR 0021）。idp だけが使う。
// 資格情報は `idp.<32バイトの base64url>`。時間切れは5秒、再試行はしない。応答の本文を例外に入れない（不変条件4）。

import { isUuid } from '../ids.ts';
import { UdsError, udsPost } from '../internal/uds-client.ts';
import {
  DELIVERY_LIMITS,
  type DeliveryRequest,
  RELAY_DELIVER_PATH,
  VERIFY_CODE_PATTERN,
} from './protocol.ts';

export type RelayDeliveryErrorCode = 'invalid_request' | 'forbidden' | 'unavailable';

export class RelayDeliveryError extends Error {
  readonly code: RelayDeliveryErrorCode;

  constructor(code: RelayDeliveryErrorCode) {
    super('relay の内部配送 API の呼び出しが失敗した');
    this.name = 'RelayDeliveryError';
    this.code = code;
  }
}

export interface RelayDeliveryConnection {
  readonly socketPath: string;
  /** `idp.<32バイトの base64url>`。 */
  readonly credential: string;
}

export interface RelayDeliveryClient {
  deliver(request: DeliveryRequest): Promise<void>;
}

const CREDENTIAL_PATTERN = /^idp\.[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();

function bodyOf(request: DeliveryRequest): Record<string, string> {
  if (request === null || typeof request !== 'object' || !isUuid(request.userId)) {
    throw new RelayDeliveryError('invalid_request');
  }
  switch (request.kind) {
    case 'email_verification':
      if (typeof request.code !== 'string' || !VERIFY_CODE_PATTERN.test(request.code)) {
        throw new RelayDeliveryError('invalid_request');
      }
      return { kind: request.kind, userId: request.userId, code: request.code };
    case 'email_changed_notice':
      return { kind: request.kind, userId: request.userId };
    default:
      throw new RelayDeliveryError('invalid_request');
  }
}

export function createRelayDeliveryClient(
  connection: RelayDeliveryConnection,
): RelayDeliveryClient {
  const credential = connection?.credential;
  if (typeof credential !== 'string' || !CREDENTIAL_PATTERN.test(credential)) {
    throw new RelayDeliveryError('forbidden');
  }
  const socketPath = connection.socketPath;
  return Object.freeze({
    async deliver(request: DeliveryRequest) {
      const body = encoder.encode(JSON.stringify(bodyOf(request)));
      let status: number;
      try {
        ({ status } = await udsPost({
          socketPath,
          path: RELAY_DELIVER_PATH,
          headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' },
          body,
          timeoutMs: DELIVERY_LIMITS.clientTimeoutMs,
          maxResponseBytes: DELIVERY_LIMITS.responseBodyBytes,
        }));
      } catch (error) {
        if (error instanceof UdsError) throw new RelayDeliveryError('unavailable');
        throw error;
      }
      if (status === 202) return;
      if (status === 400) throw new RelayDeliveryError('invalid_request');
      if (status === 401 || status === 403) throw new RelayDeliveryError('forbidden');
      throw new RelayDeliveryError('unavailable');
    },
  });
}
