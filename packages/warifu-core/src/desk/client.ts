// company-api の窓口の内部 API のクライアント（ADR 0026 の O-63）。idp だけが使う。
// 資格情報は `idp.<32バイトの base64url>`。時間切れは5秒、再試行はしない（呼び出し元が決める）。
// 応答の本文を例外に入れない（不変条件4）。

import { isUuid } from '../ids.ts';
import { UdsError, udsPost } from '../internal/uds-client.ts';
import {
  DESK_CHANGE_STATES,
  DESK_EXTERNAL_ID_PATTERN,
  DESK_LIMITS,
  DESK_PATHS,
  DESK_REQUEST_ID_PATTERN,
  type DeskApproveRequest,
  type DeskCancelRequest,
  type DeskChangeState,
  type DeskOp,
  type DeskStatusItem,
  type DeskStatusRequest,
} from './protocol.ts';

export type DeskClientErrorCode = 'invalid_request' | 'forbidden' | 'unavailable';

export class DeskClientError extends Error {
  readonly code: DeskClientErrorCode;

  constructor(code: DeskClientErrorCode) {
    super('company-api の窓口の内部 API の呼び出しが失敗した');
    this.name = 'DeskClientError';
    this.code = code;
  }
}

export interface DeskConnection {
  readonly socketPath: string;
  /** `idp.<32バイトの base64url>`。 */
  readonly credential: string;
}

export type DeskApproveResult =
  | { readonly ok: true; readonly changeId: string }
  | { readonly ok: false; readonly reason: 'conflict' | 'not_found' };

export type DeskCancelResult =
  | { readonly ok: true; readonly state: DeskChangeState }
  | { readonly ok: false; readonly reason: 'closed' | 'not_found' };

export interface DeskClient {
  approve(request: DeskApproveRequest): Promise<DeskApproveResult>;
  status(request: DeskStatusRequest): Promise<readonly DeskStatusItem[]>;
  cancel(request: DeskCancelRequest): Promise<DeskCancelResult>;
}

const CREDENTIAL_PATTERN = /^idp\.[A-Za-z0-9_-]{43}$/;
const ISO_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const encoder = new TextEncoder();

function isState(value: unknown): value is DeskChangeState {
  return typeof value === 'string' && (DESK_CHANGE_STATES as readonly string[]).includes(value);
}

function errorOf(body: Uint8Array): string | undefined {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(body).toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const error = (parsed as Record<string, unknown>).error;
      return typeof error === 'string' ? error : undefined;
    }
  } catch {
    // 下で undefined。
  }
  return undefined;
}

function jsonOf(body: Uint8Array): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(body).toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // 下で unavailable にする。
  }
  throw new DeskClientError('unavailable');
}

export function createDeskClient(connection: DeskConnection): DeskClient {
  const credential = connection?.credential;
  if (typeof credential !== 'string' || !CREDENTIAL_PATTERN.test(credential)) {
    throw new DeskClientError('forbidden');
  }
  const socketPath = connection.socketPath;

  async function call(op: DeskOp, body: object): Promise<{ status: number; body: Uint8Array }> {
    let response: { status: number; body: Uint8Array };
    try {
      response = await udsPost({
        socketPath,
        path: DESK_PATHS[op],
        headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' },
        body: encoder.encode(JSON.stringify(body)),
        timeoutMs: DESK_LIMITS.clientTimeoutMs,
        maxResponseBytes: DESK_LIMITS.responseBodyBytes,
      });
    } catch (error) {
      if (error instanceof UdsError) throw new DeskClientError('unavailable');
      throw error;
    }
    if (response.status === 400) throw new DeskClientError('invalid_request');
    if (response.status === 401 || response.status === 403) {
      throw new DeskClientError('forbidden');
    }
    return response;
  }

  return Object.freeze({
    async approve(request: DeskApproveRequest): Promise<DeskApproveResult> {
      if (
        !isUuid(request?.tenantId) ||
        !isUuid(request.userId) ||
        !isUuid(request.changeRef) ||
        typeof request.requestId !== 'string' ||
        !DESK_REQUEST_ID_PATTERN.test(request.requestId) ||
        request.action !== 'desk.case.create'
      ) {
        throw new DeskClientError('invalid_request');
      }
      const response = await call('approve', {
        tenantId: request.tenantId,
        userId: request.userId,
        changeRef: request.changeRef,
        requestId: request.requestId,
        action: request.action,
      });
      if (response.status === 200) {
        const { changeId } = jsonOf(response.body);
        if (typeof changeId === 'string' && DESK_EXTERNAL_ID_PATTERN.test(changeId)) {
          return { ok: true, changeId };
        }
        throw new DeskClientError('unavailable');
      }
      if (response.status === 409 && errorOf(response.body) === 'conflict') {
        return { ok: false, reason: 'conflict' };
      }
      if (response.status === 404) return { ok: false, reason: 'not_found' };
      throw new DeskClientError('unavailable');
    },

    async status(request: DeskStatusRequest): Promise<readonly DeskStatusItem[]> {
      if (
        !isUuid(request?.userId) ||
        !Array.isArray(request.items) ||
        request.items.length > DESK_LIMITS.statusItems ||
        !request.items.every((item) => isUuid(item?.tenantId) && isUuid(item.changeRef))
      ) {
        throw new DeskClientError('invalid_request');
      }
      if (request.items.length === 0) return [];
      const response = await call('status', {
        userId: request.userId,
        items: request.items.map((item) => ({
          tenantId: item.tenantId,
          changeRef: item.changeRef,
        })),
      });
      if (response.status !== 200) throw new DeskClientError('unavailable');
      const { items } = jsonOf(response.body);
      if (!Array.isArray(items) || items.length !== request.items.length) {
        throw new DeskClientError('unavailable');
      }
      return items.map((raw: unknown, index): DeskStatusItem => {
        const item = (raw ?? {}) as Record<string, unknown>;
        const { changeRef, state, cancelDeadline } = item;
        if (
          typeof changeRef !== 'string' ||
          changeRef !== request.items[index]?.changeRef ||
          !(state === 'unknown' || isState(state)) ||
          !(
            cancelDeadline === null ||
            (typeof cancelDeadline === 'string' && ISO_PATTERN.test(cancelDeadline))
          )
        ) {
          throw new DeskClientError('unavailable');
        }
        return { changeRef, state, cancelDeadline };
      });
    },

    async cancel(request: DeskCancelRequest): Promise<DeskCancelResult> {
      if (!isUuid(request?.tenantId) || !isUuid(request.userId) || !isUuid(request.changeRef)) {
        throw new DeskClientError('invalid_request');
      }
      const response = await call('cancel', {
        tenantId: request.tenantId,
        userId: request.userId,
        changeRef: request.changeRef,
      });
      if (response.status === 200) {
        const { state } = jsonOf(response.body);
        if (isState(state)) return { ok: true, state };
        throw new DeskClientError('unavailable');
      }
      if (response.status === 409 && errorOf(response.body) === 'closed') {
        return { ok: false, reason: 'closed' };
      }
      if (response.status === 404) return { ok: false, reason: 'not_found' };
      throw new DeskClientError('unavailable');
    },
  });
}
