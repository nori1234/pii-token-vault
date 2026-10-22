// 資格情報を付けて鍵サービスを呼ぶ（ADR 0012）。exports に載せない（各サービスのクライアントからだけ使う）。
// 汎用の call はここにだけあり、型を回避して呼ばれても、鍵サービスが能力の表で 403 を返す（二重の守り）。
// 時間切れは2秒、再試行はしない。応答の本文を例外に入れない（不変条件4）。

import { fromBase64Url, toBase64Url } from '../encoding.ts';
import { UdsError, udsPost } from '../internal/uds-client.ts';
import { KeysvcError } from './errors.ts';
import {
  CREDENTIAL_SECRET_BYTES,
  ERROR_BODY,
  type KeysvcCaller,
  type KeysvcConnection,
  type KeysvcOp,
  LIMITS,
} from './protocol.ts';

export type KeysvcCall = (
  op: KeysvcOp,
  body: Readonly<Record<string, unknown>>,
) => Promise<unknown>;

/** 工場関数に渡された資格情報が、そのサービスのものでないとき。値を入れない。 */
export class KeysvcCredentialError extends Error {
  constructor() {
    super('鍵サービスの資格情報が、このサービスのものではない');
    this.name = 'KeysvcCredentialError';
  }
}

const decoder = new TextDecoder();

export function createTransport(connection: KeysvcConnection, service: KeysvcCaller): KeysvcCall {
  const credential = connection?.credential;
  const prefix = `${service}.`;
  if (typeof credential !== 'string' || !credential.startsWith(prefix)) {
    throw new KeysvcCredentialError();
  }
  try {
    if (fromBase64Url(credential.slice(prefix.length)).byteLength !== CREDENTIAL_SECRET_BYTES) {
      throw new KeysvcCredentialError();
    }
  } catch {
    throw new KeysvcCredentialError();
  }
  const socketPath = connection.socketPath;
  const headers = Object.freeze({
    authorization: `Bearer ${credential}`,
    'content-type': 'application/json',
  });

  return async (op, body) => {
    let response: { status: number; body: Uint8Array };
    try {
      response = await udsPost({
        socketPath,
        path: `/v1/${op}`,
        headers,
        body: new TextEncoder().encode(JSON.stringify(body)),
        timeoutMs: LIMITS.clientTimeoutMs,
        maxResponseBytes: LIMITS.responseBodyBytes,
      });
    } catch (error) {
      if (error instanceof UdsError) throw new KeysvcError('unavailable');
      throw new KeysvcError('internal');
    }
    switch (response.status) {
      case 200:
        try {
          return JSON.parse(decoder.decode(response.body)) as unknown;
        } catch {
          throw new KeysvcError('internal');
        }
      case 403:
        throw new KeysvcError('forbidden');
      case 400:
        throw new KeysvcError(
          decoder.decode(response.body) === ERROR_BODY.decrypt_failed
            ? 'decrypt_failed'
            : 'invalid_request',
        );
      case 500:
        throw new KeysvcError('internal');
      default:
        throw new KeysvcError('unavailable');
    }
  };
}

// 応答の形の検査。違えば internal（鍵サービスの誤りか、なりすまし）。

function field(response: unknown, name: string): unknown {
  if (response === null || typeof response !== 'object' || Array.isArray(response)) {
    throw new KeysvcError('internal');
  }
  return (response as Record<string, unknown>)[name];
}

export function bytesFrom(response: unknown, name: string, length?: number): Uint8Array {
  const value = field(response, name);
  if (typeof value !== 'string') throw new KeysvcError('internal');
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch {
    throw new KeysvcError('internal');
  }
  if (length !== undefined && bytes.byteLength !== length) throw new KeysvcError('internal');
  return bytes;
}

export function stringFrom(response: unknown, name: string, pattern: RegExp): string {
  const value = field(response, name);
  if (typeof value !== 'string' || !pattern.test(value)) throw new KeysvcError('internal');
  return value;
}

export function arrayFrom(response: unknown, name: string): readonly unknown[] {
  const value = field(response, name);
  if (!Array.isArray(value)) throw new KeysvcError('internal');
  return value;
}

export function encodeBytes(bytes: Uint8Array, max: number): string {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > max) {
    throw new KeysvcError('invalid_request');
  }
  return toBase64Url(bytes);
}

/** クライアントの型にない用途を、呼ぶ前に止める（型を回避された場合の備え。鍵サービスも 403 を返す）。 */
export function assertOneOf<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new KeysvcError('forbidden');
  }
  return value as T;
}

export const MAC_BYTES = 32;
export const ES256_SIGNATURE_BYTES = 64;
