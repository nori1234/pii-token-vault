// 割符の内部の Unix ドメインソケットへの HTTP の POST（ADR 0012）。
//
// node:http の request を import してよいのは、このファイルだけ（biome.json の overrides の例外。t08-key-client-surface で
// 固定する）。不変条件7が塞ぐのは外部への接続で、割符の内部の接続（サービスから鍵サービスへ）は当たらない
// （spec 04 4章）。それでも、外へつながる口を作らないために、次のようにする。
// - 受け取るのはソケットのパスだけ。request に渡すのは socketPath、path、method、headers、timeout だけにする。
//   ホスト名、ポート、名前解決、エージェント、接続の関数を渡す口はない。
// - ソケットは、名前が閉じた一覧（INTERNAL_SOCKET_NAMES）にあり、このプロセスの利用者が持ち、親のディレクトリに
//   group と other の権限がないものだけ。パスは起動時の設定から来て、要求の中身（テナントや利用者の入力）からは来ない。

import { lstat } from 'node:fs/promises';
import { request } from 'node:http';
import { basename, dirname, resolve } from 'node:path';

/** 割符の内部のソケットの名前。閉じた一覧（M4 で relay の内部配送 API、M5 で sender を足す見込み）。 */
export const INTERNAL_SOCKET_NAMES: readonly string[] = Object.freeze(['keysvc.sock']);

export interface UdsPostInput {
  readonly socketPath: string;
  /** /v1/<小文字と _ の32文字まで> だけ。 */
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

export interface UdsResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

export type UdsErrorCode =
  | 'invalid_socket'
  | 'invalid_path'
  | 'unavailable'
  | 'timeout'
  | 'too_large';

const MESSAGES: Readonly<Record<UdsErrorCode, string>> = Object.freeze({
  invalid_socket: '内部のソケットの検査に通らない',
  invalid_path: '内部のソケットのパスの形が違う',
  unavailable: '内部のソケットにつながらない',
  timeout: '内部のソケットへの要求が時間切れになった',
  too_large: '内部のソケットからの応答が大きすぎる',
});

/** メッセージに値（パス、本文）を入れない。 */
export class UdsError extends Error {
  readonly code: UdsErrorCode;

  constructor(code: UdsErrorCode) {
    super(MESSAGES[code]);
    this.name = 'UdsError';
    this.code = code;
  }
}

const PATH_PATTERN = /^\/v1\/[a-z_]{1,32}$/;
// sun_path の108バイトから、終端の1バイトを引いた値。
const MAX_SOCKET_PATH_BYTES = 107;
const verified = new Set<string>();

async function checkSocket(socketPath: string): Promise<void> {
  if (verified.has(socketPath)) return;
  if (
    typeof socketPath !== 'string' ||
    !socketPath.startsWith('/') ||
    socketPath.includes('\0') ||
    resolve(socketPath) !== socketPath ||
    Buffer.byteLength(socketPath) > MAX_SOCKET_PATH_BYTES ||
    !INTERNAL_SOCKET_NAMES.includes(basename(socketPath))
  ) {
    throw new UdsError('invalid_socket');
  }
  const uid = process.getuid?.();
  try {
    const socket = await lstat(socketPath);
    const parent = await lstat(dirname(socketPath));
    if (
      !socket.isSocket() ||
      socket.uid !== uid ||
      !parent.isDirectory() ||
      parent.uid !== uid ||
      (parent.mode & 0o077) !== 0
    ) {
      throw new UdsError('invalid_socket');
    }
  } catch {
    throw new UdsError('invalid_socket');
  }
  verified.add(socketPath);
}

export async function udsPost(input: UdsPostInput): Promise<UdsResponse> {
  await checkSocket(input.socketPath);
  if (typeof input.path !== 'string' || !PATH_PATTERN.test(input.path)) {
    throw new UdsError('invalid_path');
  }
  return await new Promise<UdsResponse>((resolvePost, reject) => {
    let settled = false;
    const finish = (error: UdsError | undefined, response?: UdsResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (error !== undefined) {
        req.destroy();
        reject(error);
      } else if (response !== undefined) {
        resolvePost(response);
      }
    };
    const req = request(
      {
        socketPath: input.socketPath,
        path: input.path,
        method: 'POST',
        headers: { ...input.headers, 'content-length': String(input.body.byteLength) },
        timeout: input.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.byteLength;
          if (total > input.maxResponseBytes) {
            finish(new UdsError('too_large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          finish(undefined, {
            status: res.statusCode ?? 0,
            body: new Uint8Array(Buffer.concat(chunks)),
          });
        });
        res.on('error', () => finish(new UdsError('unavailable')));
      },
    );
    const deadline = setTimeout(() => finish(new UdsError('timeout')), input.timeoutMs);
    req.on('timeout', () => finish(new UdsError('timeout')));
    req.on('error', () => finish(new UdsError('unavailable')));
    req.end(input.body);
  });
}
