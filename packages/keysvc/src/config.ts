// 起動時の設定（標準入力の1行目の JSON）の検査（ADR 0013）。
//
// - credentials のキーは、ちょうど idp、relay、company-api の3つ。知らないキー（sender など）、足りないキー、
//   配列の形は拒否する。3つの値はどれも違う。これで「decrypt の ACL を持つ資格情報は relay の1つだけ」
//   （不変条件3）を、形として強制する。
// - socketDir は、絶対パスで、実在するディレクトリで、持ち主がこのプロセスの利用者で、group と other の権限がない。
// - 失敗の理由は固定の語だけにし、値を入れない（不変条件4）。

import { lstatSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { constantTimeEqual, fromBase64Url } from '@pii-token-vault/warifu-core';
import {
  CREDENTIAL_SECRET_BYTES,
  KEYSVC_CALLERS,
  KEYSVC_SOCKET_NAME,
  type KeysvcCaller,
} from '@pii-token-vault/warifu-core/keys/protocol';

export interface KeysvcConfig {
  readonly version: 1;
  readonly socketDir: string;
  readonly credentials: Readonly<Record<KeysvcCaller, Uint8Array>>;
}

export type KeysvcConfigReason =
  | 'too_large'
  | 'not_json'
  | 'shape'
  | 'version'
  | 'credentials_keys'
  | 'credential_format'
  | 'credential_duplicate'
  | 'socket_dir';

export class KeysvcConfigError extends Error {
  readonly reason: KeysvcConfigReason;

  constructor(reason: KeysvcConfigReason) {
    super('鍵サービスの設定が違う');
    this.name = 'KeysvcConfigError';
    this.reason = reason;
  }
}

/** 設定の1行の上限（バイト）。 */
export const CONFIG_MAX_BYTES = 65_536;
// sun_path の108バイトから、終端の1バイトを引いた値。
const MAX_SOCKET_PATH_BYTES = 107;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, i) => key === expected[i]);
}

export function parseKeysvcConfig(text: string): KeysvcConfig {
  if (typeof text !== 'string' || Buffer.byteLength(text) > CONFIG_MAX_BYTES) {
    throw new KeysvcConfigError('too_large');
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new KeysvcConfigError('not_json');
  }
  if (!isPlainObject(raw) || !sameKeys(raw, ['version', 'socketDir', 'credentials'])) {
    throw new KeysvcConfigError('shape');
  }
  if (raw.version !== 1) throw new KeysvcConfigError('version');
  if (typeof raw.socketDir !== 'string') throw new KeysvcConfigError('socket_dir');
  const credentials = raw.credentials;
  if (!isPlainObject(credentials) || !sameKeys(credentials, KEYSVC_CALLERS)) {
    throw new KeysvcConfigError('credentials_keys');
  }
  const decoded = {} as Record<KeysvcCaller, Uint8Array>;
  for (const caller of KEYSVC_CALLERS) {
    const value = credentials[caller];
    let secret: Uint8Array;
    try {
      secret = fromBase64Url(typeof value === 'string' ? value : '');
    } catch {
      throw new KeysvcConfigError('credential_format');
    }
    if (secret.byteLength !== CREDENTIAL_SECRET_BYTES) {
      throw new KeysvcConfigError('credential_format');
    }
    decoded[caller] = secret;
  }
  for (let i = 0; i < KEYSVC_CALLERS.length; i += 1) {
    for (let j = i + 1; j < KEYSVC_CALLERS.length; j += 1) {
      const a = decoded[KEYSVC_CALLERS[i] as KeysvcCaller];
      const b = decoded[KEYSVC_CALLERS[j] as KeysvcCaller];
      if (constantTimeEqual(a, b)) throw new KeysvcConfigError('credential_duplicate');
    }
  }
  return Object.freeze({
    version: 1,
    socketDir: raw.socketDir,
    credentials: Object.freeze(decoded),
  });
}

/** ソケットのディレクトリを確かめ、ソケットのパスを返す。 */
export function checkSocketDir(socketDir: string): string {
  if (!socketDir.startsWith('/') || resolve(socketDir) !== socketDir || socketDir.includes('\0')) {
    throw new KeysvcConfigError('socket_dir');
  }
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(socketDir);
  } catch {
    throw new KeysvcConfigError('socket_dir');
  }
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) {
    throw new KeysvcConfigError('socket_dir');
  }
  const socketPath = join(socketDir, KEYSVC_SOCKET_NAME);
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH_BYTES) {
    throw new KeysvcConfigError('socket_dir');
  }
  return socketPath;
}
