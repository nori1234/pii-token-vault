// 鍵サービスのサーバー（ADR 0012）。Unix ドメインソケットだけで HTTP/1.1 を待ち受ける。TCP と UDP は開かない。
//
// 検査の順番：
//   1. メソッドが POST で、パスが /v1/<小文字と _ の32文字まで>        → 404 not_found
//   2. 本文を 16 KiB まで読む                                         → 413 too_large
//   3. 資格情報（auth.ts）                                            → 403 forbidden
//   4. (サービス, 操作) が能力の表にある（本文を解析する前）           → 403 forbidden
//   5. JSON として解析する                                            → 400 invalid_request
//   6. (サービス, 操作, 対象) が能力の表にある                         → 403 forbidden
//   7. 残りの項目の検査（ops.ts）                                     → 400 invalid_request
//   8. 実行。復号の失敗                                               → 400 decrypt_failed
//   それ以外                                                          → 500 internal
// 403 の本文とヘッダーは、理由によらずバイト単位で同じにする。入力の値は、応答にもログにも入れない。

import { chmodSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  ERROR_BODY,
  KEYSVC_OPS,
  type KeysvcCaller,
  type KeysvcErrorBody,
  type KeysvcOp,
  LIMITS,
} from '@pii-token-vault/warifu-core/keys/protocol';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import { ACL, allowedOp, allowedTarget } from './acl.ts';
import { createAuthenticator } from './auth.ts';
import { checkSocketDir, type KeysvcConfig } from './config.ts';
import { createKeyring } from './keyring.ts';
import { DecryptFailedError, InvalidRequestError, runOp, targetOf } from './ops.ts';

export interface KeysvcServer {
  readonly socketPath: string;
  close(): Promise<void>;
}

const PATH_PATTERN = /^\/v1\/([a-z_]{1,32})$/;
const KNOWN_TARGETS: ReadonlySet<unknown> = new Set(ACL.map(([, , target]) => target));

class TooLargeError extends Error {}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > LIMITS.requestBodyBytes) {
      reject(new TooLargeError());
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > LIMITS.requestBodyBytes) {
        req.removeAllListeners('data');
        reject(new TooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonObject(body: Buffer): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(body.toString('utf8'));
  } catch {
    throw new InvalidRequestError();
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new InvalidRequestError();
  }
  return value as Record<string, unknown>;
}

export async function startKeysvcServer(
  config: KeysvcConfig,
  logger: Logger,
): Promise<KeysvcServer> {
  const socketPath = checkSocketDir(config.socketDir);
  const keyring = createKeyring();
  const authenticate = createAuthenticator(config.credentials);

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const started = performance.now();
    let caller: KeysvcCaller | undefined;
    let op: KeysvcOp | undefined;
    let target: unknown;

    const send = (status: number, body: string): void => {
      res.sendDate = false;
      res.writeHead(status, {
        'content-type': 'application/json',
        'cache-control': 'no-store',
        'content-length': Buffer.byteLength(body),
      });
      res.end(body);
      logger.info({
        event: status === 403 ? 'keysvc.denied' : 'keysvc.request',
        service: caller ?? 'unknown',
        op: op ?? 'unknown',
        target: KNOWN_TARGETS.has(target) ? target : 'unknown',
        status,
        durationMs: Math.round(performance.now() - started),
      });
    };
    const fail = (status: number, error: KeysvcErrorBody): void => send(status, ERROR_BODY[error]);

    try {
      const match = req.method === 'POST' ? PATH_PATTERN.exec(req.url ?? '') : null;
      if (match === null) {
        req.resume();
        fail(404, 'not_found');
        return;
      }
      let body: Buffer;
      try {
        body = await readBody(req);
      } catch (error) {
        if (error instanceof TooLargeError) {
          res.shouldKeepAlive = false;
          fail(413, 'too_large');
          return;
        }
        throw error;
      }
      caller = authenticate(req.headers.authorization);
      if (caller === undefined) {
        fail(403, 'forbidden');
        return;
      }
      const name = match[1];
      op = KEYSVC_OPS.find((known) => known === name);
      if (op === undefined || !allowedOp(caller, op)) {
        fail(403, 'forbidden');
        return;
      }
      const parsed = parseJsonObject(body);
      target = targetOf(op, parsed);
      if (!allowedTarget(caller, op, target)) {
        fail(403, 'forbidden');
        return;
      }
      send(200, JSON.stringify(runOp(op, parsed, keyring)));
    } catch (error) {
      if (res.headersSent) return;
      if (error instanceof InvalidRequestError) {
        fail(400, 'invalid_request');
      } else if (error instanceof DecryptFailedError) {
        fail(400, 'decrypt_failed');
      } else {
        fail(500, 'internal');
      }
    }
  };

  const server = createServer(
    { maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 },
    (req, res) => {
      void handle(req, res);
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ path: socketPath, exclusive: true }, () => {
      server.off('error', reject);
      resolve();
    });
  });
  chmodSync(socketPath, 0o600);

  let closing: Promise<void> | undefined;
  return {
    socketPath,
    close() {
      closing ??= new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
      return closing;
    },
  };
}
