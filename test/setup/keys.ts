// テストから鍵サービスを呼ぶための補助（ADR 0013）。
// - keysvcConnection：鍵のクライアントに渡す接続（既定は globalSetup の keysvc）。
// - rawKeysvcCall：型を通さない生の要求。攻撃の段で使う（テストの中の node:http で送る）。
// - startKeysvcExpectingFailure：起動に失敗するはずの設定で起動し、終了コードと出力を返す。

import { existsSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { request } from 'node:http';
import { join } from 'node:path';
import { inject } from 'vitest';
import type {
  KeysvcCaller,
  KeysvcConnection,
} from '../../packages/warifu-core/src/keys/protocol.ts';
import type { KeysvcProcess } from '../../scripts/keysvc-up.ts';
import { makeSocketDir, spawnKeysvc } from '../../scripts/keysvc-up.ts';

export function keysvcConnection(service: KeysvcCaller, from?: KeysvcProcess): KeysvcConnection {
  if (from !== undefined) {
    return { socketPath: from.socketPath, credential: from.credentials[service] };
  }
  const provided = inject('keysvc');
  return { socketPath: provided.socketPath, credential: provided.credentials[service] };
}

export interface RawResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly rawHeaders: readonly string[];
  readonly body: string;
}

export function rawKeysvcCall(input: {
  readonly socketPath: string;
  readonly authorization?: string;
  readonly op: string;
  readonly method?: string;
  readonly body: unknown;
}): Promise<RawResponse> {
  const payload = typeof input.body === 'string' ? input.body : JSON.stringify(input.body);
  const headers: Record<string, string | number> = {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  };
  if (input.authorization !== undefined) headers.authorization = input.authorization;
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: input.socketPath,
        path: `/v1/${input.op}`,
        method: input.method ?? 'POST',
        headers,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: Object.fromEntries(
              Object.entries(res.headers).map(([k, v]) => [
                k,
                Array.isArray(v) ? v.join(',') : (v ?? ''),
              ]),
            ),
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

export async function startKeysvcExpectingFailure(
  config: unknown,
  options?: { readonly socketDirMode?: number; readonly socketDir?: string },
): Promise<{
  readonly exitCode: number | null;
  readonly output: string;
  readonly socketCreated: boolean;
}> {
  const socketDir = options?.socketDir ?? (await makeSocketDir(options?.socketDirMode));
  const line =
    typeof config === 'function'
      ? JSON.stringify((config as (dir: string) => unknown)(socketDir))
      : JSON.stringify(config);
  const spawned = spawnKeysvc(line);
  const timer = setTimeout(() => spawned.child.kill('SIGKILL'), 10_000);
  const exitCode = await spawned.exited;
  clearTimeout(timer);
  const socketCreated = existsSync(join(socketDir, 'keysvc.sock'));
  if (options?.socketDir === undefined) await rm(socketDir, { recursive: true, force: true });
  return { exitCode, output: spawned.output(), socketCreated };
}
