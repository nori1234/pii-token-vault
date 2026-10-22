// 鍵サービス（packages/keysvc）を別プロセスで起動して止める。Vitest の globalSetup と、テストの中で使う
// （M3 以降の開発用の起動スクリプトでも使う）。ADR 0012。
//
// - ソケットのディレクトリは 0700 で作る（scripts/pg-up.ts の tempBase の下）。
// - サービスの資格情報は、起動のたびに乱数で作り、keysvc の標準入力にだけ渡す。環境変数、コマンドラインの引数、
//   ファイルには置かない。keysvc は env: {} で起動し、親の環境変数を引き継がない。
// - 標準入力は閉じずに持つ。閉じると keysvc は止まる。stop() を呼ばずにプロセスが終わっても、
//   'exit' のときに同期で SIGKILL を送り、ディレクトリを消す。

import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { KeysvcCaller } from '../packages/warifu-core/src/keys/protocol.ts';
import { tempBase } from './pg-up.ts';

export const KEYSVC_MAIN = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'packages',
  'keysvc',
  'src',
  'main.ts',
);

const CALLERS: readonly KeysvcCaller[] = ['idp', 'relay', 'company-api'];
const READY_TIMEOUT_MS = 10_000;
const STOP_TIMEOUT_MS = 3000;

export interface KeysvcProcess {
  readonly socketDir: string;
  readonly socketPath: string;
  readonly pid: number;
  /** `<service>.<base64url>`。実行ごとの乱数で、メモリの中だけに持つ。 */
  readonly credentials: Readonly<Record<KeysvcCaller, string>>;
  /** ここまでの標準出力と標準エラーのすべて。 */
  output(): string;
  stop(): Promise<void>;
}

export interface SpawnedKeysvc {
  readonly child: ChildProcessWithoutNullStreams;
  output(): string;
  exited: Promise<number | null>;
}

/** keysvc を起動し、設定の1行を標準入力に書く（閉じない）。ready を待たない。 */
export function spawnKeysvc(configLine: string): SpawnedKeysvc {
  const child = spawn(process.execPath, [KEYSVC_MAIN], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {},
  });
  let output = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (text: string) => {
    output += text;
  });
  child.stderr.on('data', (text: string) => {
    output += text;
  });
  const exited = new Promise<number | null>((resolve) => {
    child.once('exit', (code) => resolve(code));
  });
  child.stdin.on('error', () => {});
  child.stdin.write(`${configLine}\n`);
  return { child, output: () => output, exited };
}

export async function makeSocketDir(mode = 0o700): Promise<string> {
  const dir = await mkdtemp(join(tempBase(), 'warifu-ks-'));
  await chmod(dir, mode);
  return dir;
}

export async function startKeysvc(): Promise<KeysvcProcess> {
  const socketDir = await makeSocketDir();
  const secrets = Object.fromEntries(
    CALLERS.map((caller) => [caller, randomBytes(32).toString('base64url')]),
  ) as Record<KeysvcCaller, string>;
  const spawned = spawnKeysvc(JSON.stringify({ version: 1, socketDir, credentials: secrets }));
  const { child } = spawned;
  const onExit = () => {
    try {
      child.kill('SIGKILL');
    } catch {
      // もう止まっている。
    }
    rmSync(socketDir, { recursive: true, force: true });
  };
  process.once('exit', onExit);

  const stop = async (): Promise<void> => {
    if (child.exitCode === null && child.signalCode === null) {
      child.stdin.end();
      const timer = setTimeout(() => child.kill('SIGKILL'), STOP_TIMEOUT_MS);
      await spawned.exited;
      clearTimeout(timer);
    }
    await rm(socketDir, { recursive: true, force: true });
    process.off('exit', onExit);
  };

  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('keysvc が時間内に起動しなかった')),
        READY_TIMEOUT_MS,
      );
      const check = () => {
        if (spawned.output().includes('"event":"keysvc.ready"')) {
          clearTimeout(timer);
          child.stdout.off('data', check);
          resolve();
        }
      };
      child.stdout.on('data', check);
      spawned.exited.then(() => {
        clearTimeout(timer);
        reject(new Error('keysvc が起動の途中で終わった'));
      });
      check();
    });
  } catch (error) {
    await stop();
    throw error;
  }

  const credentials = Object.fromEntries(
    CALLERS.map((caller) => [caller, `${caller}.${secrets[caller]}`]),
  ) as Record<KeysvcCaller, string>;
  return {
    socketDir,
    socketPath: join(socketDir, 'keysvc.sock'),
    pid: child.pid ?? -1,
    credentials,
    output: spawned.output,
    stop,
  };
}
