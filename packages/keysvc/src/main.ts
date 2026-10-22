// 鍵サービスのプロセスの入口（ADR 0012）。引数は取らない。
//
// - 標準入力の1行目で設定の JSON を受け取る。資格情報を、環境変数、コマンドラインの引数、ファイルに置かないため
//   （/proc/<pid>/environ や ps から読めるため）。
// - 設定が違えば、keysvc.config_invalid と理由の語だけを出し、終了コード 2 で終わる。ソケットは作らない。
// - 待ち受けを始めたら keysvc.ready の1行を標準出力に書く。
// - 標準入力の EOF、SIGTERM、SIGINT で止まる。起動した側が終わるとパイプが閉じるので、孤児にならない。

import { createLogger } from '@pii-token-vault/warifu-core/log';
import { CONFIG_MAX_BYTES, KeysvcConfigError, parseKeysvcConfig } from './config.ts';
import { type KeysvcServer, startKeysvcServer } from './server.ts';

const logger = createLogger({ component: 'keysvc' });

let server: KeysvcServer | undefined;
let stopping = false;
let buffered = Buffer.alloc(0);
let configured = false;

function stop(): void {
  if (stopping) return;
  stopping = true;
  const done = () => {
    logger.info({ event: 'keysvc.stopped' });
    process.exit(0);
  };
  if (server === undefined) {
    done();
    return;
  }
  server.close().then(done, done);
}

function failConfig(reason: string): never {
  logger.error({ event: 'keysvc.config_invalid', reason });
  process.exit(2);
}

async function start(line: string): Promise<void> {
  try {
    const config = parseKeysvcConfig(line);
    server = await startKeysvcServer(config, logger);
  } catch (error) {
    if (error instanceof KeysvcConfigError) failConfig(error.reason);
    logger.error({ event: 'keysvc.start_failed', err: error });
    process.exit(1);
  }
  logger.info({ event: 'keysvc.ready' });
  if (stopping) stop();
}

process.stdin.on('data', (chunk: Buffer) => {
  if (configured) return;
  buffered = Buffer.concat([buffered, chunk]);
  const newline = buffered.indexOf(0x0a);
  if (newline === -1) {
    if (buffered.byteLength > CONFIG_MAX_BYTES) failConfig('too_large');
    return;
  }
  configured = true;
  const line = buffered.subarray(0, newline).toString('utf8');
  buffered = Buffer.alloc(0);
  void start(line);
});

process.stdin.on('end', () => {
  if (!configured) failConfig('not_json');
  stop();
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, stop);
}
