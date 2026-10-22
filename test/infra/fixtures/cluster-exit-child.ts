// pg-cluster.test.ts から子プロセスとして動かす。クラスタを起動して接続先とサーバーの PID を出力し、
// stop() を呼ばないまま終わる。Vitest が Ctrl-C で globalSetup の teardown を呼ばずに
// process.exit() する場面と同じにするため、SIGINT では process.exit(130) だけを行う。
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { startCluster } from '../../../scripts/pg-up.ts';

const cluster = await startCluster();
// postmaster.pid の1行目が、サーバー（postmaster）の PID。
const pid = Number(
  readFileSync(join(cluster.host, 'data', 'postmaster.pid'), 'utf8').split('\n')[0],
);
process.on('SIGINT', () => process.exit(130));
setInterval(() => {}, 2 ** 30);
process.stdout.write(`${JSON.stringify({ host: cluster.host, pid })}\n`);
