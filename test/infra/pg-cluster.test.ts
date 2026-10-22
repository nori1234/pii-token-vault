// scripts/pg-up.ts と、ワーカーごとの DB の作り方を確かめる。
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { workerDatabase } from '../setup/worker-db.ts';

const EXIT_CHILD = fileURLToPath(new URL('./fixtures/cluster-exit-child.ts', import.meta.url));
const SENTINEL = 'SENTINEL-pg-log-0001';

/** PID のプロセスが動いているか。終わってまだ回収されていない（ゾンビの）プロセスは、止まったものとして扱う。 */
function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0] !== 'Z';
  } catch {
    return true;
  }
}

describe('テスト用の一時的なクラスタ', () => {
  let client: pg.Client;

  beforeAll(async () => {
    client = new pg.Client(await workerDatabase());
    await client.connect();
  });

  afterAll(async () => {
    await client.end();
  });

  it('ワーカーごとの DB につながる', async () => {
    const { rows } = await client.query<{ db: string }>('SELECT current_database() AS db');
    expect(rows[0]?.db).toBe(`warifu_test_${process.env.VITEST_POOL_ID ?? '1'}`);
  });

  it('TCP では待ち受けず、ソケットだけを使う', async () => {
    const { rows } = await client.query<{ listen_addresses: string }>('SHOW listen_addresses');
    expect(rows[0]?.listen_addresses).toBe('');
    expect(inject('pg').host.startsWith('/')).toBe(true);
  });

  it('Postgres 16 で、テスト専用の設定になっている', async () => {
    const version = await client.query<{ server_version_num: string }>('SHOW server_version_num');
    expect(Number(version.rows[0]?.server_version_num)).toBeGreaterThanOrEqual(160000);
    expect(Number(version.rows[0]?.server_version_num)).toBeLessThan(170000);
    const fsync = await client.query<{ fsync: string }>('SHOW fsync');
    expect(fsync.rows[0]?.fsync).toBe('off');
  });

  it('TEMPLATE の DB がある', async () => {
    const { rows } = await client.query<{ datname: string }>(
      'SELECT datname FROM pg_database WHERE datname = $1',
      [inject('pg').template],
    );
    expect(rows).toHaveLength(1);
  });

  it('失敗した SQL の値を、サーバーのログに残さない（不変条件4）', async () => {
    await client.query('CREATE TEMP TABLE log_probe (v text UNIQUE, n int CHECK (n > 0))');
    const failing: [string, unknown[]][] = [
      // 一意性の違反。DETAIL に「Key (v)=(…) already exists.」が付く。
      ['INSERT INTO log_probe (v, n) VALUES ($1, 1), ($1, 2)', [`${SENTINEL}-unique`]],
      // CHECK の違反。DETAIL に「Failing row contains (…)」が付く。
      ['INSERT INTO log_probe (v, n) VALUES ($1, -1)', [`${SENTINEL}-check`]],
      // 型の変換の失敗。ERROR の本文に入力の値が入る。
      ['SELECT $1::uuid', [`${SENTINEL}-uuid`]],
      // SQL の本文に値を書いた場合。STATEMENT に本文が付く。
      [`SELECT '${SENTINEL}-literal'::int`, []],
    ];
    for (const [sql, values] of failing) {
      await expect(client.query(sql, values)).rejects.toThrow();
    }
    // サーバーのログは、エラーを接続先に返す前に書かれる。ファイルの場所は scripts/pg-up.ts の pg_ctl の --log。
    const log = readFileSync(join(inject('pg').host, 'server.log'), 'utf8');
    expect(log.includes(SENTINEL)).toBe(false);
  });
});

describe('中断されたときの後始末', () => {
  it('stop() を呼ばずに process.exit() で終わっても、サーバーを止めてディレクトリを消す', async () => {
    const child = spawn(process.execPath, [EXIT_CHILD], { stdio: ['ignore', 'pipe', 'inherit'] });
    const exited = once(child, 'exit');
    try {
      const lines = createInterface({ input: child.stdout });
      const line = await Promise.race([
        once(lines, 'line').then(([value]) => String(value)),
        exited.then(() => {
          throw new Error('子プロセスが、接続先を出力する前に終わった');
        }),
      ]);
      const { host, pid } = JSON.parse(line) as { host: string; pid: number };
      expect(existsSync(host)).toBe(true);
      expect(isRunning(pid)).toBe(true);

      child.kill('SIGINT');
      const [code] = await exited;
      expect(code).toBe(130);
      expect(existsSync(host)).toBe(false);
      expect(isRunning(pid)).toBe(false);
    } finally {
      // 途中で失敗しても、子プロセス（と、その後始末）を残さない。
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGINT');
        await exited;
      }
    }
  }, 60_000);
});
