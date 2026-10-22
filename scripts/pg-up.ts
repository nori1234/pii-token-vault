// 一時的な Postgres 16 のクラスタを起動して止める。Vitest の globalSetup と、手元の開発で使う。
//
// - バイナリは環境変数 PG_BIN（既定は /usr/lib/postgresql/16/bin）から使う。システムのクラスタ（5432 番）には触れない。
// - root で実行されたときだけ `runuser -u postgres` で動かす（initdb と postgres は root では動かないため）。
// - mktemp -d 相当のディレクトリにデータとソケットを置く。TCP では待ち受けず、ソケットのディレクトリは 0700 にする。
//   そのため trust 認証でも、つなげるのは起動した利用者（と root）だけになる。
// - root のときは、TMPDIR ではなく /tmp の下に置く。TMPDIR が 0700 のディレクトリを指していると、
//   postgres の利用者がたどれず、initdb が失敗するため。
// - stop() を呼ばずにプロセスが終わっても（Ctrl-C など）、'exit' のときに同期で止めて消す。
//   pg_ctl は postmaster を別のセッションで起動するので、Ctrl-C は Postgres に届かない。
//   また Vitest は、SIGINT と SIGTERM では globalSetup の teardown を呼ばずに process.exit() する。
// - fsync=off などはテストを速くするための設定で、本番の設定ではない。
//
// ここで使うスーパーユーザー（warifu_bootstrap）は、不変条件8の例外（マイグレーション、テスト用の DB の作成）にだけ使う。
// アプリのコードは、このロールでつながない。

import { execFile, execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { appendFile, chown, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);

export const BOOTSTRAP_ROLE = 'warifu_bootstrap';

export interface PgCluster {
  /** ソケットを置いたディレクトリ。pg の `host` にそのまま渡す。 */
  host: string;
  port: number;
  user: string;
  stop(): Promise<void>;
}

function pgBin(name: string): string {
  return join(process.env.PG_BIN ?? '/usr/lib/postgresql/16/bin', name);
}

function isRoot(): boolean {
  return process.getuid?.() === 0;
}

/** root のときは postgres の利用者で動かすように、コマンドを組み立てる。 */
function postgresCommand(command: string, args: string[]): [string, string[]] {
  return isRoot() ? ['runuser', ['-u', 'postgres', '--', command, ...args]] : [command, args];
}

async function asPostgres(command: string, args: string[]): Promise<void> {
  await run(...postgresCommand(command, args));
}

function stopArgs(data: string): string[] {
  return ['--pgdata', data, '--mode=immediate', '--wait', 'stop'];
}

/** プロセスが終わるときの後始末。'exit' の中で動くので、すべて同期で行う。 */
function stopSync(data: string, dir: string): void {
  try {
    execFileSync(...postgresCommand(pgBin('pg_ctl'), stopArgs(data)), { stdio: 'ignore' });
  } catch {
    // まだ起動していないか、もう止まっている。
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// postgresql.conf の unix_socket_directories は、カンマ区切りの一覧で、引用符も解釈する。
// パスをそのまま書くので、区切りや引用符になりうる文字を含むパスは使わない。
const UNSAFE_PATH = /[\s'",\\\p{Cc}]/u;
// ソケットのパス（<dir>/.s.PGSQL.<port>）の上限。sun_path の108バイトから、終端の1バイトを引いた値。
const MAX_SOCKET_PATH_BYTES = 107;
// 一時ディレクトリの名前の接頭辞。mkdtemp が後ろに6文字を足す。
const TEMP_PREFIX = 'warifu-pg-';

/** 一時ディレクトリを置く場所を決め、そのまま postgresql.conf に書けるかを確かめる。 */
function tempBase(): string {
  const base = isRoot() ? '/tmp' : tmpdir();
  if (UNSAFE_PATH.test(base)) {
    throw new Error(
      '一時ディレクトリのパスに、空白、引用符、カンマ、バックスラッシュ、制御文字のどれかが入っている（TMPDIR を見直す）',
    );
  }
  // mkdtemp が足す6文字と、ソケットのファイル名（ポートは最大5桁）を見込む。
  const longestSocket = join(base, `${TEMP_PREFIX}XXXXXX`, '.s.PGSQL.65535');
  if (Buffer.byteLength(longestSocket) > MAX_SOCKET_PATH_BYTES) {
    throw new Error(
      '一時ディレクトリのパスが長く、Unix ソケットを置けない（TMPDIR を短いパスにする）',
    );
  }
  return base;
}

async function postgresOwner(): Promise<{ uid: number; gid: number }> {
  const [{ stdout: uid }, { stdout: gid }] = await Promise.all([
    run('id', ['-u', 'postgres']),
    run('id', ['-g', 'postgres']),
  ]);
  return { uid: Number(uid.trim()), gid: Number(gid.trim()) };
}

/** 空いているポートの番号を得る。TCP では待ち受けないが、ソケットのファイル名にポートの番号が入る。 */
async function freePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => {
        if (address !== null && typeof address === 'object') {
          resolve(address.port);
        } else {
          reject(new Error('空いているポートを得られなかった'));
        }
      });
    });
  });
}

export async function startCluster(): Promise<PgCluster> {
  const dir = await mkdtemp(join(tempBase(), TEMP_PREFIX));
  const data = join(dir, 'data');
  const onExit = () => stopSync(data, dir);
  process.once('exit', onExit);
  const teardown = async () => {
    try {
      await asPostgres(pgBin('pg_ctl'), stopArgs(data));
    } finally {
      await rm(dir, { recursive: true, force: true });
      process.off('exit', onExit);
    }
  };
  try {
    if (isRoot()) {
      const { uid, gid } = await postgresOwner();
      await chown(dir, uid, gid);
    }
    await asPostgres(pgBin('initdb'), [
      '--pgdata',
      data,
      '--username',
      BOOTSTRAP_ROLE,
      '--auth-local=trust',
      '--auth-host=reject',
      '--encoding=UTF8',
      '--locale=C',
      '--no-sync',
      '--no-instructions',
    ]);
    const port = await freePort();
    await appendFile(
      join(data, 'postgresql.conf'),
      [
        '',
        '# scripts/pg-up.ts が追記（テスト専用）',
        "listen_addresses = ''",
        `unix_socket_directories = '${dir}'`,
        'unix_socket_permissions = 0700',
        `port = ${port}`,
        'fsync = off',
        'synchronous_commit = off',
        'full_page_writes = off',
        // サーバーのログに値を残さない（不変条件4）。失敗した SQL の本文（STATEMENT）、DETAIL（制約に反した行や
        // キーの値）、ERROR の本文（"invalid input syntax" は入力の値を含む）には、値が平文で入りうる。
        // そのため FATAL より軽いものは書かず、書くものにも DETAIL などを付けない。
        'log_min_messages = fatal',
        'log_min_error_statement = panic',
        'log_error_verbosity = terse',
        'log_parameter_max_length_on_error = 0',
        '',
      ].join('\n'),
    );
    await asPostgres(pgBin('pg_ctl'), [
      '--pgdata',
      data,
      '--log',
      join(dir, 'server.log'),
      '--wait',
      '--timeout=60',
      'start',
    ]);
    let stopped = false;
    return {
      host: dir,
      port,
      user: BOOTSTRAP_ROLE,
      async stop() {
        if (stopped) return;
        stopped = true;
        await teardown();
      },
    };
  } catch (error) {
    // pg_ctl start が時間切れのときは、サーバーが動いていることがある。止めてから消す。
    await teardown().catch(() => {});
    throw error;
  }
}

// `npm run pg-up` で直接実行したときは、接続先を表示して、Ctrl-C で止めるまで動かし続ける。
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let cluster: PgCluster | undefined;
  let stopping = false;
  // シグナルの待ち受けだけではイベントループが止まってしまうので、タイマーで生かしておく
  const keepAlive = setInterval(() => {}, 2 ** 30);
  const stopAndExit = (started: PgCluster) => {
    started.stop().then(
      () => process.exit(0),
      (error: unknown) => {
        console.error(error);
        process.exit(1);
      },
    );
  };
  const shutdown = () => {
    // 止めている途中の2回目のシグナルは無視する（既定の動作で落ちると、'exit' の後始末も動かない）。
    if (stopping) return;
    stopping = true;
    clearInterval(keepAlive);
    // 起動の途中なら、起動が終わってから止める。すぐに終わると、動いている initdb などと、消す処理が競合する。
    if (cluster !== undefined) stopAndExit(cluster);
  };
  // 起動の途中で止められても後始末できるように、startCluster より前に待ち受ける。
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(signal, shutdown);
  }
  cluster = await startCluster();
  if (stopping) {
    stopAndExit(cluster);
  } else {
    console.log(`PGHOST=${cluster.host}`);
    console.log(`PGPORT=${cluster.port}`);
    console.log(`PGUSER=${cluster.user}`);
    console.log('Ctrl-C で止めて、ディレクトリを消す。');
  }
}
