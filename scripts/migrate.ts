// マイグレーションを流す（不変条件8の例外「マイグレーション」と「テスト用の DB の作成」。ADR 0015）。
// ブートストラップのロール（スーパーユーザー）でだけ動かす。アプリのコード（サービスのプロセス）には入れない。
//
// - 未適用の packages/warifu-core/migrations/NNNN_<名前>.sql を番号の順に、全体で1つのトランザクションで流す。
// - トランザクションを操作する文（BEGIN、COMMIT など）を含むファイルは流さない。
// - マージした後のファイルは書き換えない。変更は新しいファイルにする（チェックサムは取らない。SHA-256 は
//   不変条件9の許可リストにないため）。
// - `npm run migrate` は、npm run pg-up が表示した PGHOST、PGPORT、PGUSER と、PGDATABASE につないで流す。

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

export const MIGRATIONS_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'packages',
  'warifu-core',
  'migrations',
);

// 並行して流さないためのアドバイザリロックの鍵（"WARIFU" と 0x0002）。
const MIGRATE_LOCK_KEY = '6287397029451988994';
const FILE_PATTERN = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const TRANSACTION_CONTROL = /^\s*(BEGIN|COMMIT|ROLLBACK|ABORT|END|START\s+TRANSACTION)\s*;/im;
const DATABASE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;
const APP_ROLES = ['warifu_idp', 'warifu_relay', 'warifu_company_api'];

export interface MigrationFile {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
}

export function migrationFiles(dir = MIGRATIONS_DIR): MigrationFile[] {
  const files: MigrationFile[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const match = FILE_PATTERN.exec(entry);
    if (match === null) {
      throw new Error('マイグレーションのファイル名の形が違う');
    }
    const sql = readFileSync(join(dir, entry), 'utf8');
    if (TRANSACTION_CONTROL.test(sql)) {
      throw new Error('マイグレーションのファイルに、トランザクションを操作する文を書かない');
    }
    files.push({ version: Number(match[1]), name: match[2] ?? '', sql });
  }
  files.forEach((file, index) => {
    if (file.version !== index + 1) throw new Error('マイグレーションの番号が連続していない');
  });
  return files;
}

/** 未適用のものを流し、流した名前を返す。 */
export async function migrate(client: pg.Client, dir = MIGRATIONS_DIR): Promise<string[]> {
  const files = migrationFiles(dir);
  const applied: string[] = [];
  await client.query('BEGIN');
  try {
    await client.query('SELECT pg_catalog.pg_advisory_xact_lock($1::bigint)', [MIGRATE_LOCK_KEY]);
    const role = await client.query<{ rolsuper: boolean }>(
      'SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user',
    );
    if (role.rows[0]?.rolsuper !== true) {
      throw new Error('マイグレーションは、ブートストラップのロールで流す');
    }
    const exists = await client.query<{ t: string | null }>(
      "SELECT pg_catalog.to_regclass('warifu_meta.migrations')::text AS t",
    );
    const done = new Set<number>();
    if (exists.rows[0]?.t !== null && exists.rows[0]?.t !== undefined) {
      const rows = await client.query<{ version: number }>(
        'SELECT version FROM warifu_meta.migrations',
      );
      for (const row of rows.rows) done.add(row.version);
    }
    for (const file of files) {
      if (done.has(file.version)) continue;
      await client.query(file.sql);
      await client.query('INSERT INTO warifu_meta.migrations (version, name) VALUES ($1, $2)', [
        file.version,
        file.name,
      ]);
      applied.push(`${String(file.version).padStart(4, '0')}_${file.name}`);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
  return applied;
}

/**
 * DB ごとの ACL。CREATE DATABASE … TEMPLATE は DB の ACL を写さないので、DB ごとにかける。
 * PUBLIC から CONNECT と TEMP を外し（一時テーブルや pg_temp の関数で検索の順を乗っ取らせない）、
 * アプリのロールには CONNECT だけを与える。
 */
export async function applyDatabaseAcl(client: pg.Client, database: string): Promise<void> {
  if (!DATABASE_NAME.test(database)) throw new Error('DB の名前の形が違う');
  await client.query(`REVOKE ALL ON DATABASE ${database} FROM PUBLIC`);
  await client.query(`GRANT CONNECT ON DATABASE ${database} TO ${APP_ROLES.join(', ')}`);
}

// `npm run migrate` で直接実行したとき。
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const database = process.env.PGDATABASE;
  if (database === undefined || database === '') {
    console.error('PGDATABASE を指定する（npm run pg-up が表示した PGHOST、PGPORT、PGUSER も）');
    process.exit(2);
  }
  const client = new pg.Client();
  await client.connect();
  try {
    const applied = await migrate(client);
    await applyDatabaseAcl(client, database);
    console.log(applied.length === 0 ? '適用するものはない' : `適用した：${applied.join('、')}`);
  } finally {
    await client.end();
  }
}
