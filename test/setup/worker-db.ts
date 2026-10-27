// ワーカーごとの DB。TEMPLATE から作り、同じワーカーの中では使い回す（ファイルの間で共有する）。
// DB の作成は不変条件8の例外（テスト用の DB の作成）なので、ブートストラップのロールで行う。
// テストは、ブートストラップのロールで DB の中身を読み書きしない（アプリのロールか、境界を通す）。

import pg from 'pg';
import { inject } from 'vitest';
import { applyDatabaseAcl } from '../../scripts/migrate.ts';

const DUPLICATE_DATABASE = '42P04';

export type AppRole = 'warifu_idp' | 'warifu_relay' | 'warifu_company_api';

let created: Promise<pg.ClientConfig> | undefined;

/** ワーカーの DB の、ブートストラップのロールでの接続の設定。 */
export function workerDatabase(): Promise<pg.ClientConfig> {
  created ??= createWorkerDatabase();
  return created;
}

/** ワーカーの DB の、アプリのロールでの接続の設定（資格情報なし。ソケットの 0700 と trust による）。 */
export async function workerDatabaseAs(role: AppRole): Promise<pg.ClientConfig> {
  const config = await workerDatabase();
  return { ...config, user: role };
}

async function createWorkerDatabase(): Promise<pg.ClientConfig> {
  const { host, port, user, template } = inject('pg');
  const poolId = Number(process.env.VITEST_POOL_ID ?? '1');
  if (!Number.isInteger(poolId) || poolId < 1) {
    throw new Error('VITEST_POOL_ID が不正');
  }
  const database = `warifu_test_${poolId}`;
  const admin = new pg.Client({ host, port, user, database: 'postgres' });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${database} TEMPLATE ${template}`);
    await applyDatabaseAcl(admin, database);
  } catch (error) {
    if ((error as { code?: string }).code !== DUPLICATE_DATABASE) throw error;
  } finally {
    await admin.end();
  }
  return { host, port, user, database };
}
