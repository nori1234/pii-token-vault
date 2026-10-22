// ワーカーごとの DB。TEMPLATE から作り、同じワーカーの中では使い回す。
// DB の作成は不変条件8の例外（テスト用の DB の作成）なので、ブートストラップのロールで行う。

import pg from 'pg';
import { inject } from 'vitest';

const DUPLICATE_DATABASE = '42P04';

let created: Promise<pg.ClientConfig> | undefined;

export function workerDatabase(): Promise<pg.ClientConfig> {
  created ??= createWorkerDatabase();
  return created;
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
  } catch (error) {
    if ((error as { code?: string }).code !== DUPLICATE_DATABASE) throw error;
  } finally {
    await admin.end();
  }
  return { host, port, user, database };
}
