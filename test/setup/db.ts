// テストから DB に触れるための補助（ADR 0015）。
// - serviceDb、relayDb：アプリと同じ境界（withTenant、withWarifuUser）を通る接続。
// - rawRoleClient：境界を設定しない、アプリのロールの生の接続。盗んだ資格情報や SQL インジェクションを模す。
//   権限はアプリのロールと同じで、不変条件8の例外ではない。
// テストは、ブートストラップのロールで DB の中身を読み書きしない。

import pg from 'pg';
import { createDb } from '../../packages/warifu-core/src/db/boundary.ts';
import { createRelayDb, type RelayDb } from '../../packages/warifu-core/src/db/relay.ts';
import type { Db, DbConnection } from '../../packages/warifu-core/src/db/types.ts';
import { type AppRole, workerDatabase, workerDatabaseAs } from './worker-db.ts';

export type { AppRole };

async function connection(maxConnections?: number): Promise<DbConnection> {
  const config = await workerDatabase();
  return {
    host: String(config.host),
    port: Number(config.port),
    database: String(config.database),
    ...(maxConnections === undefined ? {} : { maxConnections }),
  };
}

export async function serviceDb(
  service: 'idp' | 'company-api',
  options?: { readonly maxConnections?: number },
): Promise<Db> {
  return createDb({ service, connection: await connection(options?.maxConnections) });
}

export async function relayDb(): Promise<RelayDb> {
  return createRelayDb({ connection: await connection() });
}

export async function rawRoleClient(role: AppRole): Promise<pg.Client> {
  const client = new pg.Client(await workerDatabaseAs(role));
  await client.connect();
  return client;
}

/** pg の例外の SQLSTATE（成功したら undefined）。 */
export async function sqlstateOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code ?? 'other';
  }
}
