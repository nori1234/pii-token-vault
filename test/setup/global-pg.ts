// Vitest の globalSetup。一時的なクラスタを1つ起動し、終わったら止めて消す。
// Ctrl-C などで teardown が呼ばれずに終わったときは、scripts/pg-up.ts が 'exit' のときに止めて消す。
// マイグレーションは TEMPLATE の DB に流し、各ワーカーはそこから自分の DB を作る（worker-db.ts）。
// マイグレーションと DB の作成は、不変条件8の例外として、ブートストラップのロールで行う。

import pg from 'pg';
import type { TestProject } from 'vitest/node';
import { applyDatabaseAcl, migrate } from '../../scripts/migrate.ts';
import { startCluster } from '../../scripts/pg-up.ts';

export const TEMPLATE_DATABASE = 'warifu_template';

export interface ProvidedPg {
  host: string;
  port: number;
  user: string;
  template: string;
}

declare module 'vitest' {
  export interface ProvidedContext {
    pg: ProvidedPg;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const cluster = await startCluster();
  try {
    const admin = new pg.Client({
      host: cluster.host,
      port: cluster.port,
      user: cluster.user,
      database: 'postgres',
    });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${TEMPLATE_DATABASE}`);
    } finally {
      await admin.end();
    }
    // 複製は、テンプレートへの接続が残っていると失敗するので、流したら閉じる。
    const template = new pg.Client({
      host: cluster.host,
      port: cluster.port,
      user: cluster.user,
      database: TEMPLATE_DATABASE,
    });
    await template.connect();
    try {
      await migrate(template);
      await applyDatabaseAcl(template, TEMPLATE_DATABASE);
    } finally {
      await template.end();
    }
  } catch (error) {
    await cluster.stop();
    throw error;
  }
  project.provide('pg', {
    host: cluster.host,
    port: cluster.port,
    user: cluster.user,
    template: TEMPLATE_DATABASE,
  });
  return async () => {
    await cluster.stop();
  };
}
