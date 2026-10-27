// scripts/migrate.ts を確かめる。マイグレーションと DB の作成は、不変条件8の例外として、ブートストラップのロールで行う。

import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import {
  applyDatabaseAcl,
  MIGRATIONS_DIR,
  migrate,
  migrationFiles,
} from '../../scripts/migrate.ts';

const database = `warifu_migrate_${process.env.VITEST_POOL_ID ?? '1'}`;
let admin: pg.Client;
let client: pg.Client;

beforeAll(async () => {
  const { host, port, user } = inject('pg');
  admin = new pg.Client({ host, port, user, database: 'postgres' });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${database}`);
  await admin.query(`CREATE DATABASE ${database}`);
  client = new pg.Client({ host, port, user, database });
  await client.connect();
});

afterAll(async () => {
  await client.end();
  await admin.query(`DROP DATABASE IF EXISTS ${database}`);
  await admin.end();
});

describe('マイグレーション', () => {
  it('空の DB に流すとすべて適用し、2回目は何もしない', async () => {
    const files = migrationFiles();
    expect(await migrate(client)).toHaveLength(files.length);
    expect(await migrate(client)).toEqual([]);
  });

  it('トランザクションを操作する文を含むファイルは流さない', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'warifu-migrations-'));
    try {
      for (const name of await readdir(MIGRATIONS_DIR)) {
        await writeFile(join(dir, name), await readFile(join(MIGRATIONS_DIR, name)));
      }
      const next = String((await readdir(MIGRATIONS_DIR)).length + 1).padStart(4, '0');
      await writeFile(join(dir, `${next}_bad.sql`), 'COMMIT;\nSELECT 1;\n');
      await expect(migrate(client, dir)).rejects.toThrow('トランザクション');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('DB の ACL：PUBLIC に CONNECT と TEMP がなく、アプリのロールは CONNECT だけ', async () => {
    await applyDatabaseAcl(client, database);
    const { rows } = await client.query<{ grantee: string; privilege_type: string }>(
      `SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
              a.privilege_type
         FROM pg_catalog.pg_database AS d, pg_catalog.aclexplode(d.datacl) AS a
        WHERE d.datname = $1`,
      [database],
    );
    expect(rows.filter((r) => r.grantee === 'PUBLIC')).toEqual([]);
    for (const role of ['warifu_idp', 'warifu_relay', 'warifu_company_api']) {
      expect(rows.filter((r) => r.grantee === role).map((r) => r.privilege_type)).toEqual([
        'CONNECT',
      ]);
    }
  });

  it('DB の名前の形が違えば ACL をかけない', async () => {
    await expect(applyDatabaseAcl(client, 'x; DROP DATABASE postgres')).rejects.toThrow();
  });
});
