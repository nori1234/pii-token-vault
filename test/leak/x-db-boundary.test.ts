// DB の境界（不変条件8、plan 2章「BOLA を防ぐ」、10章 M2）。ワーカーの DB を使う。

import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SqlRejectedError, sql } from '../../packages/warifu-core/src/db/sql.ts';
import { type Db, DbError } from '../../packages/warifu-core/src/db/types.ts';
import {
  InvalidIdError,
  parseTenantId,
  parseWarifuUserId,
  type TenantId,
  type WarifuUserId,
} from '../../packages/warifu-core/src/ids.ts';
import { rawRoleClient, serviceDb, sqlstateOf } from '../setup/db.ts';
import { importsOf, packageSourceFiles, read } from '../setup/source.ts';

const tenantA = parseTenantId(randomUUID());
const tenantB = parseTenantId(randomUUID());
const user1 = parseWarifuUserId(randomUUID());
const user2 = parseWarifuUserId(randomUUID());
const macOf = () => new Uint8Array(randomBytes(32));

let idp: Db;
const raws: pg.Client[] = [];

async function raw(role: 'warifu_idp' | 'warifu_relay' | 'warifu_company_api') {
  const client = await rawRoleClient(role);
  raws.push(client);
  return client;
}

async function insertAlias(tenantId: TenantId, userId: WarifuUserId): Promise<void> {
  await idp.withTenant(tenantId, (tx) =>
    tx.execute(
      sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
          VALUES (${tenantId}, ${userId}, 1, ${macOf()})`,
    ),
  );
}

beforeAll(async () => {
  idp = await serviceDb('idp');
  await insertAlias(tenantA, user1);
  await insertAlias(tenantB, user2);
});

afterAll(async () => {
  await idp.close();
  await Promise.all(raws.map((client) => client.end()));
});

describe('漏えい：DB の境界（plan 2章 BOLA、10章 M2）', () => {
  it('テナントの境界の中から、別のテナントの行が見えない', async () => {
    // 攻撃者が持っている情報：A社のテナントの文脈で動くルート（ATK-02、ATK-03。TH-30）
    // 試す経路：withTenant(A) の中で aliases.generation を全件読む
    // 期待する結果：B の行は0件。A の行だけが見える
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const rows = await idp.withTenant(tenantA, (tx) =>
      tx.query<{ tenant_id: string }>(sql`SELECT tenant_id FROM aliases.generation`),
    );
    expect(rows.length).toBeGreaterThan(0);
    expect(new Set(rows.map((r) => r.tenant_id))).toEqual(new Set([tenantA]));
  });

  it('利用者の境界の中から、別の利用者の行が見えない', async () => {
    // 攻撃者が持っている情報：U1 の文脈（ATK-02。TH-31）
    // 試す経路：withWarifuUser(U1) で aliases.generation を全件読む
    // 期待する結果：U2 の行は0件
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const rows = await idp.withWarifuUser(user1, (tx) =>
      tx.query<{ user_id: string }>(sql`SELECT user_id FROM aliases.generation`),
    );
    expect(rows.length).toBeGreaterThan(0);
    expect(new Set(rows.map((r) => r.user_id))).toEqual(new Set([user1]));
  });

  it('境界を設定しない生の接続では、読めず、書けない', async () => {
    // 攻撃者が持っている情報：盗んだアプリのロールの接続の設定（ATK-07）
    // 試す経路：rawRoleClient で、境界の値を設定せずに、読める表をすべて読み、INSERT する
    // 期待する結果：SELECT は0行（権限のない表は 42501）。INSERT は 42501
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    for (const role of ['warifu_idp', 'warifu_company_api', 'warifu_relay'] as const) {
      const client = await raw(role);
      for (const text of [
        'SELECT tenant_id FROM aliases.generation',
        'SELECT seq FROM audit.chain',
        'SELECT seq FROM audit.events',
      ]) {
        const result = await client.query(text).then(
          (r) => r.rowCount,
          (e: { code?: string }) => e.code,
        );
        expect([0, '42501']).toContain(result);
      }
      expect(
        await sqlstateOf(
          client.query(
            'INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac) VALUES ($1, $2, 1, $3)',
            [tenantA, user1, Buffer.from(macOf())],
          ),
        ),
      ).toBe('42501');
      expect(
        await sqlstateOf(
          client.query(
            'INSERT INTO audit.chain (seq, content_mac, prev_mac, mac) VALUES (999999, $1, $1, $1)',
            [Buffer.from(macOf())],
          ),
        ),
      ).toBe('42501');
    }
  });

  it('境界の値を自分で設定した生の接続でも、列の権限を越えられない（残るリスクの確認）', async () => {
    // 攻撃者が持っている情報：盗んだ warifu_idp の接続の設定と、テナント B の ID（ATK-07）
    // 試す経路：set_config でテナント B を設定してから読む
    // 期待する結果：B の行のうち、列の権限のある列だけが読める（ADR 0015 の残るリスク）。lookup_mac は 42501
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const client = await raw('warifu_idp');
    await client.query("SELECT pg_catalog.set_config('warifu.tenant_id', $1, false)", [tenantB]);
    const visible = await client.query('SELECT tenant_id FROM aliases.generation');
    expect(visible.rows.map((r) => r.tenant_id)).toEqual([tenantB]);
    expect(await sqlstateOf(client.query('SELECT lookup_mac FROM aliases.generation'))).toBe(
      '42501',
    );
  });

  it.each([
    ['SET ROLE warifu_owner'],
    ["SELECT pg_catalog.set_config('role', 'warifu_owner', false)"],
    ['ALTER TABLE aliases.generation DISABLE ROW LEVEL SECURITY'],
    ['ALTER TABLE aliases.generation NO FORCE ROW LEVEL SECURITY'],
    ['CREATE TABLE public.x (a int)'],
    ['CREATE TEMP TABLE x (a int)'],
    ['ALTER ROLE warifu_idp BYPASSRLS'],
    ['DROP POLICY idp_select ON aliases.generation'],
  ])('権限の昇格ができない：%s', async (text) => {
    // 攻撃者が持っている情報：SQL インジェクションか盗んだ資格情報で、warifu_idp として任意の SQL を実行できる（ATK-02、ATK-07）
    // 試す経路：所有者への切り替え、RLS を外す、表を作る、ロールの属性を変える
    // 期待する結果：すべて 42501
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const client = await raw('warifu_idp');
    expect(await sqlstateOf(client.query(text))).toBe('42501');
  });

  it.each([
    ['set_config', () => sql`SELECT pg_catalog.set_config('warifu.tenant_id', ${tenantB}, true)`],
    ['current_setting', () => sql`SELECT current_setting('x', true)`],
    ['Unicode の識別子', () => sql`SELECT U&"set_\\0063onfig"('a', 'b', true)`],
    ['二重引用符', () => sql`SELECT "tenant_id" FROM aliases.generation`],
    ['セミコロン', () => sql`SELECT 1; SELECT 2`],
    ['ドル記号の引用', () => sql`SELECT $$x$$`],
    ['コメント', () => sql`SELECT 1 -- x`],
    ['SET', () => sql`SET ROLE warifu_owner`],
    ['RESET', () => sql`RESET ROLE`],
    ['BEGIN', () => sql`BEGIN`],
    ['DO', () => sql`DO 'x'`],
    ['COPY', () => sql`COPY aliases.generation TO STDOUT`],
    ['CREATE', () => sql`CREATE TABLE idp.x (a int)`],
  ])('sql タグは、境界を変える文を作らせない：%s', async (_label, make) => {
    // 攻撃者が持っている情報：なし（開発者の誤りを止める固定。境界の値を書き換える文を、アプリのコードに書かせない）
    // 試す経路：境界の値に触れる文、複数の文、トランザクションや DDL を sql タグで作る
    // 期待する結果：作る時点で SqlRejectedError。DB に届かない
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2。spec 03 の TH-35）
    expect(make).toThrow(SqlRejectedError);
    await expect(
      idp.withTenant(tenantA, (tx) => tx.query({ text: 'SELECT 1', values: [] })),
    ).rejects.toThrow(SqlRejectedError);
  });

  it('UUID でない ID は、DB に届く前に拒否する', async () => {
    // 攻撃者が持っている情報：利用者の入力をそのまま ID に使う誤り（ATK-02）
    // 試す経路：withTenant("' OR 1=1 --")、withWarifuUser に大文字の UUID
    // 期待する結果：InvalidIdError。DB に届かない
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    await expect(idp.withTenant("' OR 1=1 --" as TenantId, async () => 1)).rejects.toThrow(
      InvalidIdError,
    );
    await expect(
      idp.withWarifuUser(randomUUID().toUpperCase() as WarifuUserId, async () => 1),
    ).rejects.toThrow(InvalidIdError);
  });

  it('境界の入れ子と、fn の外に持ち出した tx を拒否する', async () => {
    // 攻撃者が持っている情報：なし（作りの固定。2つの境界の値が混ざる経路を作らない）
    // 試す経路：withTenant の中で withWarifuUser を呼ぶ。fn の外に持ち出した tx で query を呼ぶ
    // 期待する結果：nested_boundary、tx_closed
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    await expect(
      idp.withTenant(tenantA, () => idp.withWarifuUser(user1, async () => 1)),
    ).rejects.toMatchObject({ code: 'nested_boundary' });
    let leaked: Parameters<Parameters<Db['withTenant']>[1]>[0] | undefined;
    await idp.withTenant(tenantA, async (tx) => {
      leaked = tx;
    });
    await expect(leaked?.query(sql`SELECT 1 AS x`)).rejects.toMatchObject({ code: 'tx_closed' });
  });

  it('接続を使い回しても、前の境界が残らない', async () => {
    // 攻撃者が持っている情報：なし（プールの使い回しの固定。前の要求の境界で、次の要求が動かない）
    // 試す経路：接続数1の Db で、withTenant(A) の fn が例外で ROLLBACK した後、withWarifuUser(U2) で読む
    // 期待する結果：A の行は0件。warifu.current_tenant_id() は NULL
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const single = await serviceDb('idp', { maxConnections: 1 });
    try {
      await expect(
        single.withTenant(tenantA, async (tx) => {
          await tx.query(sql`SELECT tenant_id FROM aliases.generation`);
          throw new Error('fn failed');
        }),
      ).rejects.toThrow('fn failed');
      const after = await single.withWarifuUser(user2, async (tx) => ({
        rows: await tx.query<{ tenant_id: string }>(sql`SELECT tenant_id FROM aliases.generation`),
        current: await tx.one<{ t: string | null }>(sql`SELECT warifu.current_tenant_id() AS t`),
      }));
      expect(after.rows.map((r) => r.tenant_id)).toEqual([tenantB]);
      expect(after.current.t).toBeNull();
    } finally {
      await single.close();
    }
  });

  it('DB のエラーに、入力の値を入れない', async () => {
    // 攻撃者が持っている情報：ログやエラー報告を読める者（TH-36）
    // 試す経路：同じ lookup_mac の INSERT（一意性の違反）と、UUID の形の誤り（型の変換の失敗）を起こす
    // 期待する結果：DbError は code と constraint だけ。message と detail に入力の値（16進を含む）がない
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2。不変条件4）
    const mac = macOf();
    const hex = Buffer.from(mac).toString('hex');
    const insert = (userId: string) =>
      idp.withTenant(tenantA, (tx) =>
        tx.execute(
          sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
              VALUES (${tenantA}, ${userId}, 1, ${mac})`,
        ),
      );
    await insert(randomUUID());
    const duplicate = await insert(randomUUID()).catch((e: unknown) => e);
    expect(duplicate).toBeInstanceOf(DbError);
    expect(duplicate).toMatchObject({ code: '23505', constraint: 'generation_lookup_mac_key' });
    const marker = `not-a-uuid-${randomBytes(6).toString('hex')}`;
    const malformed = await insert(marker).catch((e: unknown) => e);
    expect(malformed).toMatchObject({ code: '22P02' });
    for (const error of [duplicate, malformed]) {
      const text = `${String(error)} ${JSON.stringify(error)} ${(error as Error).stack ?? ''}`;
      expect(text).not.toContain(hex);
      expect(text).not.toContain(marker);
      expect((error as { detail?: unknown }).detail).toBeUndefined();
    }
  });

  it('pg を直接使うのは、warifu-core の db だけ', () => {
    // 攻撃者が持っている情報：なし（静的な固定。境界を通らない DB の経路を作らない）
    // 試す経路：packages/*/src の import から、pg と pg-pool を探す
    // 期待する結果：packages/warifu-core/src/db/ の外では0件
    // plan 11章：番号なし（plan 2章「BOLA を防ぐ」、10章 M2）
    const offenders = packageSourceFiles().filter(
      (file) =>
        !file.startsWith('packages/warifu-core/src/db/') &&
        importsOf(read(file)).some((info) => /^(pg|pg-pool|pg-native)(\/|$)/.test(info.specifier)),
    );
    expect(offenders).toEqual([]);
  });
});
