// 偽の pg のプールで、境界が送る文の順番と、書き換えの検出を確かめる（DB には届かない）。

import type pg from 'pg';
import { describe, expect, it } from 'vitest';
import { openServiceDb } from '../src/db/boundary.ts';
import { sql } from '../src/db/sql.ts';
import { DbError } from '../src/db/types.ts';
import { parseTenantId, parseWarifuUserId } from '../src/ids.ts';

const TENANT = parseTenantId('8f14e45f-ceea-467a-9575-0c1f2e3d4b5a');
const USER = parseWarifuUserId('1b4e28ba-2fa1-41d2-883f-0016d3cca427');

interface Sent {
  readonly text: string;
  readonly values: readonly unknown[];
  readonly queryMode: unknown;
}

function fakePool(options: {
  role?: { role: string; rolsuper: boolean; rolbypassrls: boolean };
  finalCheck?: (sent: Sent[]) => { t: string; u: string; r: string };
  failOn?: RegExp;
}) {
  const sent: Sent[] = [];
  const released: boolean[] = [];
  const client = {
    async query(config: { text: string; values: unknown[]; queryMode?: string }) {
      sent.push({ text: config.text, values: config.values, queryMode: config.queryMode });
      if (options.failOn?.test(config.text)) {
        throw Object.assign(new Error(`duplicate key value (secret-${config.values[0]})`), {
          code: '23505',
          constraint: 'generation_lookup_mac_key',
          detail: 'Key (lookup_mac)=(secret) already exists.',
        });
      }
      if (config.text.includes('rolbypassrls')) {
        return {
          rows: [options.role ?? { role: 'warifu_idp', rolsuper: false, rolbypassrls: false }],
          rowCount: 1,
        };
      }
      if (config.text.includes('current_setting')) {
        const set = sent.find((s) => s.text.includes('set_config'));
        const fallback = { t: String(set?.values[0]), u: String(set?.values[1]), r: 'warifu_idp' };
        return { rows: [options.finalCheck?.(sent) ?? fallback], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    release(destroy?: boolean) {
      released.push(destroy === true);
    },
  };
  const pool = {
    async connect() {
      return client;
    },
    on() {
      return pool;
    },
    async end() {},
  };
  const db = openServiceDb(
    'idp',
    { host: '/nonexistent', port: 1, database: 'x' },
    () => pool as unknown as pg.Pool,
  ).db;
  return { db, sent, released };
}

describe('DB の境界（偽のプール）', () => {
  it('ロールの確認、BEGIN、set_config(…, true)、fn の文、読み直し、COMMIT の順に送る', async () => {
    const { db, sent, released } = fakePool({});
    await db.withTenant(TENANT, (tx) => tx.query(sql`SELECT 1 AS x FROM s.t`));
    const order = [
      /^SELECT current_user AS role/,
      /^BEGIN ISOLATION LEVEL READ COMMITTED$/,
      /^SELECT pg_catalog\.set_config\('warifu\.tenant_id'/,
      /^SELECT 1 AS x FROM s\.t$/,
      /^SELECT pg_catalog\.current_setting\('warifu\.tenant_id'/,
      /^COMMIT$/,
    ];
    expect(sent).toHaveLength(order.length);
    sent.forEach((s, i) => {
      expect(s.text).toMatch(order[i] as RegExp);
    });
    const set = sent[2];
    expect(set?.text).toContain("set_config('warifu.tenant_id', $1, true)");
    expect(set?.text).toContain("set_config('warifu.user_id', $2, true)");
    expect(set?.values).toEqual([TENANT, '']);
    expect(sent.every((s) => s.queryMode === 'extended')).toBe(true);
    expect(released).toEqual([false]);
  });

  it('利用者の境界では、テナントの値を空にする', async () => {
    const { db, sent } = fakePool({});
    await db.withWarifuUser(USER, async () => undefined);
    expect(sent.find((s) => s.text.includes('set_config'))?.values).toEqual(['', USER]);
  });

  it('最後の読み直しで値が違えば、boundary_tampered で ROLLBACK する', async () => {
    const { db, sent } = fakePool({
      finalCheck: () => ({ t: '00000000-0000-4000-8000-000000000000', u: '', r: 'warifu_idp' }),
    });
    await expect(db.withTenant(TENANT, async () => 1)).rejects.toMatchObject({
      code: 'boundary_tampered',
    });
    expect(sent.at(-1)?.text).toBe('ROLLBACK');
    expect(sent.some((s) => s.text === 'COMMIT')).toBe(false);
  });

  it('ロールが違えば boundary_tampered', async () => {
    const { db } = fakePool({
      finalCheck: (sent) => ({ t: String(sent[2]?.values[0]), u: '', r: 'warifu_owner' }),
    });
    await expect(db.withTenant(TENANT, async () => 1)).rejects.toMatchObject({
      code: 'boundary_tampered',
    });
  });

  it('スーパーユーザーや BYPASSRLS なら unsafe_role で、問い合わせを送らずに接続を捨てる', async () => {
    for (const role of [
      { role: 'warifu_idp', rolsuper: true, rolbypassrls: false },
      { role: 'warifu_idp', rolsuper: false, rolbypassrls: true },
      { role: 'warifu_bootstrap', rolsuper: false, rolbypassrls: false },
    ]) {
      const { db, sent, released } = fakePool({ role });
      await expect(db.withTenant(TENANT, async () => 1)).rejects.toMatchObject({
        code: 'unsafe_role',
      });
      expect(sent).toHaveLength(1);
      expect(released).toEqual([true]);
    }
  });

  it('pg のエラーは code と制約の名前だけにする', async () => {
    const { db, sent } = fakePool({ failOn: /^INSERT/ });
    const error = await db
      .withTenant(TENANT, (tx) => tx.execute(sql`INSERT INTO s.t (a) VALUES (${'secret-value'})`))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DbError);
    expect(error).toMatchObject({ code: '23505', constraint: 'generation_lookup_mac_key' });
    expect(JSON.stringify(error)).not.toContain('secret');
    expect(String(error)).not.toContain('secret');
    expect((error as { detail?: unknown }).detail).toBeUndefined();
    expect(sent.at(-1)?.text).toBe('ROLLBACK');
  });

  it('fn の例外は、そのまま投げ直し、ROLLBACK する', async () => {
    const { db, sent } = fakePool({});
    const failure = new Error('fn failed');
    await expect(
      db.withTenant(TENANT, async () => {
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(sent.at(-1)?.text).toBe('ROLLBACK');
  });

  it('入れ子と、閉じた tx', async () => {
    const { db } = fakePool({});
    await expect(
      db.withTenant(TENANT, () => db.withWarifuUser(USER, async () => 1)),
    ).rejects.toMatchObject({ code: 'nested_boundary' });
    let leaked: Parameters<Parameters<typeof db.withTenant>[1]>[0] | undefined;
    await db.withTenant(TENANT, async (tx) => {
      leaked = tx;
    });
    await expect(leaked?.query(sql`SELECT 1`)).rejects.toMatchObject({ code: 'tx_closed' });
  });

  it('タグで作っていない文は送らない', async () => {
    const { db, sent } = fakePool({});
    await expect(
      db.withTenant(TENANT, (tx) => tx.query({ text: 'SELECT 1', values: [] })),
    ).rejects.toThrow('この形の SQL は送らない');
    expect(sent.some((s) => s.text === 'SELECT 1')).toBe(false);
  });

  it('UUID でない ID は、接続を取る前に拒否する', async () => {
    const { db, sent } = fakePool({});
    await expect(db.withTenant("' OR 1=1 --" as never, async () => 1)).rejects.toThrow(
      'ID の形が違う',
    );
    expect(sent).toHaveLength(0);
  });
});
