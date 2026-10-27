// 監査ログのチェーン（CAP-17、plan 11章 テスト8）。globalSetup の鍵サービスと、ワーカーの DB を使う。
// ワーカーの DB はファイルの間で共有するので、偽の行は境界の中で足して ROLLBACK する（DB を汚さない）。

import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type AuditChainRow,
  type AuditEventRow,
  appendAudit,
  defineAuditEvent,
  readAuditRows,
  verifyAuditChain,
  verifyAuditRows,
} from '../../packages/warifu-core/src/audit/index.ts';
import type { RelayDb } from '../../packages/warifu-core/src/db/relay.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { Db, Tx } from '../../packages/warifu-core/src/db/types.ts';
import {
  parseTenantId,
  parseWarifuUserId,
  type TenantId,
  type WarifuUserId,
} from '../../packages/warifu-core/src/ids.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { createRelayKeyClient } from '../../packages/warifu-core/src/keys/relay.ts';
import { rawRoleClient, relayDb, serviceDb, sqlstateOf } from '../setup/db.ts';
import { keysvcConnection } from '../setup/keys.ts';

const PROBE = defineAuditEvent('test.probe', { n: 'int', target: 'uuid' });

let idp: Db;
let companyApi: Db;
let relay: RelayDb;
let idpKeys: ReturnType<typeof createIdpKeyClient>;
let companyKeys: ReturnType<typeof createCompanyApiKeyClient>;
let relayKeys: ReturnType<typeof createRelayKeyClient>;
const raws: pg.Client[] = [];

const tenantA = parseTenantId(randomUUID());
const tenantB = parseTenantId(randomUUID());
const user1 = parseWarifuUserId(randomUUID());
const user2 = parseWarifuUserId(randomUUID());

async function raw(role: 'warifu_idp' | 'warifu_relay' | 'warifu_company_api') {
  const client = await rawRoleClient(role);
  raws.push(client);
  return client;
}

const probe = (n: number) => ({ n, target: randomUUID() });

beforeAll(async () => {
  idp = await serviceDb('idp');
  companyApi = await serviceDb('company-api');
  relay = await relayDb();
  idpKeys = createIdpKeyClient(keysvcConnection('idp'));
  companyKeys = createCompanyApiKeyClient(keysvcConnection('company-api'));
  relayKeys = createRelayKeyClient(keysvcConnection('relay'));
});

afterAll(async () => {
  await Promise.all([idp.close(), companyApi.close(), relay.close()]);
  await Promise.all(raws.map((client) => client.end()));
});

async function inTenant<T>(db: Db, tenantId: TenantId, fn: (tx: Tx) => Promise<T>) {
  return db.withTenant(tenantId, fn);
}

async function inUser<T>(db: Db, userId: WarifuUserId, fn: (tx: Tx) => Promise<T>) {
  return db.withWarifuUser(userId, fn);
}

describe('漏えい：監査ログのチェーン（plan 11章 テスト8）', () => {
  it('3つのサービス、2つのテナント、2人の利用者で追記し、どの範囲でもチェーンが検証できる', async () => {
    // 攻撃者が持っている情報：なし（正常系。検証が通ることが、改ざんの検出の前提）
    // 試す経路：idp、company-api、relay から、2つのテナントと2人の利用者の範囲で追記し、各範囲で verifyAuditChain
    // 期待する結果：すべて ok。seq は全体で、scope_seq は範囲ごとに連続する
    // plan 11章：テスト8
    await inTenant(idp, tenantA, (tx) => appendAudit(tx, idpKeys, PROBE, probe(1)));
    await inTenant(companyApi, tenantA, (tx) => appendAudit(tx, companyKeys, PROBE, probe(2)));
    await inTenant(relay, tenantB, (tx) => appendAudit(tx, relayKeys, PROBE, probe(3)));
    await inUser(idp, user1, (tx) => appendAudit(tx, idpKeys, PROBE, probe(4)));
    await inUser(relay, user1, (tx) => appendAudit(tx, relayKeys, PROBE, probe(5)));
    await inUser(companyApi, user2, (tx) => appendAudit(tx, companyKeys, PROBE, probe(6)));

    const checks: [Db, 'tenant' | 'user', string, number][] = [
      [idp, 'tenant', tenantA, 2],
      [companyApi, 'tenant', tenantB, 1],
      [relay, 'user', user1, 2],
      [idp, 'user', user2, 1],
    ];
    for (const [db, kind, id, events] of checks) {
      const verify = (tx: Tx) => verifyAuditChain(tx, idpKeys);
      const result =
        kind === 'tenant'
          ? await db.withTenant(parseTenantId(id), verify)
          : await db.withWarifuUser(parseWarifuUserId(id), verify);
      expect(result.ok).toBe(true);
      expect(result.scopeEvents).toBe(events);
      expect(result.chainRows).toBeGreaterThanOrEqual(6);
    }
    const services = await idp.withTenant(tenantA, async (tx) =>
      (await readAuditRows(tx)).events.map((e) => e.service),
    );
    expect(services).toEqual(['idp', 'company-api']);
  });

  it('同時に追記しても、通番が連続し、検証が通る', async () => {
    // 攻撃者が持っている情報：なし（同上。アドバイザリロックで直列になっていることの確認）
    // 試す経路：20件を同時に追記する（2つのサービス、同じテナント）
    // 期待する結果：seq と scope_seq が連続し、検証が ok
    // plan 11章：テスト8
    const tenant = parseTenantId(randomUUID());
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        i % 2 === 0
          ? inTenant(idp, tenant, (tx) => appendAudit(tx, idpKeys, PROBE, probe(i)))
          : inTenant(companyApi, tenant, (tx) => appendAudit(tx, companyKeys, PROBE, probe(i))),
      ),
    );
    const result = await idp.withTenant(tenant, (tx) => verifyAuditChain(tx, idpKeys));
    expect(result).toMatchObject({ ok: true, scopeEvents: 20 });
  });

  it('アプリのロールでは、監査ログを書き換えも消しもできない', async () => {
    // 攻撃者が持っている情報：SQL インジェクションで、warifu_idp として境界の中で任意の SQL を実行できる（ATK-02）
    // 試す経路：rawRoleClient で境界を設定し、audit.chain と audit.events に UPDATE、DELETE、TRUNCATE
    // 期待する結果：すべて 42501。行は変わらない
    // plan 11章：テスト8
    const before = await idp.withTenant(tenantA, (tx) => readAuditRows(tx));
    const client = await raw('warifu_idp');
    await client.query("SELECT pg_catalog.set_config('warifu.tenant_id', $1, false)", [tenantA]);
    for (const text of [
      'UPDATE audit.chain SET mac = prev_mac',
      'DELETE FROM audit.chain',
      'TRUNCATE audit.chain',
      "UPDATE audit.events SET event_type = 'test.other'",
      'DELETE FROM audit.events',
      'TRUNCATE audit.events',
    ]) {
      expect(await sqlstateOf(client.query(text))).toBe('42501');
    }
    const after = await idp.withTenant(tenantA, (tx) => readAuditRows(tx));
    expect(after.events).toEqual(before.events);
    expect(after.chain.slice(0, before.chain.length)).toEqual(before.chain);
  });

  it('別の範囲、別のサービス、境界の外として書けない', async () => {
    // 攻撃者が持っている情報：同上（warifu_idp として任意の SQL）
    // 試す経路：境界 A の中で、テナント B の行と、service = 'relay' の行を INSERT。境界なしで chain に INSERT
    // 期待する結果：すべて 42501
    // plan 11章：テスト8
    const inA = await raw('warifu_idp');
    await inA.query("SELECT pg_catalog.set_config('warifu.tenant_id', $1, false)", [tenantA]);
    const insertEvent = (tenantId: string, service: string) =>
      inA.query(
        `INSERT INTO audit.events (seq, scope_seq, occurred_at, service, event_type, tenant_id, attrs)
         VALUES (999999999, 1, now(), $1, 'test.probe', $2, '{}')`,
        [service, tenantId],
      );
    expect(await sqlstateOf(insertEvent(tenantB, 'idp'))).toBe('42501');
    expect(await sqlstateOf(insertEvent(tenantA, 'relay'))).toBe('42501');
    const outside = await raw('warifu_idp');
    const mac = randomBytes(32);
    expect(
      await sqlstateOf(
        outside.query(
          'INSERT INTO audit.chain (seq, content_mac, prev_mac, mac) VALUES (999999999, $1, $1, $1)',
          [mac],
        ),
      ),
    ).toBe('42501');
  });

  it('別のテナントの監査ログを読めない', async () => {
    // 攻撃者が持っている情報：侵害した company-api と、テナント B の資格情報（ATK-02、ATK-03）
    // 試す経路：テナント B の境界で audit.events を全件読む。境界なしで audit.chain を読む
    // 期待する結果：A の行は0件。境界なしの chain は0件
    // plan 11章：テスト8
    const events = await companyApi.withTenant(tenantB, (tx) =>
      tx.query<{ tenant_id: string | null; user_id: string | null }>(
        sql`SELECT tenant_id, user_id FROM audit.events`,
      ),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e) => e.tenant_id === tenantB && e.user_id === null)).toBe(true);
    const client = await raw('warifu_company_api');
    expect((await client.query('SELECT seq FROM audit.chain')).rowCount).toBe(0);
    expect((await client.query('SELECT seq FROM audit.events')).rowCount).toBe(0);
  });

  it('鍵を持たない者が足した偽の行を見つける', async () => {
    // 攻撃者が持っている情報：同上（warifu_idp として境界の中で任意の SQL。鍵サービスの資格情報は持たない）
    // 試す経路：withTenant の fn の中で、乱数の MAC で chain と events に1件ずつ足し、検証する。
    //           その後、例外を投げて ROLLBACK する
    // 期待する結果：検証は mac で失敗する。ROLLBACK の後の検証は ok（ワーカーの DB を汚さない）
    // plan 11章：テスト8
    const rollback = new Error('rollback');
    let inside: Awaited<ReturnType<typeof verifyAuditChain>> | undefined;
    await expect(
      idp.withTenant(tenantA, async (tx) => {
        const [head] = await tx.query<{ seq: string; mac: Uint8Array }>(
          sql`SELECT seq, mac FROM audit.chain ORDER BY seq DESC LIMIT 1`,
        );
        const [scope] = await tx.query<{ scope_seq: string }>(
          sql`SELECT scope_seq FROM audit.events ORDER BY scope_seq DESC LIMIT 1`,
        );
        const seq = BigInt(head?.seq ?? '0') + 1n;
        await tx.execute(
          sql`INSERT INTO audit.chain (seq, content_mac, prev_mac, mac)
              VALUES (${seq}, ${new Uint8Array(randomBytes(32))}, ${new Uint8Array(head?.mac ?? new Uint8Array(32))},
                      ${new Uint8Array(randomBytes(32))})`,
        );
        await tx.execute(
          sql`INSERT INTO audit.events (seq, scope_seq, occurred_at, service, event_type, tenant_id, attrs)
              VALUES (${seq}, ${BigInt(scope?.scope_seq ?? '0') + 1n}, ${new Date()}, ${'idp'},
                      ${'test.forged'}, ${tenantA}, ${'{}'}::jsonb)`,
        );
        inside = await verifyAuditChain(tx, idpKeys);
        throw rollback;
      }),
    ).rejects.toBe(rollback);
    expect(inside?.ok).toBe(false);
    expect(inside?.failure?.reason).toBe('mac');
    const after = await idp.withTenant(tenantA, (tx) => verifyAuditChain(tx, idpKeys));
    expect(after.ok).toBe(true);
  });

  it.each([
    [
      '属性の書き換え',
      (r: { chain: AuditChainRow[]; events: AuditEventRow[] }) => {
        r.events[0] = {
          ...(r.events[0] as AuditEventRow),
          attrs: { n: 999, target: randomUUID() },
        };
      },
      'content',
    ],
    [
      '本文の行の削除',
      (r: { chain: AuditChainRow[]; events: AuditEventRow[] }) => {
        r.events.splice(0, 1);
      },
      'scope_gap',
    ],
    [
      'チェーンの途中の行の削除',
      (r: { chain: AuditChainRow[]; events: AuditEventRow[] }) => {
        r.chain.splice(1, 1);
      },
      'gap',
    ],
    [
      'チェーンの2行の入れ替え',
      (r: { chain: AuditChainRow[]; events: AuditEventRow[] }) => {
        const a = r.chain[1] as AuditChainRow;
        const b = r.chain[2] as AuditChainRow;
        r.chain[1] = { ...b, seq: a.seq };
        r.chain[2] = { ...a, seq: b.seq };
      },
      'link',
    ],
    [
      'mac の差し替え',
      (r: { chain: AuditChainRow[]; events: AuditEventRow[] }) => {
        r.chain[1] = { ...(r.chain[1] as AuditChainRow), mac: new Uint8Array(randomBytes(32)) };
      },
      'mac',
    ],
  ])('DB を書き換えられる運用者による %s を見つける', async (_label, tamper, reason) => {
    // 攻撃者が持っている情報：DB を書き換えられる運用者（ATK-06、TH-60）。鍵サービスの鍵は持たない
    // 試す経路：DB は書き換えず、読んだ行をメモリの中で書き換えて verifyAuditRows に渡す
    // 期待する結果：属性の書き換えは content、本文の削除は scope_gap、チェーンの途中の削除は gap、入れ替えは link、
    //               mac の差し替えは mac で失敗する
    // plan 11章：テスト8
    const tenant = parseTenantId(randomUUID());
    for (let i = 0; i < 3; i += 1) {
      await inTenant(idp, tenant, (tx) => appendAudit(tx, idpKeys, PROBE, probe(i)));
    }
    const rows = await idp.withTenant(tenant, (tx) => readAuditRows(tx));
    expect(
      (await verifyAuditRows({ ...rows, boundary: { kind: 'tenant', tenantId: tenant } }, idpKeys))
        .ok,
    ).toBe(true);
    const copy = { chain: [...rows.chain], events: [...rows.events] };
    tamper(copy);
    const result = await verifyAuditRows(
      { ...copy, boundary: { kind: 'tenant', tenantId: tenant } },
      idpKeys,
    );
    expect(result.ok).toBe(false);
    expect(result.failure?.reason).toBe(reason);
  });
});
