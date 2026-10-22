// relay の解決関数（不変条件8の例外、plan 2章「逆引きをしない」。テスト4の後半とテスト5の前提）。
// ワーカーの DB と globalSetup の鍵サービスを使う。

import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { aliasLookupMessage } from '../../packages/warifu-core/src/aliases.ts';
import type { RelayDb } from '../../packages/warifu-core/src/db/relay.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { Db } from '../../packages/warifu-core/src/db/types.ts';
import { parseTenantId, parseWarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { createRelayKeyClient } from '../../packages/warifu-core/src/keys/relay.ts';
import { rawRoleClient, relayDb, serviceDb, sqlstateOf } from '../setup/db.ts';
import { keysvcConnection } from '../setup/keys.ts';

const tenant = parseTenantId(randomUUID());
const user = parseWarifuUserId(randomUUID());
const firstMac = new Uint8Array(randomBytes(32));

let idp: Db;
let companyApi: Db;
let relay: RelayDb;
const raws: pg.Client[] = [];

async function raw(role: 'warifu_idp' | 'warifu_relay' | 'warifu_company_api') {
  const client = await rawRoleClient(role);
  raws.push(client);
  return client;
}

beforeAll(async () => {
  idp = await serviceDb('idp');
  companyApi = await serviceDb('company-api');
  relay = await relayDb();
  await idp.withTenant(tenant, (tx) =>
    tx.execute(
      sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
          VALUES (${tenant}, ${user}, 1, ${firstMac})`,
    ),
  );
});

afterAll(async () => {
  await Promise.all([idp.close(), companyApi.close(), relay.close()]);
  await Promise.all(raws.map((client) => client.end()));
});

describe('漏えい：relay の解決関数（plan 2章「逆引きをしない」）', () => {
  it('返すのは、利用者 ID とテナント ID の2つだけ', async () => {
    // 攻撃者が持っている情報：生きている別名の照合用の HMAC（relay の通常の入力）
    // 試す経路：relayDb().resolveAlias と、warifu_relay の生の接続で関数を呼ぶ
    // 期待する結果：列は user_id と tenant_id の2つ。1行。連絡先や別名は返らない
    // plan 11章：番号なし（不変条件8の例外。plan 2章「逆引きをしない」。テスト4の後半と5の前提）
    expect(await relay.resolveAlias(firstMac)).toEqual({ userId: user, tenantId: tenant });
    const client = await raw('warifu_relay');
    const result = await client.query('SELECT * FROM relay.resolve_alias($1)', [
      Buffer.from(firstMac),
    ]);
    expect(result.fields.map((f) => f.name)).toEqual(['user_id', 'tenant_id']);
    expect(result.rows).toEqual([{ user_id: user, tenant_id: tenant }]);
  });

  it('廃番、存在しない、長さの違う入力、NULL は、どれも同じ0行', async () => {
    // 攻撃者が持っている情報：廃番にした別名（第2世代を足した後の第1世代）、乱数の32バイト、3バイト、NULL
    // 試す経路：warifu_relay の生の接続で関数を呼び、生きているかどうかを見分けようとする
    // 期待する結果：どれも0行で、区別がつかない
    // plan 11章：番号なし（不変条件8の例外、不変条件10。plan 2章「逆引きをしない」）
    const retiredTenant = parseTenantId(randomUUID());
    const retiredUser = parseWarifuUserId(randomUUID());
    const retired = new Uint8Array(randomBytes(32));
    await idp.withTenant(retiredTenant, (tx) =>
      tx.execute(
        sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
            VALUES (${retiredTenant}, ${retiredUser}, 1, ${retired})`,
      ),
    );
    await companyApi.withTenant(retiredTenant, (tx) =>
      tx.execute(
        sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
            VALUES (${retiredTenant}, ${retiredUser}, 2, ${new Uint8Array(randomBytes(32))})`,
      ),
    );
    const client = await raw('warifu_relay');
    for (const input of [
      Buffer.from(retired),
      randomBytes(32),
      randomBytes(3),
      Buffer.concat([Buffer.from(firstMac), Buffer.from([0])]),
      null,
    ]) {
      const result = await client.query('SELECT * FROM relay.resolve_alias($1)', [input]);
      expect(result.rows).toEqual([]);
    }
    expect(await relay.resolveAlias(retired)).toBeUndefined();
    await expect(relay.resolveAlias(new Uint8Array(3))).rejects.toMatchObject({
      code: 'invalid_input',
    });
  });

  it('relay 以外のサービスは、解決関数を呼べない', async () => {
    // 攻撃者が持っている情報：侵害した idp か company-api（ATK-07、TH-62）と、照合用の HMAC
    // 試す経路：warifu_idp と warifu_company_api の生の接続で、関数を呼ぶ
    // 期待する結果：42501
    // plan 11章：番号なし（不変条件8の例外。plan 2章「逆引きをしない」）
    for (const role of ['warifu_idp', 'warifu_company_api'] as const) {
      const client = await raw(role);
      expect(
        await sqlstateOf(
          client.query('SELECT * FROM relay.resolve_alias($1)', [Buffer.from(firstMac)]),
        ),
      ).toBe('42501');
    }
  });

  it('relay は表を直接読めず、ほかのサービスは照合用の HMAC を読めない', async () => {
    // 攻撃者が持っている情報：侵害した relay、idp、company-api（ATK-07）
    // 試す経路：warifu_relay で aliases.generation を SELECT。idp と company-api で、境界の中から lookup_mac を SELECT
    // 期待する結果：すべて 42501
    // plan 11章：番号なし（不変条件8の例外。plan 2章「逆引きをしない」）
    const relayClient = await raw('warifu_relay');
    expect(await sqlstateOf(relayClient.query('SELECT tenant_id FROM aliases.generation'))).toBe(
      '42501',
    );
    for (const db of [idp, companyApi]) {
      await expect(
        db.withTenant(tenant, (tx) => tx.query(sql`SELECT lookup_mac FROM aliases.generation`)),
      ).rejects.toMatchObject({ code: '42501' });
    }
  });

  it('世代を書き換えたり、照合用の HMAC を再利用したりできない', async () => {
    // 攻撃者が持っている情報：侵害した company-api（ATK-07、TH-41）
    // 試す経路：既存の lookup_mac で新しい世代を INSERT。UPDATE と DELETE。第1世代の INSERT。別テナントの行の INSERT
    // 期待する結果：23505、42501、42501、42501、42501。行は変わらない
    // plan 11章：番号なし（テスト4の「割り当て処理は一意制約により旧値を返せない」の土台）
    const insert = (tenantId: string, generation: number, mac: Uint8Array) =>
      companyApi.withTenant(tenant, (tx) =>
        tx.execute(
          sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
              VALUES (${tenantId}, ${user}, ${generation}, ${mac})`,
        ),
      );
    const codeOf = (promise: Promise<unknown>) =>
      promise.then(
        () => undefined,
        (e: { code?: string }) => e.code,
      );
    expect(await codeOf(insert(tenant, 5, firstMac))).toBe('23505');
    expect(
      await codeOf(
        companyApi.withTenant(tenant, (tx) =>
          tx.execute(sql`UPDATE aliases.generation SET generation = 9 WHERE tenant_id = ${tenant}`),
        ),
      ),
    ).toBe('42501');
    expect(
      await codeOf(
        companyApi.withTenant(tenant, (tx) =>
          tx.execute(sql`DELETE FROM aliases.generation WHERE tenant_id = ${tenant}`),
        ),
      ),
    ).toBe('42501');
    expect(await codeOf(insert(tenant, 1, new Uint8Array(randomBytes(32))))).toBe('42501');
    expect(await codeOf(insert(randomUUID(), 3, new Uint8Array(randomBytes(32))))).toBe('42501');
    expect(await relay.resolveAlias(firstMac)).toEqual({ userId: user, tenantId: tenant });
  });

  it('導出から解決までの往復。再発行すると、前の世代は解決できない', async () => {
    // 攻撃者が持っている情報：なし（正常系。テスト4・5の前提）
    // 試す経路：idp の deriveAlias → mac('alias_lookup', aliasLookupMessage(…)) → withTenant で第1世代を INSERT →
    //           relay の mac → resolveAlias。company-api が第2世代を足す
    // 期待する結果：(U, T) が返る。第2世代の後は、第1世代の HMAC は0行、第2世代の HMAC は (U, T)
    // plan 11章：番号なし（テスト4の後半と5の前提）
    const t = parseTenantId(randomUUID());
    const u = parseWarifuUserId(randomUUID());
    const idpKeys = createIdpKeyClient(keysvcConnection('idp'));
    const companyKeys = createCompanyApiKeyClient(keysvcConnection('company-api'));
    const relayKeys = createRelayKeyClient(keysvcConnection('relay'));

    const first = await idpKeys.deriveAlias({ tenantId: t, userId: u, generation: 1 });
    const firstLookup = await idpKeys.mac('alias_lookup', aliasLookupMessage(first));
    await idp.withTenant(t, (tx) =>
      tx.execute(
        sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
            VALUES (${t}, ${u}, 1, ${firstLookup})`,
      ),
    );
    // relay は、届いたメールの宛先（別名）から、自分で照合用の HMAC を作る。
    const atRelay = await relayKeys.mac('alias_lookup', aliasLookupMessage(first));
    expect(await relay.resolveAlias(atRelay)).toEqual({ userId: u, tenantId: t });

    const second = await companyKeys.deriveAlias({ tenantId: t, userId: u, generation: 2 });
    expect(second).not.toBe(first);
    const secondLookup = await companyKeys.mac('alias_lookup', aliasLookupMessage(second));
    await companyApi.withTenant(t, (tx) =>
      tx.execute(
        sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
            VALUES (${t}, ${u}, 2, ${secondLookup})`,
      ),
    );
    expect(await relay.resolveAlias(atRelay)).toBeUndefined();
    expect(
      await relay.resolveAlias(await relayKeys.mac('alias_lookup', aliasLookupMessage(second))),
    ).toEqual({ userId: u, tenantId: t });
  });
});
