// 参加の状態の記録（ADR 0010、ADR 0028 の O-93・O-95・O-105）。参加の状態、移行中の期限、参加の状態の版は、配備の
// ときの静的な設定にだけあり、どのルートからも書き換えない。運営者が版を上げて配備し直したことは、起動のときに
// 監査ログに残る（延長と、参加の状態の変更の記録）。

import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { parseTenantId, type TenantId } from '../../packages/warifu-core/src/ids.ts';
import { newApiClient, startTestCompanyApi, type TenantSpec } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';

async function participationEvents(tenantId: TenantId) {
  const db = await serviceDb('company-api');
  try {
    return await db.withTenant(tenantId, (tx) =>
      tx.query<{ attrs: Record<string, unknown> }>(
        sql`SELECT attrs FROM audit.events
             WHERE tenant_id = ${tenantId} AND event_type = 'company_api.participation.changed'
             ORDER BY seq`,
      ),
    );
  } finally {
    await db.close();
  }
}

async function boot(spec: TenantSpec) {
  const api = await startTestCompanyApi({ tenants: [spec] });
  await api.stop();
}

describe('参加の状態の記録（ADR 0028 の O-95）', () => {
  it('版が変わった配備だけ、起動のときに監査ログに残す。期限は日数で残し、利用者の値は入れない', async () => {
    // 攻撃者が持っている情報：なし（運営者の配備の記録を確かめる）
    // 試す経路：同じテナントを、版 0（完全な参加）、版 0（同じ）、版 1（移行中、期限あり）、版 1（同じ）の順に起動する
    // 期待する結果：事象は2つだけ（版 0 と版 1）。属性は版、参加の状態、期限の日数だけ
    // plan 11章：テスト6（参加の状態は配備だけで変わる）
    const tenantId = parseTenantId(randomUUID());
    const client = newApiClient();
    const relayDomain = `t${randomUUID().slice(0, 8)}.relay.warifu.test`;
    await boot({ tenantId, client, relayDomain });
    await boot({ tenantId, client, relayDomain });
    expect((await participationEvents(tenantId)).map((e) => e.attrs)).toEqual([
      { revision: 0, participation: 'full', deadline_day: 0 },
    ]);

    const migrating: TenantSpec = {
      tenantId,
      client,
      relayDomain,
      participation: 'migrating',
      migrationDeadline: '2027-05-14',
      participationRevision: 1,
    };
    await boot(migrating);
    await boot(migrating);
    const deadlineDay = Date.parse('2027-05-14T00:00:00Z') / 86_400_000;
    expect((await participationEvents(tenantId)).map((e) => e.attrs)).toEqual([
      { revision: 0, participation: 'full', deadline_day: 0 },
      { revision: 1, participation: 'migrating', deadline_day: deadlineDay },
    ]);
  });
});
