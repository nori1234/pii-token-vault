// テナントの参加の状態の記録（ADR 0028 の O-95）。参加の状態、移行中の期限、参加の状態の版は、配備のときの静的な
// 設定にあり、どのルートからも書き換えない。運営者が設定を直して配備し直したことを、起動のときに監査ログに残す。
//
// - 起動のとき、テナントごとに（withTenant）、監査ログに最後に残した版（company_api.participation.changed の
//   revision）を読み、今の設定の版と違えば（または、まだ残していなければ）、事象を1つ足す。
// - 延長（O-93）も、参加の状態の変更（O-98・O-100）も、運営者が版を上げて配備し直すので、この事象に残る。
// - 利用者の画面には出さない（ADR 0028 の O-105）。

import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { type Db, sql } from '@pii-token-vault/warifu-core/db';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import { PARTICIPATION_CHANGED } from './audit-events.ts';
import type { CompanyApiConfig } from './config.ts';

const DAY_MS = 24 * 3600 * 1000;

/** YYYY-MM-DD を、1970-01-01 からの日数にする（期限がなければ 0）。 */
export function deadlineDay(deadline: string | null): number {
  if (deadline === null) return 0;
  return Math.floor(Date.parse(`${deadline}T00:00:00Z`) / DAY_MS);
}

export async function recordParticipationRevisions(deps: {
  readonly config: CompanyApiConfig;
  readonly db: Db;
  readonly keys: CompanyApiKeyClient;
  readonly now: () => Date;
}): Promise<number> {
  let recorded = 0;
  for (const tenant of deps.config.tenants.values()) {
    const added = await deps.db.withTenant(tenant.tenantId, async (tx) => {
      // 同じテナントを同時に起動した2つのプロセスが、二重に残さないように、テナントごとに直列にする。
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtextextended(${`participation:${tenant.tenantId}`}, 0))`,
      );
      const [last] = await tx.query<{ revision: string | null }>(
        sql`SELECT attrs->>'revision' AS revision FROM audit.events
             WHERE tenant_id = ${tenant.tenantId} AND event_type = ${PARTICIPATION_CHANGED.type}
             ORDER BY seq DESC LIMIT 1`,
      );
      if (last !== undefined && Number(last.revision) === tenant.participationRevision)
        return false;
      await appendAudit(
        tx,
        deps.keys,
        PARTICIPATION_CHANGED,
        {
          revision: tenant.participationRevision,
          participation: tenant.participation,
          deadline_day: deadlineDay(tenant.migrationDeadline),
        },
        { now: deps.now },
      );
      return true;
    });
    if (added) recorded += 1;
  }
  return recorded;
}
