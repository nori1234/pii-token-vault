// 企業への回復の知らせ（ADR 0027 の O-79、O-81、RP-53）。idp の内部 API から、2段で呼ばれる。
//
// - 準備（prepare。回復が成立する前）：利用者が接続しているテナントごとに、回復の SET を、まだ配送できない形
//   （recovery_confirmed = false）で送信待ちに入れる。company-api に届かなければ、idp は回復を成立させない。
// - 確定（confirm。回復が成立した後）：準備した行を配送できるようにする。取り消された回復は確定されないので、
//   企業には届かない（成立と取消の競合を含む）。確定は、idp が届くまで送り直す。確定されない行は30日で消す。
// - sub は置かず、送るときにテナントの範囲で aliases.subject から引く。緊急停止したテナント、受け口のないテナント、
//   sub のないテナントには入れない（ID トークンの recovered_at では伝わる）。
// - 同じ回復（回復の記録の ID）の再送は、二重に入れない（テナントと recovery_ref の一意制約）。
// - 初めて送る時刻は、確定から、テナントごとに独立した0〜6時間の乱数だけ遅らせる（同じ回復を複数の企業が受け取る
//   ので、届く時刻の近さで突き合わせさせない。不変条件5）。

import {
  randomBytesOf,
  randomUuid,
  type TenantId,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { sql, type Tx } from '@pii-token-vault/warifu-core/db';
import { RECOVERY_NOTIFIED } from './audit-events.ts';
import type { CompanyApiConfig } from './config.ts';
import type { DeskDeps } from './desk.ts';

/** 回復の SET を初めて送るまでの、意図した遅延の上限（ミリ秒）。確定の時刻から数える。 */
export const RECOVERY_SET_MAX_DELAY_MS = 6 * 3600 * 1000;
/** 確定されない準備の行を消すまで（ミリ秒）。 */
export const RECOVERY_UNCONFIRMED_KEEP_MS = 30 * 24 * 3600 * 1000;

function recoveryDelayMs(): number {
  const bytes = randomBytesOf(4);
  const value =
    ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0);
  return (value >>> 0) % (RECOVERY_SET_MAX_DELAY_MS + 1);
}

export async function enqueueRecovered(
  deps: DeskDeps,
  config: CompanyApiConfig,
  input: {
    readonly userId: WarifuUserId;
    readonly attemptId: string;
    readonly tenantIds: readonly TenantId[];
    readonly recoveredDay: number;
  },
): Promise<number> {
  let queued = 0;
  for (const tenantId of new Set(input.tenantIds)) {
    const tenant = config.tenants.get(tenantId);
    if (tenant === undefined || tenant.suspended || tenant.webhookUrl === undefined) continue;
    queued += await deps.db.withTenant(tenantId, async (tx) => {
      const [subject] = await tx.query<{ sub: string }>(
        sql`SELECT sub FROM aliases.subject WHERE user_id = ${input.userId}`,
      );
      if (subject === undefined) return 0;
      // 配送できない形で入れる（deliver_after は確定のときに決め直す）。
      return tx.execute(
        sql`INSERT INTO company_api.set_outbox
              (event_id, tenant_id, event_type, state, user_id, recovery_ref, recovered_day, recovery_confirmed,
               deliver_after)
            VALUES (${randomUuid()}, ${tenantId}, 'account_recovered', ${null}, ${input.userId},
                    ${input.attemptId}, ${input.recoveredDay}, false, ${deps.now()})
            ON CONFLICT (tenant_id, recovery_ref) DO NOTHING`,
      );
    });
  }
  return queued;
}

/**
 * 準備した回復の SET を確定し、配送できるようにする（回復が成立した後に idp が呼ぶ）。同じ回復の確定の送り直しは、
 * 確定済みの行を変えない。確定した行の数を返す。
 */
export async function confirmRecovered(
  deps: DeskDeps,
  config: CompanyApiConfig,
  input: {
    readonly userId: WarifuUserId;
    readonly attemptId: string;
    readonly tenantIds: readonly TenantId[];
  },
): Promise<number> {
  let confirmed = 0;
  for (const tenantId of new Set(input.tenantIds)) {
    if (!config.tenants.has(tenantId)) continue;
    confirmed += await deps.db.withTenant(tenantId, async (tx) => {
      const updated = await tx.execute(
        sql`UPDATE company_api.set_outbox
               SET recovery_confirmed = true,
                   deliver_after = ${new Date(deps.now().getTime() + recoveryDelayMs())}
             WHERE event_type = 'account_recovered' AND recovery_ref = ${input.attemptId}
               AND user_id = ${input.userId} AND recovery_confirmed = false`,
      );
      if (updated === 1) await appendAudit(tx, deps.keys, RECOVERY_NOTIFIED, {}, { now: deps.now });
      return updated;
    });
  }
  return confirmed;
}

/** 確定されないまま30日を過ぎた準備の行を消す（withTenant の中で呼ぶ）。消した数を返す。 */
export async function purgeUnconfirmedRecovered(tx: Tx, now: Date): Promise<number> {
  return tx.execute(
    sql`DELETE FROM company_api.set_outbox
         WHERE event_type = 'account_recovered' AND recovery_confirmed = false
           AND created_at <= ${new Date(now.getTime() - RECOVERY_UNCONFIRMED_KEEP_MS)}`,
  );
}

/** 回復の SET の宛先（テナントの sub）と、回復した日。行がなければ undefined。 */
export async function recoveredEventOf(
  deps: Pick<DeskDeps, 'db'>,
  tenantId: TenantId,
  userId: string,
): Promise<{ readonly sub: string } | undefined> {
  return deps.db.withTenant(tenantId, async (tx) => {
    const [subject] = await tx.query<{ sub: string }>(
      sql`SELECT sub FROM aliases.subject WHERE user_id = ${userId}`,
    );
    return subject;
  });
}
