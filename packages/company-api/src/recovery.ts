// 企業への回復の知らせ（ADR 0027 の O-81、RP-53）。idp の配送の回が、成立した回復だけを内部 API で渡す
// （idp は、成立と同じトランザクションで自分の送信待ちに置き、渡せるまで送り直す）。
//
// - 利用者が接続しているテナントごとに、回復の SET を送信待ちに入れる。sub は置かず、送るときにテナントの範囲で
//   aliases.subject から引く。緊急停止したテナント、受け口のないテナント、sub のないテナントには入れない
//   （ID トークンの recovered_at では伝わる）。
// - 同じ回復（回復の記録の ID）の送り直しは、二重に入れない（テナントと recovery_ref の一意制約）。回復した日は、
//   idp が成立の時刻から決めて送信待ちに持たせた値なので、送り直しが日付をまたいでも変わらない。
// - 初めて送る時刻は、テナントごとに独立した0〜6時間の乱数だけ遅らせる（同じ回復を複数の企業が受け取るので、
//   届く時刻の近さで突き合わせさせない。不変条件5）。

import {
  randomBytesOf,
  randomUuid,
  type TenantId,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { sql } from '@pii-token-vault/warifu-core/db';
import { RECOVERY_NOTIFIED } from './audit-events.ts';
import type { CompanyApiConfig } from './config.ts';
import type { DeskDeps } from './desk.ts';

/** 回復の SET を初めて送るまでの、意図した遅延の上限（ミリ秒）。 */
export const RECOVERY_SET_MAX_DELAY_MS = 6 * 3600 * 1000;

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
      const inserted = await tx.execute(
        sql`INSERT INTO company_api.set_outbox
              (event_id, tenant_id, event_type, state, user_id, recovery_ref, recovered_day, deliver_after)
            VALUES (${randomUuid()}, ${tenantId}, 'account_recovered', ${null}, ${input.userId},
                    ${input.attemptId}, ${input.recoveredDay},
                    ${new Date(deps.now().getTime() + recoveryDelayMs())})
            ON CONFLICT (tenant_id, recovery_ref) DO NOTHING`,
      );
      if (inserted === 1)
        await appendAudit(tx, deps.keys, RECOVERY_NOTIFIED, {}, { now: deps.now });
      return inserted;
    });
  }
  return queued;
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
