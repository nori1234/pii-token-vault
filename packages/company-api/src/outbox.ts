// SET の送信待ちと送信（RFC 8935 の push、ADR 0022）。
//
// - 送るものは company_api.set_outbox に置く（署名した SET は置かない。送るときに署名する。不変条件4）。
// - 送るときは、1件ずつ「借りる」（回数を足し、少し先まで次の人に渡さない）。借りた後にトランザクションを閉じてから、
//   sender の内部 API に渡す（外への送信の間、DB のトランザクションを開いたままにしない）。
// - 送れたら消す。送れなければ、間を空けて送り直す（1分、5分、30分、2時間、6時間）。6回送れなければ諦めて消し、
//   その数だけをログに残す。jti と iat は初めて送るときに決め、送り直しでも同じにする。
// - 緊急停止したテナントと、受け口を登録していないテナントには送らない（送信待ちは残す）。

import { randomBytesOf, randomUuid, toBase64Url } from '@pii-token-vault/warifu-core';
import { type Db, sql } from '@pii-token-vault/warifu-core/db';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import type { SenderWebhookClient } from '@pii-token-vault/warifu-core/sender/client';
import type { CompanyApiConfig, CompanyTenant } from './config.ts';
import type { PublicKeyCache } from './jwt.ts';
import { type SetEventType, signSet } from './set.ts';

/** 送り直しまでの間（回数ごと）。最後の回で送れなければ諦める。 */
export const RETRY_DELAYS_MS: readonly number[] = Object.freeze([
  60_000,
  5 * 60_000,
  30 * 60_000,
  2 * 3_600_000,
  6 * 3_600_000,
]);
export const MAX_ATTEMPTS = RETRY_DELAYS_MS.length + 1;
/** 借りている間（その間に送り終えなければ、次の回で送り直す）。 */
const LEASE_MS = 2 * 60_000;
const BATCH = 20;
export const STATE_PATTERN = /^[A-Za-z0-9._~-]{1,64}$/;

export interface OutboxDeps {
  readonly config: CompanyApiConfig;
  readonly db: Db;
  readonly keys: CompanyApiKeyClient;
  readonly cache: PublicKeyCache;
  readonly sender: SenderWebhookClient | undefined;
  readonly log: Logger;
  readonly now: () => Date;
}

export async function enqueueEvent(
  deps: Pick<OutboxDeps, 'db' | 'now'>,
  tenant: CompanyTenant,
  event: { readonly type: SetEventType; readonly state: string | null },
): Promise<void> {
  await deps.db.withTenant(tenant.tenantId, async (tx) => {
    await tx.execute(
      sql`INSERT INTO company_api.set_outbox (event_id, tenant_id, event_type, state, deliver_after)
          VALUES (${randomUuid()}, ${tenant.tenantId}, ${event.type}, ${event.state}, ${deps.now()})`,
    );
  });
}

interface Claimed {
  readonly event_id: string;
  readonly event_type: SetEventType;
  readonly state: string | null;
  readonly jti: string;
  readonly issued_at: Date;
  readonly attempts: number;
}

async function claim(deps: OutboxDeps, tenant: CompanyTenant): Promise<Claimed | undefined> {
  const now = deps.now();
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const [row] = await tx.query<Claimed>(
      sql`UPDATE company_api.set_outbox
             SET attempts = attempts + 1,
                 deliver_after = ${new Date(now.getTime() + LEASE_MS)},
                 jti = COALESCE(jti, ${toBase64Url(randomBytesOf(16))}),
                 issued_at = COALESCE(issued_at, ${now})
           WHERE event_id = (
                   SELECT event_id FROM company_api.set_outbox
                    WHERE deliver_after <= ${now}
                    ORDER BY deliver_after, event_id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED)
       RETURNING event_id, event_type, state, jti, issued_at, attempts`,
    );
    return row;
  });
}

async function settle(
  deps: OutboxDeps,
  tenant: CompanyTenant,
  row: Claimed,
  delivered: boolean,
): Promise<'delivered' | 'retry' | 'dropped'> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    if (delivered || row.attempts >= MAX_ATTEMPTS) {
      await tx.execute(sql`DELETE FROM company_api.set_outbox WHERE event_id = ${row.event_id}`);
      return delivered ? 'delivered' : 'dropped';
    }
    const delay = RETRY_DELAYS_MS[row.attempts - 1] ?? RETRY_DELAYS_MS.at(-1) ?? LEASE_MS;
    await tx.execute(
      sql`UPDATE company_api.set_outbox SET deliver_after = ${new Date(deps.now().getTime() + delay)}
           WHERE event_id = ${row.event_id}`,
    );
    return 'retry';
  });
}

/** 期限の来た送信待ちを送る。送った数、送り直しに回した数、諦めた数を返す。 */
export async function deliverDue(
  deps: OutboxDeps,
): Promise<{ delivered: number; retry: number; dropped: number }> {
  const counts = { delivered: 0, retry: 0, dropped: 0 };
  if (deps.sender === undefined) return counts;
  for (const tenant of deps.config.tenants.values()) {
    if (tenant.suspended || tenant.webhookUrl === undefined) continue;
    for (let i = 0; i < BATCH; i += 1) {
      const row = await claim(deps, tenant);
      if (row === undefined) break;
      let delivered = false;
      try {
        const set = await signSet(deps.keys, deps.cache, deps.config.issuer, tenant, {
          type: row.event_type,
          state: row.state,
          jti: row.jti,
          issuedAt: row.issued_at,
        });
        const result = await deps.sender.postSet({ url: tenant.webhookUrl, set });
        delivered = result.ok;
        if (!result.ok)
          deps.log.warn({ event: 'company_api.set_not_delivered', reason: result.reason });
      } catch (err) {
        deps.log.warn({ event: 'company_api.set_not_delivered', err });
      }
      const outcome = await settle(deps, tenant, row, delivered);
      counts[outcome] += 1;
      if (outcome === 'dropped') deps.log.warn({ event: 'company_api.set_dropped', count: 1 });
    }
  }
  return counts;
}
