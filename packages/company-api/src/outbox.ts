// SET の送信待ちと送信（RFC 8935 の push、ADR 0022、ADR 0026 の O-67）。
//
// - 送るものは company_api.set_outbox に置く（署名した SET は置かない。送るときに署名する。不変条件4）。
// - 送るときは、1件ずつ「借りる」（回数を足し、少し先まで次の人に渡さない）。借りた後にトランザクションを閉じてから、
//   sender の内部 API に渡す（外への送信の間、DB のトランザクションを開いたままにしない）。
// - 緊急停止したテナントと、受け口を登録していないテナントには送らない（送信待ちは残す）。
//
// 検証の SET（ADR 0022）：
// - 2xx で消す。送れなければ、間を空けて送り直す（1分、5分、30分、2時間、6時間）。6回送れなければ諦めて消し、
//   その数だけをログに残す。jti と iat は初めて送るときに決め、送り直しでも同じにする。
//
// 窓口の取消の SET（ADR 0026 の O-67）。取消は受理済みなので、諦めて消すことはしない：
// - 202 だけを配送できたことにして消す。業務の取消の完了は、企業の cancellation-results で決まる。
// - 400 の set_too_old は、同じ取消を、5秒の後に新しい jti と iat で送り直す（同じ回の中では送り直さない）。
//   続けて3回なら保留にする（受け口の時計の狂いとみなす）。
// - 429、5xx、つながらない、時間切れは、1分、5分、30分、2時間、6時間、以後6時間ごとに、少し揺らして送り直す。
//   送り直すときに iat が4分より古ければ、新しい jti と iat にする（受け口の受信の規則の300秒に収めるため）。
// - そのほか（iat_in_future、ほかの 4xx、リダイレクト、202 以外の 2xx、宛先の検査に通らない）は保留にする。
//   保留は自動では解かない（時計、鍵、登録の確認が要る。運用で設定を直して配備し直す）。

import {
  randomBytesOf,
  randomUuid,
  type TenantId,
  toBase64Url,
} from '@pii-token-vault/warifu-core';
import { type Db, sql } from '@pii-token-vault/warifu-core/db';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import type { Logger } from '@pii-token-vault/warifu-core/log';
import type {
  SenderWebhookClient,
  WebhookResult,
} from '@pii-token-vault/warifu-core/sender/client';
import type { CompanyApiConfig, CompanyTenant } from './config.ts';
import { cancellationEventOf } from './desk.ts';
import type { PublicKeyCache } from './jwt.ts';
import { type SetContent, signSet } from './set.ts';

/** 送り直しまでの間（回数ごと）。検証の SET は、最後の回で送れなければ諦める。 */
export const RETRY_DELAYS_MS: readonly number[] = Object.freeze([
  60_000,
  5 * 60_000,
  30 * 60_000,
  2 * 3_600_000,
  6 * 3_600_000,
]);
export const MAX_ATTEMPTS = RETRY_DELAYS_MS.length + 1;
/** 取消の SET を、新しい jti と iat で続けて送り直せる回数（set_too_old。これを超えたら保留）。 */
export const MAX_REISSUES = 3;
/** set_too_old の後、送り直すまでの間。 */
export const REISSUE_DELAY_MS = 5_000;
/** 取消の SET の iat がこれより古ければ、送り直すときに新しい jti と iat にする。 */
export const REISSUE_AGE_MS = 240_000;
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
  event: { readonly type: 'verification'; readonly state: string | null },
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
  readonly event_type: 'verification' | 'desk_cancellation';
  readonly state: string | null;
  readonly change_ref: string | null;
  readonly jti: string;
  readonly issued_at: Date;
  readonly attempts: number;
  readonly reissues: number;
}

async function claim(deps: OutboxDeps, tenant: CompanyTenant): Promise<Claimed | undefined> {
  const now = deps.now();
  const stale = new Date(now.getTime() - REISSUE_AGE_MS);
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    // SET の右辺の列は、書き換える前の値を指す（jti と issued_at の2つの CASE は、同じ条件を見る）。
    const [row] = await tx.query<Claimed>(
      sql`UPDATE company_api.set_outbox
             SET attempts = attempts + 1,
                 deliver_after = ${new Date(now.getTime() + LEASE_MS)},
                 jti = CASE WHEN jti IS NULL OR (event_type = 'desk_cancellation' AND issued_at <= ${stale})
                            THEN ${toBase64Url(randomBytesOf(16))} ELSE jti END,
                 issued_at = CASE WHEN jti IS NULL OR (event_type = 'desk_cancellation' AND issued_at <= ${stale})
                                  THEN ${now} ELSE issued_at END
           WHERE event_id = (
                   SELECT event_id FROM company_api.set_outbox
                    WHERE deliver_after <= ${now} AND NOT held
                    ORDER BY deliver_after, event_id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED)
       RETURNING event_id, event_type, state, change_ref, jti, issued_at, attempts, reissues`,
    );
    return row;
  });
}

type Outcome = 'delivered' | 'retry' | 'dropped' | 'reissue' | 'held';

/** 取消の SET の結果を、送信待ちの扱いに分ける（ADR 0026 の O-67）。 */
export function cancellationOutcomeOf(
  result: WebhookResult | undefined,
): 'delivered' | 'reissue' | 'retry' | 'held' {
  if (result === undefined) return 'retry';
  if (result.ok) return result.status === 202 ? 'delivered' : 'held';
  if (result.status === 400 && result.setError === 'set_too_old') return 'reissue';
  if (result.status !== undefined) {
    return result.status === 429 || result.status >= 500 ? 'retry' : 'held';
  }
  switch (result.reason) {
    case 'connect_failed':
    case 'timeout':
    case 'dns_failed':
    case 'no_address':
      return 'retry';
    default:
      return 'held';
  }
}

/** 間に、0〜20% の揺らぎを足す。 */
function jittered(ms: number): number {
  const bytes = randomBytesOf(2);
  const fraction = (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) / 65_535;
  return Math.round(ms * (1 + fraction * 0.2));
}

async function settle(
  deps: OutboxDeps,
  tenant: CompanyTenant,
  row: Claimed,
  result: WebhookResult | undefined,
): Promise<Outcome> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    if (row.event_type === 'verification') {
      const delivered = result?.ok === true;
      if (delivered || row.attempts >= MAX_ATTEMPTS) {
        await tx.execute(sql`DELETE FROM company_api.set_outbox WHERE event_id = ${row.event_id}`);
        return delivered ? 'delivered' : 'dropped';
      }
      const delay = RETRY_DELAYS_MS[row.attempts - 1] ?? RETRY_DELAYS_MS.at(-1) ?? LEASE_MS;
      await tx.execute(
        sql`UPDATE company_api.set_outbox SET deliver_after = ${new Date(now.getTime() + delay)}
             WHERE event_id = ${row.event_id}`,
      );
      return 'retry';
    }
    const outcome = cancellationOutcomeOf(result);
    switch (outcome) {
      case 'delivered':
        await tx.execute(sql`DELETE FROM company_api.set_outbox WHERE event_id = ${row.event_id}`);
        return 'delivered';
      case 'reissue': {
        if (row.reissues + 1 >= MAX_REISSUES) {
          await tx.execute(
            sql`UPDATE company_api.set_outbox SET held = true, reissues = ${row.reissues + 1}
                 WHERE event_id = ${row.event_id}`,
          );
          return 'held';
        }
        // 次に借りるときに、新しい jti と iat にする。
        await tx.execute(
          sql`UPDATE company_api.set_outbox
                 SET jti = ${null}, issued_at = ${null}, reissues = ${row.reissues + 1},
                     deliver_after = ${new Date(now.getTime() + REISSUE_DELAY_MS)}
               WHERE event_id = ${row.event_id}`,
        );
        return 'reissue';
      }
      case 'retry': {
        const base = RETRY_DELAYS_MS[row.attempts - 1] ?? RETRY_DELAYS_MS.at(-1) ?? LEASE_MS;
        await tx.execute(
          sql`UPDATE company_api.set_outbox
                 SET deliver_after = ${new Date(now.getTime() + jittered(base))}, reissues = 0
               WHERE event_id = ${row.event_id}`,
        );
        return 'retry';
      }
      case 'held':
        await tx.execute(
          sql`UPDATE company_api.set_outbox SET held = true WHERE event_id = ${row.event_id}`,
        );
        return 'held';
    }
  });
}

async function contentOf(
  deps: OutboxDeps,
  tenantId: TenantId,
  row: Claimed,
): Promise<SetContent | undefined> {
  if (row.event_type === 'verification') {
    return { type: 'verification', state: row.state, jti: row.jti, issuedAt: row.issued_at };
  }
  if (row.change_ref === null) return undefined;
  const ids = await cancellationEventOf(deps, tenantId, row.change_ref);
  if (ids === undefined) return undefined;
  return { type: 'desk_cancellation', ...ids, jti: row.jti, issuedAt: row.issued_at };
}

/** 期限の来た送信待ちを送る。結果ごとの数を返す。 */
export async function deliverDue(
  deps: OutboxDeps,
): Promise<{ delivered: number; retry: number; dropped: number; reissue: number; held: number }> {
  const counts = { delivered: 0, retry: 0, dropped: 0, reissue: 0, held: 0 };
  if (deps.sender === undefined) return counts;
  for (const tenant of deps.config.tenants.values()) {
    if (tenant.suspended || tenant.webhookUrl === undefined) continue;
    for (let i = 0; i < BATCH; i += 1) {
      const row = await claim(deps, tenant);
      if (row === undefined) break;
      const content = await contentOf(deps, tenant.tenantId, row);
      if (content === undefined) {
        // 正本の行が消えた後の取消の SET（終端から7日を過ぎた）。送るものがないので消す。
        await deps.db.withTenant(tenant.tenantId, (tx) =>
          tx.execute(sql`DELETE FROM company_api.set_outbox WHERE event_id = ${row.event_id}`),
        );
        counts.dropped += 1;
        continue;
      }
      let result: WebhookResult | undefined;
      try {
        const set = await signSet(deps.keys, deps.cache, deps.config.issuer, tenant, content);
        result = await deps.sender.postSet({ url: tenant.webhookUrl, set });
        if (!result.ok)
          deps.log.warn({ event: 'company_api.set_not_delivered', reason: result.reason });
      } catch (err) {
        deps.log.warn({ event: 'company_api.set_not_delivered', err });
        result = undefined;
      }
      const outcome = await settle(deps, tenant, row, result);
      counts[outcome] += 1;
      if (outcome === 'dropped') deps.log.warn({ event: 'company_api.set_dropped', count: 1 });
      if (outcome === 'held') deps.log.warn({ event: 'company_api.set_held', count: 1 });
    }
  }
  return counts;
}
