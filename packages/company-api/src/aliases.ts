// 別名の入れ替え（plan 3-2、ADR 0005、ADR 0022。テスト4の後半）。
//
// - 企業は sub で利用者を指す。sub から利用者を引くのは、テナントの中の索引（aliases.subject）だけ。
//   ほかのテナントの sub は見えない（RLS。テスト6）。
// - 次の世代の別名を鍵サービスで導き、照合用の MAC だけを置く。照合用の MAC は一意なので、前の世代の別名が
//   もう一度割り当てられることはない（不変条件5）。最新でない世代は、relay の解決関数が返さない（廃番）。
// - 返すのは新しい別名だけ。本物の連絡先や利用者の属性は返さない（不変条件2）。
// - 一括の入れ替えは作らない（P0。一括の操作には、テナントの側の2人承認と実行までの遅延が要る。plan 2章）。

import { aliasLookupMessage, type TenantId, type WarifuUserId } from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { type Db, DbError, sql } from '@pii-token-vault/warifu-core/db';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import { ALIAS_ROTATED } from './audit-events.ts';
import type { CompanyTenant } from './config.ts';

/** sub の形（base64url の32バイト。idp の subject.ts）。 */
export const SUB_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UNIQUE_VIOLATION = '23505';
const MAX_TRIES = 3;

export interface AliasDeps {
  readonly db: Db;
  readonly keys: CompanyApiKeyClient;
  readonly now: () => Date;
}

async function rotateOnce(
  deps: AliasDeps,
  tenant: CompanyTenant,
  sub: string,
): Promise<string | undefined> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const [subject] = await tx.query<{ user_id: string }>(
      sql`SELECT user_id FROM aliases.subject WHERE sub = ${sub}`,
    );
    if (subject === undefined) return undefined;
    const userId = subject.user_id as WarifuUserId;
    const [latest] = await tx.query<{ generation: number | null }>(
      sql`SELECT pg_catalog.max(generation) AS generation FROM aliases.generation WHERE user_id = ${userId}`,
    );
    const current = latest?.generation ?? null;
    // 第1世代は、idp が接続の同意のときに置く。まだなければ、入れ替えるものがない。
    if (current === null) return undefined;
    const generation = current + 1;
    const local = await deps.keys.deriveAlias({
      tenantId: tenant.tenantId as TenantId,
      userId,
      generation,
    });
    const lookupMac = await deps.keys.mac('alias_lookup', aliasLookupMessage(local));
    await tx.execute(
      sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
          VALUES (${tenant.tenantId}, ${userId}, ${generation}, ${lookupMac})`,
    );
    await appendAudit(tx, deps.keys, ALIAS_ROTATED, { generation }, { now: deps.now });
    return `${local}@${tenant.relayDomain}`;
  });
}

/** sub の利用者の別名を次の世代にして、新しい別名を返す。その sub がテナントになければ undefined。 */
export async function rotateAlias(
  deps: AliasDeps,
  tenant: CompanyTenant,
  sub: string,
): Promise<string | undefined> {
  if (!SUB_PATTERN.test(sub)) return undefined;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await rotateOnce(deps, tenant, sub);
    } catch (error) {
      // 同じ利用者の入れ替えが同時に来ると、世代の主キーで片方が失敗する。読み直してもう一度だけ試す。
      const retry =
        error instanceof DbError &&
        error.code === UNIQUE_VIOLATION &&
        error.constraint === 'generation_pkey' &&
        attempt < MAX_TRIES;
      if (!retry) throw error;
    }
  }
}
