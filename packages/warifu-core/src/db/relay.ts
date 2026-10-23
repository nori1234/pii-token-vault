// relay の DB（不変条件8の例外の SECURITY DEFINER 関数、ADR 0005、ADR 0015）。relay だけが import する。
// resolveAlias は、境界の値を両方とも空にしたトランザクションで、relay.resolve_alias だけを呼ぶ。
// 返すのは利用者 ID とテナント ID の2つだけ。戻り値を relay の外に出さない（不変条件2）。
// テナント ID は配送の判断（送信元ロックなど）だけに使い、許可の判断に流さない（不変条件1(e)）。

import { parseTenantId, parseWarifuUserId, type TenantId, type WarifuUserId } from '../ids.ts';
import { openServiceDb } from './boundary.ts';
import { sql } from './sql.ts';
import { type Db, type DbConnection, DbError } from './types.ts';

export interface RelayDb extends Db {
  /** 照合用の HMAC（32バイト）から、2つの ID だけを得る。廃番、存在しないものは undefined。 */
  resolveAlias(
    lookupMac: Uint8Array,
  ): Promise<{ readonly userId: WarifuUserId; readonly tenantId: TenantId } | undefined>;
}

const LOOKUP_MAC_BYTES = 32;

export function createRelayDb(options: { readonly connection: DbConnection }): RelayDb {
  const { db, run } = openServiceDb('relay', options.connection);
  return Object.freeze({
    service: db.service,
    withTenant: db.withTenant,
    withWarifuUser: db.withWarifuUser,
    close: db.close,
    async resolveAlias(lookupMac: Uint8Array) {
      if (!(lookupMac instanceof Uint8Array) || lookupMac.byteLength !== LOOKUP_MAC_BYTES) {
        throw new DbError('invalid_input');
      }
      const rows = await run({ kind: 'none' }, (tx) =>
        tx.query<{ user_id: string; tenant_id: string }>(
          sql`SELECT r.user_id, r.tenant_id FROM relay.resolve_alias(${lookupMac}) AS r`,
        ),
      );
      if (rows.length > 1) throw new DbError('cardinality');
      const row = rows[0];
      if (row === undefined) return undefined;
      return { userId: parseWarifuUserId(row.user_id), tenantId: parseTenantId(row.tenant_id) };
    },
  });
}
