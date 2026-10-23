// DB の境界（不変条件8、ADR 0015）。アプリのコードは withTenant か withWarifuUser を通してだけ DB に触れる。
//
// 1つのトランザクションごとに：
//   1. すでに境界の中なら nested_boundary（境界を入れ子にしない）。
//   2. プールから接続を取る。その接続で初めてなら、期待したロールで、スーパーユーザーでも BYPASSRLS でもないことを
//      確かめる。違えば unsafe_role で失敗し、接続を壊して捨てる。
//   3. BEGIN ISOLATION LEVEL READ COMMITTED
//   4. set_config('warifu.tenant_id', …, true) と set_config('warifu.user_id', …, true)。使わない方は空文字。
//   5. fn(tx)。tx.query は sql タグが作った文だけを、拡張プロトコル（1つの文だけ）で送る。
//   6. fn が終わったら tx を閉じる（以後は tx_closed）。
//   7. 境界の値とロールが 4 のままかを読み直す。違えば boundary_tampered。
//   8. COMMIT。どこで失敗しても ROLLBACK。ROLLBACK も失敗したら、接続を壊して捨てる。
// pg の例外は DbError(code, constraint) に写し直し、message、detail、where、hint を捨てる（不変条件4）。
// warifu-core は、プールも pg のクライアントも外に出さない。

import { AsyncLocalStorage } from 'node:async_hooks';
import pg from 'pg';
import {
  parseTenantId,
  parseWarifuUserId,
  SERVICE_ROLE,
  type ServiceName,
  type TenantId,
  type WarifuUserId,
} from '../ids.ts';
import { isSql, SqlRejectedError } from './sql.ts';
import {
  type Boundary,
  type Db,
  type DbConnection,
  DbError,
  type Sql,
  type SqlValue,
  type Tx,
} from './types.ts';

const active = new AsyncLocalStorage<true>();
const SQLSTATE = /^[0-9A-Z]{5}$/;

/** 境界の値を空にしたトランザクション（relay の解決関数だけが使う）。 */
export type InternalBoundary = Boundary | { readonly kind: 'none' };

/** pg の例外を、code と制約の名前だけの DbError に写す。 */
export function toDbError(error: unknown): Error {
  if (error instanceof DbError || error instanceof SqlRejectedError) return error;
  const code = (error as { code?: unknown } | null)?.code;
  const constraint = (error as { constraint?: unknown } | null)?.constraint;
  if (typeof code === 'string' && SQLSTATE.test(code)) {
    return new DbError(code, typeof constraint === 'string' ? constraint : undefined);
  }
  return new DbError('unavailable');
}

function encodeValue(value: SqlValue): unknown {
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'bigint') return value.toString();
  return value;
}

/** pg 8 の拡張プロトコルを強制する設定（@types/pg に型がない）。 */
function extended(text: string, values: readonly unknown[]): pg.QueryConfig {
  return { text, values: [...values], queryMode: 'extended' } as pg.QueryConfig;
}

interface BoundaryValues {
  readonly tenant: string;
  readonly user: string;
}

function valuesOf(boundary: InternalBoundary): BoundaryValues {
  switch (boundary.kind) {
    case 'tenant':
      return { tenant: parseTenantId(boundary.tenantId), user: '' };
    case 'user':
      return { tenant: '', user: parseWarifuUserId(boundary.userId) };
    case 'none':
      return { tenant: '', user: '' };
  }
}

export interface ServiceDbInternal {
  readonly db: Db;
  run<T>(boundary: InternalBoundary, fn: (tx: Tx) => Promise<T>): Promise<T>;
}

/** プールを作る関数。単体テストだけが偽のプールを渡す（exports に載せない）。 */
export type PoolFactory = (config: pg.PoolConfig) => pg.Pool;

export function openServiceDb(
  service: ServiceName,
  connection: DbConnection,
  makePool: PoolFactory = (config) => new pg.Pool(config),
): ServiceDbInternal {
  const role = SERVICE_ROLE[service];
  const pool = makePool({
    host: connection.host,
    port: connection.port,
    database: connection.database,
    user: role,
    max: connection.maxConnections ?? 10,
  });
  // 接続の失敗はクエリの側で扱う。プールの 'error' を待ち受けないと、プロセスが落ちる。
  pool.on('error', () => {});
  const verified = new WeakSet<pg.PoolClient>();

  const verifyRole = async (client: pg.PoolClient): Promise<void> => {
    if (verified.has(client)) return;
    const result = await client.query<{ role: string; rolsuper: boolean; rolbypassrls: boolean }>(
      extended(
        'SELECT current_user AS role, r.rolsuper, r.rolbypassrls FROM pg_catalog.pg_roles AS r WHERE r.rolname = current_user',
        [],
      ),
    );
    const row = result.rows[0];
    if (row === undefined || row.role !== role || row.rolsuper || row.rolbypassrls) {
      throw new DbError('unsafe_role');
    }
    verified.add(client);
  };

  const run = async <T>(boundary: InternalBoundary, fn: (tx: Tx) => Promise<T>): Promise<T> => {
    if (active.getStore() === true) throw new DbError('nested_boundary');
    const values = valuesOf(boundary);
    let client: pg.PoolClient;
    try {
      client = await pool.connect();
    } catch (error) {
      throw toDbError(error);
    }
    let destroy = false;
    let began = false;
    try {
      try {
        await verifyRole(client);
      } catch (error) {
        destroy = true;
        throw toDbError(error);
      }
      try {
        await client.query(extended('BEGIN ISOLATION LEVEL READ COMMITTED', []));
        began = true;
        await client.query(
          extended(
            "SELECT pg_catalog.set_config('warifu.tenant_id', $1, true), pg_catalog.set_config('warifu.user_id', $2, true)",
            [values.tenant, values.user],
          ),
        );
      } catch (error) {
        throw toDbError(error);
      }

      let closed = false;
      const send = async (statement: Sql): Promise<pg.QueryResult<Record<string, unknown>>> => {
        if (closed) throw new DbError('tx_closed');
        if (!isSql(statement)) throw new SqlRejectedError();
        try {
          return await client.query(extended(statement.text, statement.values.map(encodeValue)));
        } catch (error) {
          throw toDbError(error);
        }
      };
      const tx: Tx = Object.freeze({
        service,
        // 'none' は relay の解決関数（db/relay.ts）だけが使い、その fn は boundary を読まない。
        boundary: boundary as Boundary,
        async query<R extends object>(statement: Sql) {
          return (await send(statement)).rows as R[];
        },
        async one<R extends object>(statement: Sql) {
          const rows = (await send(statement)).rows;
          if (rows.length !== 1) throw new DbError('cardinality');
          return rows[0] as R;
        },
        async execute(statement: Sql) {
          return (await send(statement)).rowCount ?? 0;
        },
      });

      let result: T;
      try {
        result = await active.run(true, () => fn(tx));
      } finally {
        closed = true;
      }

      let check: pg.QueryResult<{ t: string | null; u: string | null; r: string }>;
      try {
        check = await client.query(
          extended(
            "SELECT pg_catalog.current_setting('warifu.tenant_id', true) AS t, pg_catalog.current_setting('warifu.user_id', true) AS u, current_user AS r",
            [],
          ),
        );
      } catch (error) {
        throw toDbError(error);
      }
      const row = check.rows[0];
      if (row === undefined || row.t !== values.tenant || row.u !== values.user || row.r !== role) {
        throw new DbError('boundary_tampered');
      }
      try {
        await client.query(extended('COMMIT', []));
      } catch (error) {
        began = false;
        throw toDbError(error);
      }
      began = false;
      return result;
    } catch (error) {
      if (began) {
        try {
          await client.query(extended('ROLLBACK', []));
        } catch {
          destroy = true;
        }
      }
      throw error;
    } finally {
      client.release(destroy);
    }
  };

  const db: Db = Object.freeze({
    service,
    async withTenant<T>(tenantId: TenantId, fn: (tx: Tx) => Promise<T>) {
      return await run({ kind: 'tenant', tenantId: parseTenantId(tenantId) }, fn);
    },
    async withWarifuUser<T>(userId: WarifuUserId, fn: (tx: Tx) => Promise<T>) {
      return await run({ kind: 'user', userId: parseWarifuUserId(userId) }, fn);
    },
    async close() {
      await pool.end();
    },
  });
  return { db, run };
}

/** ロールは SERVICE_ROLE[service] に固定する。ロールの名前は受け取らない。relay は createRelayDb を使う。 */
export function createDb(options: {
  readonly service: 'idp' | 'company-api';
  readonly connection: DbConnection;
}): Db {
  if (options.service !== 'idp' && options.service !== 'company-api') {
    throw new DbError('unsafe_role');
  }
  return openServiceDb(options.service, options.connection).db;
}
