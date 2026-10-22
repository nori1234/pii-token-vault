// DB の境界（不変条件8、ADR 0014）。relay は '@pii-token-vault/warifu-core/db/relay' の createRelayDb を使う。

export { createDb } from './boundary.ts';
export { isSql, SqlRejectedError, sql } from './sql.ts';
export type {
  Boundary,
  Db,
  DbConnection,
  DbErrorCode,
  Sql,
  SqlValue,
  Tx,
} from './types.ts';
export { DbError } from './types.ts';
