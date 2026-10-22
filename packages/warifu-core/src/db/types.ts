// DB の境界の型（不変条件8、ADR 0014）。

import type { ServiceName, TenantId, WarifuUserId } from '../ids.ts';

export type Boundary =
  | { readonly kind: 'tenant'; readonly tenantId: TenantId }
  | { readonly kind: 'user'; readonly userId: WarifuUserId };

export type SqlValue =
  | string
  | number
  | bigint
  | boolean
  | null
  | Date
  | Uint8Array
  | readonly string[];

/** sql タグが作った文。text と values はタグの中で作る。 */
export interface Sql {
  readonly text: string;
  readonly values: readonly SqlValue[];
}

export interface Tx {
  readonly service: ServiceName;
  readonly boundary: Boundary;
  query<R extends object = Record<string, unknown>>(statement: Sql): Promise<R[]>;
  /** ちょうど1行でなければ DbError('cardinality')。 */
  one<R extends object = Record<string, unknown>>(statement: Sql): Promise<R>;
  /** 変わった行の数。 */
  execute(statement: Sql): Promise<number>;
}

export interface Db {
  readonly service: ServiceName;
  withTenant<T>(tenantId: TenantId, fn: (tx: Tx) => Promise<T>): Promise<T>;
  withWarifuUser<T>(userId: WarifuUserId, fn: (tx: Tx) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export interface DbConnection {
  /** ソケットのディレクトリ（ローカル）。 */
  readonly host: string;
  readonly port: number;
  readonly database: string;
  /** 既定は 10。 */
  readonly maxConnections?: number;
}

export type DbErrorCode =
  | 'boundary_tampered'
  | 'nested_boundary'
  | 'tx_closed'
  | 'unsafe_role'
  | 'cardinality'
  | 'invalid_input'
  | (string & {});

/** DB のエラー。code（SQLSTATE か上の名前）と制約の名前だけを持つ。pg の本文と DETAIL は捨てる（不変条件4）。 */
export class DbError extends Error {
  readonly code: DbErrorCode;
  readonly constraint: string | undefined;

  constructor(code: DbErrorCode, constraint?: string) {
    super('DB の操作に失敗した');
    this.name = 'DbError';
    this.code = code;
    this.constraint = constraint;
  }
}
