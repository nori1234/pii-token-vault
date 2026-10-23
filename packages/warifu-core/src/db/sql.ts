// SQL の書き方（spec 03 の TH-35、ADR 0015）。
//
// - アプリのコードは tx.query(sql`…`) などだけを使う。sql タグが作ったもの（WeakSet に登録）だけを受け付ける。
// - ${} はすべてパラメータ（$1…）。識別子や SQL の断片は埋め込めない。可変長の一覧は `= ANY(${array})`。
// - 先頭の語は SELECT、INSERT、UPDATE、DELETE、WITH のどれか。
// - 静的な部分に、; " ドル記号の引用 U& -- /* と、境界の値を読み書きする名前（set_config、current_setting、
//   warifu.tenant_id、warifu.user_id）を含めない。
// この検査は開発者の誤りを止めるためのもの。攻撃者の入力は値としてしか届かない。

import type { Sql, SqlValue } from './types.ts';

/** メッセージは固定（SQL の本文や値を入れない）。 */
export class SqlRejectedError extends Error {
  constructor() {
    super('この形の SQL は送らない');
    this.name = 'SqlRejectedError';
  }
}

const created = new WeakSet<object>();

const FIRST_WORD = /^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i;
const FORBIDDEN: readonly RegExp[] = [
  /;/,
  /"/,
  /\$[A-Za-z_]*\$/,
  /U&/i,
  /--/,
  /\/\*/,
  /set_config/i,
  /current_setting/i,
  /warifu\s*\.\s*tenant_id/i,
  /warifu\s*\.\s*user_id/i,
];

function isSqlValue(value: unknown): value is SqlValue {
  if (value === null) return true;
  switch (typeof value) {
    case 'string':
    case 'boolean':
    case 'bigint':
      return true;
    case 'number':
      return Number.isFinite(value);
    case 'object':
      if (value instanceof Date) return !Number.isNaN(value.getTime());
      if (value instanceof Uint8Array) return true;
      return Array.isArray(value) && value.every((item) => typeof item === 'string');
    default:
      return false;
  }
}

export function sql(strings: TemplateStringsArray, ...values: SqlValue[]): Sql {
  if (
    !Array.isArray(strings) ||
    !Object.isFrozen(strings) ||
    !Array.isArray((strings as { raw?: unknown }).raw) ||
    strings.length !== values.length + 1
  ) {
    throw new SqlRejectedError();
  }
  for (const part of strings) {
    if (typeof part !== 'string' || FORBIDDEN.some((pattern) => pattern.test(part))) {
      throw new SqlRejectedError();
    }
  }
  if (!values.every(isSqlValue)) throw new SqlRejectedError();
  let text = strings[0] ?? '';
  for (let i = 1; i < strings.length; i += 1) text += `$${i}${strings[i] ?? ''}`;
  if (!FIRST_WORD.test(text)) throw new SqlRejectedError();
  const statement: Sql = Object.freeze({ text, values: Object.freeze([...values]) });
  created.add(statement);
  return statement;
}

/** sql タグが作った文か。 */
export function isSql(value: unknown): value is Sql {
  return typeof value === 'object' && value !== null && created.has(value);
}
