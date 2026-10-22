import { describe, expect, it } from 'vitest';
import { isSql, SqlRejectedError, sql } from '../src/db/sql.ts';

describe('sql タグ', () => {
  it('埋め込んだ値を、すべて $n のパラメータにする', () => {
    const a = 'x';
    const b = 2;
    const statement = sql`SELECT c FROM s.t WHERE a = ${a} AND b = ANY(${['1', '2']}) AND n = ${b}`;
    expect(statement.text).toBe('SELECT c FROM s.t WHERE a = $1 AND b = ANY($2) AND n = $3');
    expect(statement.values).toEqual(['x', ['1', '2'], 2]);
    expect(isSql(statement)).toBe(true);
    expect(Object.isFrozen(statement)).toBe(true);
  });

  it.each([
    ['セミコロン', () => sql`SELECT 1; SELECT 2`],
    ['二重引用符', () => sql`SELECT "x" FROM s.t`],
    ['ドル記号の引用', () => sql`SELECT $$x$$`],
    ['名前付きのドル記号の引用', () => sql`SELECT $tag$x$tag$`],
    ['Unicode の識別子', () => sql`SELECT U&"set_\\0063onfig"('a', 'b', true)`],
    ['行のコメント', () => sql`SELECT 1 -- x`],
    ['ブロックのコメント', () => sql`SELECT /* x */ 1`],
    ['set_config', () => sql`SELECT pg_catalog.set_config('warifu.tenant_id', ${'x'}, true)`],
    ['current_setting', () => sql`SELECT current_setting('x', true)`],
    ['境界の値の名前', () => sql`SELECT 'warifu.user_id'`],
    ['SET', () => sql`SET ROLE warifu_owner`],
    ['RESET', () => sql`RESET ROLE`],
    ['BEGIN', () => sql`BEGIN`],
    ['DO', () => sql`DO 'x'`],
    ['COPY', () => sql`COPY s.t TO STDOUT`],
    ['CREATE', () => sql`CREATE TABLE s.t (a int)`],
  ])('%s を拒否する', (_label, make) => {
    expect(make).toThrow(SqlRejectedError);
  });

  it('タグで作っていない値を受け付けない', () => {
    const fake = Object.freeze({ text: 'SELECT 1', values: [] });
    expect(isSql(fake)).toBe(false);
    const strings = Object.assign(['SELECT 1'], { raw: ['SELECT 1'] });
    expect(() => sql(strings as unknown as TemplateStringsArray)).toThrow(SqlRejectedError);
  });

  it('値の型を確かめる', () => {
    expect(() => sql`SELECT ${Number.NaN}`).toThrow(SqlRejectedError);
    expect(() => sql`SELECT ${{ a: 1 } as never}`).toThrow(SqlRejectedError);
    expect(() => sql`SELECT ${[1, 2] as never}`).toThrow(SqlRejectedError);
    expect(sql`SELECT ${new Uint8Array([1])}, ${10n}, ${null}, ${true}`.values).toHaveLength(4);
  });
});
