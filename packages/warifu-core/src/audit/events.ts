// 監査の事象の定義と、属性の検査（不変条件4、ADR 0015）。
// 属性の値は、UUID、整数、真偽値、定義した列挙の文字列だけ。自由な文字列（連絡先、トークン、名前など）は入れられない。

import { isUuid } from '../ids.ts';

export type AuditAttrKind = 'uuid' | 'int' | 'bool' | { readonly enum: readonly string[] };

export interface AuditEventDef<
  T extends string = string,
  A extends Readonly<Record<string, AuditAttrKind>> = Readonly<Record<string, AuditAttrKind>>,
> {
  readonly type: T;
  readonly attrs: A;
}

type AttrValue<K> = K extends 'uuid'
  ? string
  : K extends 'int'
    ? number
    : K extends 'bool'
      ? boolean
      : K extends { readonly enum: readonly (infer E)[] }
        ? E
        : never;

export type AuditAttrs<D extends AuditEventDef> = {
  readonly [P in keyof D['attrs']]: AttrValue<D['attrs'][P]>;
};

/** 属性の誤り。値を入れない（不変条件4）。 */
export class AuditAttrError extends Error {
  constructor() {
    super('監査の属性の形が違う');
    this.name = 'AuditAttrError';
  }
}

const EVENT_TYPE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const NAME = /^[a-z][a-z0-9_]{0,31}$/;

export function defineAuditEvent<
  const T extends string,
  const A extends Readonly<Record<string, AuditAttrKind>>,
>(type: T, attrs: A): AuditEventDef<T, A> {
  if (!EVENT_TYPE.test(type) || Buffer.byteLength(type) > 64) throw new AuditAttrError();
  for (const [name, kind] of Object.entries(attrs)) {
    if (!NAME.test(name)) throw new AuditAttrError();
    if (typeof kind === 'object') {
      if (kind.enum.length === 0 || !kind.enum.every((value) => NAME.test(value))) {
        throw new AuditAttrError();
      }
    } else if (kind !== 'uuid' && kind !== 'int' && kind !== 'bool') {
      throw new AuditAttrError();
    }
  }
  return Object.freeze({ type, attrs: Object.freeze({ ...attrs }) as A });
}

/** 定義どおりの属性だけを、そのまま返す。知らないキー、足りないキー、型の違い、列挙の外は AuditAttrError。 */
export function checkAuditAttrs(
  def: AuditEventDef,
  attrs: Readonly<Record<string, unknown>>,
): Record<string, string | number | boolean> {
  if (attrs === null || typeof attrs !== 'object' || Array.isArray(attrs)) {
    throw new AuditAttrError();
  }
  const names = Object.keys(def.attrs);
  const given = Object.keys(attrs);
  if (given.length !== names.length || !given.every((name) => Object.hasOwn(def.attrs, name))) {
    throw new AuditAttrError();
  }
  const out: Record<string, string | number | boolean> = {};
  for (const name of names) {
    const kind = def.attrs[name];
    const value = attrs[name];
    const ok =
      kind === 'uuid'
        ? isUuid(value)
        : kind === 'int'
          ? typeof value === 'number' && Number.isSafeInteger(value)
          : kind === 'bool'
            ? typeof value === 'boolean'
            : typeof kind === 'object' && typeof value === 'string' && kind.enum.includes(value);
    if (!ok) throw new AuditAttrError();
    out[name] = value as string | number | boolean;
  }
  return out;
}
