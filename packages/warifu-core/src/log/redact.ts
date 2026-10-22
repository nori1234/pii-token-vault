// ログの伏せ字の規則。ここ以外に書かない（不変条件4、ADR 0016）。
//
// 許可リスト方式にする。伏せる対象を並べる方式は、新しい項目で必ず漏れる（ADR 0001 と同じ考え方）。
// - 載せてよいフィールドの名前と、値の形を決める。それ以外のキーは落とし、落とした数だけを dropped に出す。
// - メッセージは、決めた固定の文だけを載せる。値を埋め込んだ文は一致しないので伏せる。
// - Cookie、Authorization、Set-Cookie のヘッダー、req.url のクエリ、リクエストの本文は、許可リストにないので出ない。

import type { Component } from '../ids.ts';

export type FieldRule =
  | { readonly kind: 'code' }
  | { readonly kind: 'enum'; readonly values: readonly string[] }
  | { readonly kind: 'int' }
  | { readonly kind: 'bool' }
  | { readonly kind: 'route' }
  | { readonly kind: 'sqlstate' }
  | { readonly kind: 'errorName' }
  | { readonly kind: 'errorCode' }
  | { readonly kind: 'reqId' };

const CODE: FieldRule = { kind: 'code' };
const INT: FieldRule = { kind: 'int' };
const COMPONENTS: readonly (Component | 'unknown')[] = [
  'idp',
  'relay',
  'company-api',
  'keysvc',
  'sender',
  'unknown',
];

/** 載せてよいフィールド。 */
export const LOG_FIELD_RULES: Readonly<Record<string, FieldRule>> = Object.freeze({
  event: CODE,
  op: CODE,
  target: CODE,
  purpose: CODE,
  keyId: CODE,
  reason: CODE,
  service: { kind: 'enum', values: COMPONENTS },
  method: {
    kind: 'enum',
    values: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  },
  route: { kind: 'route' },
  status: INT,
  durationMs: INT,
  count: INT,
  errorName: { kind: 'errorName' },
  errorCode: { kind: 'errorCode' },
  sqlstate: { kind: 'sqlstate' },
  reqId: { kind: 'reqId' },
});

/** 載せてよいメッセージ（固定の文だけ）。Fastify 5 が出す2つ。 */
export const ALLOWED_MESSAGES: ReadonlySet<string> = new Set([
  'incoming request',
  'request completed',
]);

export const REDACTED_MESSAGE = '[redacted]';

const CODE_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
// ルートの型（例：/v1/:op）。クエリ（? = &）、フラグメント（#）、利用者情報（@）を含めない。
const ROUTE_PATTERN = /^\/[A-Za-z0-9_\-/:.*]{0,127}$/;
const SQLSTATE_PATTERN = /^[0-9A-Z]{5}$/;
const ERROR_NAME_PATTERN = /^[A-Z][A-Za-z]{0,39}$/;
const REQ_ID_PATTERN = /^req-[0-9a-z]{1,16}$/;

function isCode(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 48 && CODE_PATTERN.test(value);
}

function isSqlstate(value: unknown): value is string {
  return typeof value === 'string' && SQLSTATE_PATTERN.test(value);
}

function accepts(rule: FieldRule, value: unknown): value is string | number | boolean {
  switch (rule.kind) {
    case 'code':
      return isCode(value);
    case 'enum':
      return typeof value === 'string' && rule.values.includes(value);
    case 'int':
      return typeof value === 'number' && Number.isSafeInteger(value);
    case 'bool':
      return typeof value === 'boolean';
    case 'route':
      return typeof value === 'string' && ROUTE_PATTERN.test(value);
    case 'sqlstate':
      return isSqlstate(value);
    case 'errorName':
      return typeof value === 'string' && ERROR_NAME_PATTERN.test(value);
    case 'errorCode':
      return isCode(value) || isSqlstate(value);
    case 'reqId':
      return typeof value === 'string' && REQ_ID_PATTERN.test(value);
  }
}

/** req.url を読まない。method と、ルートの型（routeOptions.url）だけを出す。 */
export function serializeRequest(req: {
  readonly method?: string;
  readonly routeOptions?: { readonly url?: string };
}): { method?: string; route?: string } {
  const out: { method?: string; route?: string } = {};
  const method = req?.method;
  const methodRule = LOG_FIELD_RULES.method;
  if (methodRule !== undefined && accepts(methodRule, method)) out.method = method;
  const route = req?.routeOptions?.url;
  if (accepts({ kind: 'route' }, route)) out.route = route;
  return out;
}

export function serializeResponse(res: { readonly statusCode?: number }): { status?: number } {
  const status = res?.statusCode;
  return accepts(INT, status) ? { status } : {};
}

/** 例外の名前とコードだけを出す。message、detail、stack、cause は出さない（入力の値が入りうるため）。 */
export function serializeError(err: unknown): { errorName?: string; errorCode?: string } {
  const out: { errorName?: string; errorCode?: string } = {};
  if (err === null || typeof err !== 'object') return out;
  const name = (err as { name?: unknown }).name;
  if (typeof name === 'string' && ERROR_NAME_PATTERN.test(name)) out.errorName = name;
  const code = (err as { code?: unknown }).code;
  if (isCode(code) || isSqlstate(code)) out.errorCode = code;
  return out;
}

/** 許可リストに合うフィールドだけを残す。合わないものは落とし、その数を dropped に出す（キーの名前も出さない）。 */
export function sanitizeFields(
  fields: Readonly<Record<string, unknown>>,
): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  let dropped = 0;
  if (fields === null || typeof fields !== 'object') return out;
  for (const [key, value] of Object.entries(fields)) {
    if (key === 'req') {
      Object.assign(out, serializeRequest(value as Parameters<typeof serializeRequest>[0]));
      continue;
    }
    if (key === 'res') {
      Object.assign(out, serializeResponse(value as Parameters<typeof serializeResponse>[0]));
      continue;
    }
    if (key === 'err' || key === 'error') {
      Object.assign(out, serializeError(value));
      continue;
    }
    if (key === 'responseTime') {
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
        out.durationMs = Math.round(value);
      } else {
        dropped += 1;
      }
      continue;
    }
    const rule = Object.hasOwn(LOG_FIELD_RULES, key) ? LOG_FIELD_RULES[key] : undefined;
    if (rule !== undefined && accepts(rule, value)) {
      out[key] = value;
    } else {
      dropped += 1;
    }
  }
  if (dropped > 0) out.dropped = dropped;
  return out;
}

export function sanitizeMessage(message: unknown): string | undefined {
  if (message === undefined) return undefined;
  return typeof message === 'string' && ALLOWED_MESSAGES.has(message) ? message : REDACTED_MESSAGE;
}
