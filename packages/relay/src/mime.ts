// メールのヘッダーの読み書き（ADR 0021）。本文には触れない（バイト単位で変えない。plan 8章）。
// ヘッダーの区切りは mailauth の parseHeaders に任せ、書き換えたヘッダーだけを作り直す。残すヘッダーは元のバイト列のまま。

import tools from 'mailauth/lib/tools.js';
import { splitMessage } from './dkim.ts';

export interface HeaderField {
  /** 小文字の名前。 */
  readonly key: string;
  /** 折り返しを含む、元の1行（末尾の CRLF なし）。 */
  readonly line: Buffer;
}

export interface ParsedMessage {
  readonly headers: readonly HeaderField[];
  readonly body: Buffer;
}

const CRLF = Buffer.from('\r\n');

export function parseMessage(raw: Buffer): ParsedMessage {
  const { head, body } = splitMessage(raw);
  const { parsed } = tools.parseHeaders(head);
  const headers = parsed
    .filter((h) => typeof h.key === 'string' && h.key.length > 0)
    .map((h) => ({ key: h.key as string, line: h.line }));
  return { headers, body };
}

export function buildMessage(headers: readonly HeaderField[], body: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (const h of headers) parts.push(h.line, CRLF);
  parts.push(CRLF, body);
  return Buffer.concat(parts);
}

/** ヘッダーの値（名前とコロンの後ろ。折り返しを戻し、前後の空白を除く）。 */
export function headerValue(field: HeaderField): string {
  const text = field.line.toString('latin1');
  const colon = text.indexOf(':');
  return text
    .slice(colon + 1)
    .replace(/\r?\n[ \t]+/g, ' ')
    .trim();
}

export function fieldsNamed(headers: readonly HeaderField[], key: string): HeaderField[] {
  return headers.filter((h) => h.key === key);
}

/** 新しいヘッダーの1行。値に CR と LF は入れない（呼び出し側で作った固定の形だけを渡す）。 */
export function field(name: string, value: string): HeaderField {
  if (/[\r\n]/.test(value) || /[\r\n:]/.test(name)) throw new RangeError('ヘッダーの形が違う');
  return { key: name.toLowerCase(), line: Buffer.from(`${name}: ${value}`, 'utf8') };
}

/** RFC 2047 の encoded-word（UTF-8、B 符号化）。表示名に使う。 */
export function encodeWord(text: string): string {
  if (/^[\x20-\x7e]*$/.test(text) && !/[()<>@,;:\\".[\]=?]/.test(text)) return text;
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

const ADDR_SPEC = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$/;

/**
 * 1つのアドレスだけを持つ値から、アドレスを取り出す（Reply-To などに使う）。`<addr>` か、裸の addr-spec だけを読む。
 * 読み切れない形（複数、グループ、コメント、引用の中の山括弧など）は undefined（読めないものは使わない）。
 */
export function singleAddress(value: string): string | undefined {
  const angle = value.match(/<([^<>]*)>/g);
  let candidate: string | undefined;
  if (angle !== null) {
    if (angle.length !== 1) return undefined;
    candidate = angle[0].slice(1, -1).trim();
    const outside = value.replace(angle[0], '');
    if (/[<>@,;]/.test(outside.replace(/"[^"]*"/g, ''))) return undefined;
  } else {
    candidate = value.trim();
  }
  if (!ADDR_SPEC.test(candidate)) return undefined;
  return candidate;
}
