// 返信の検査（plan 3-2、ADR 0021）。利用者から企業へ送る返信に、本物のアドレスが含まれていないかを確かめる。
//
// 見るのは、企業へ送るもの全部：残すヘッダー（件名など）と、本文の各部分（部分のヘッダー、前置きと後置きを含む）。
// - 転送符号化（base64、quoted-printable）と文字コード（Content-Type の charset。TextDecoder が知るもの）を戻す。
// - ヘッダーの encoded-word（RFC 2047）と、パラメータの %xx（RFC 2231）を戻す。
// - HTML の文字参照（数値と、アドレスに使う記号の名前）を戻し、タグを除いたものも見る。URL の %xx を戻したものも見る。
// - NFKC で全角を半角にし、書式の文字（ゼロ幅の空白、ソフトハイフンなど）を除き、大文字と小文字を区別しない。
// 中身を確かめられない部分（text/* と multipart/* と message/rfc822 以外の形式、添付ファイル（attachment の指定か、
// ファイル名の付いた部分。形式によらない）、知らない文字コードや転送符号化、HTML の中の data: URI、境界のない
// multipart、終わりの境界のない multipart、深すぎる入れ子、多すぎる部分）があれば、確かめられないとして扱う。
// 利用者が意図して崩した書き方（「at」と書く、画像にする）は、検出の対象にしない（ADR 0021 の残るリスク）。

import {
  fieldsNamed,
  type HeaderField,
  headerValue,
  type ParsedMessage,
  parseMessage,
} from './mime.ts';

export type InspectResult = 'clean' | 'contains_address' | 'uninspectable';

const MAX_DEPTH = 8;
const MAX_PARTS = 100;

/** アドレスに使う記号と、よく使う記号の名前の文字参照。ほかの名前は戻さない（意図して崩したものは対象外）。 */
const NAMED_REFERENCES: Readonly<Record<string, string>> = Object.freeze({
  commat: '@',
  period: '.',
  lowbar: '_',
  plus: '+',
  hyphen: '-',
  dash: '-',
  minus: '-',
  num: '#',
  percnt: '%',
  excl: '!',
  quest: '?',
  equals: '=',
  sol: '/',
  comma: ',',
  colon: ':',
  semi: ';',
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
});

class Uninspectable extends Error {
  override name = 'Uninspectable';
}

function decoderFor(charset: string): { decode(input: Uint8Array): string } {
  try {
    return new TextDecoder(charset === '' ? 'utf-8' : charset, { fatal: false });
  } catch {
    throw new Uninspectable();
  }
}

function fromCodePoint(value: number): string {
  return Number.isInteger(value) && value > 0 && value <= 0x10ffff
    ? String.fromCodePoint(value)
    : '';
}

function decodeReferences(text: string): string {
  return text
    .replace(/&#x([0-9a-f]{1,6});?/gi, (_, hex: string) => fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#([0-9]{1,7});?/g, (_, dec: string) => fromCodePoint(Number.parseInt(dec, 10)))
    .replace(
      /&([a-z]{2,8});/gi,
      (all, name: string) => NAMED_REFERENCES[name.toLowerCase()] ?? all,
    );
}

function decodePercent(text: string): string {
  return text.replace(/%([0-9a-f]{2})/gi, (_, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

function normalize(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/\p{Cf}/gu, '')
    .toLowerCase();
}

class Finder {
  readonly #needle: string;
  parts = 0;
  found = false;

  constructor(address: string) {
    this.#needle = normalize(address);
  }

  /** 文字列を、戻し方を変えた形でそれぞれ見る。 */
  text(value: string): void {
    if (this.found) return;
    const references = decodeReferences(value);
    for (const variant of [
      value,
      references,
      references.replace(/<[^>]*>/g, ''),
      decodeReferences(value.replace(/<[^>]*>/g, '')),
      decodePercent(references),
    ]) {
      if (normalize(variant).includes(this.#needle)) {
        this.found = true;
        return;
      }
    }
  }

  /** バイト列を、UTF-8 と Latin-1 と（あれば）宣言された文字コードで読んで見る。 */
  bytes(value: Uint8Array, charset?: string): void {
    this.text(new TextDecoder('utf-8').decode(value));
    this.text(Buffer.from(value).toString('latin1'));
    if (charset !== undefined) this.text(decoderFor(charset).decode(value));
  }
}

/** encoded-word（RFC 2047）を戻す。知らない文字コードや形は、確かめられないとして扱う。 */
export function decodeEncodedWords(value: string): string {
  return value
    .replace(/(=\?[^?\s]+\?[bq]\?[^?\s]*\?=)\s+(?==\?)/gi, '$1')
    .replace(
      /=\?([^?\s]+)\?([bq])\?([^?\s]*)\?=/gi,
      (_, charsetSpec: string, kind: string, text: string) => {
        const charset = charsetSpec.split('*')[0] ?? '';
        const bytes =
          kind.toLowerCase() === 'b'
            ? Buffer.from(text, 'base64')
            : Buffer.from(
                text
                  .replace(/_/g, ' ')
                  .replace(/=([0-9a-f]{2})/gi, (__, hex: string) =>
                    String.fromCharCode(Number.parseInt(hex, 16)),
                  ),
                'latin1',
              );
        return decoderFor(charset.toLowerCase()).decode(bytes);
      },
    );
}

function headerParameters(value: string): {
  readonly type: string;
  readonly params: Map<string, string>;
} {
  const [first, ...rest] = value.split(';');
  const params = new Map<string, string>();
  for (const part of rest) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    const key = part.slice(0, at).trim().toLowerCase();
    params.set(
      key,
      part
        .slice(at + 1)
        .trim()
        .replace(/^"(.*)"$/s, '$1'),
    );
  }
  return { type: (first ?? '').trim().toLowerCase(), params };
}

function inspectHeaders(headers: readonly HeaderField[], finder: Finder): void {
  for (const field of headers) {
    finder.bytes(field.line);
    finder.text(decodeEncodedWords(field.line.toString('utf8')));
  }
}

function transferDecoded(body: Buffer, headers: readonly HeaderField[]): Buffer {
  const cte = fieldsNamed(headers, 'content-transfer-encoding')[0];
  const encoding = cte === undefined ? '7bit' : headerValue(cte).toLowerCase();
  switch (encoding) {
    case '7bit':
    case '8bit':
    case 'binary':
      return body;
    case 'base64':
      return Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
    case 'quoted-printable':
      return Buffer.from(
        body
          .toString('latin1')
          .replace(/=\r?\n/g, '')
          .replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) =>
            String.fromCharCode(Number.parseInt(hex, 16)),
          ),
        'latin1',
      );
    default:
      throw new Uninspectable();
  }
}

/** 部分に分ける。始まりの境界がない、終わりの境界がない（途中で切れた）ものは、確かめられないとして扱う。 */
function splitParts(body: Buffer, boundary: string): Buffer[] {
  const lines = body.toString('latin1').split('\r\n');
  const parts: Buffer[] = [];
  let current: string[] | undefined;
  let closed = false;
  for (const line of lines) {
    const trimmed = line.replace(/[ \t]+$/, '');
    if (trimmed === `--${boundary}` || trimmed === `--${boundary}--`) {
      if (current !== undefined) parts.push(Buffer.from(current.join('\r\n'), 'latin1'));
      closed = trimmed !== `--${boundary}`;
      current = closed ? undefined : [];
      continue;
    }
    current?.push(line);
  }
  if (!closed || parts.length === 0) throw new Uninspectable();
  return parts;
}

/** 添付ファイルか（attachment の指定、または部分にファイル名が付いている）。形式によらず差し戻す（O-27）。 */
function isAttachment(headers: readonly HeaderField[]): boolean {
  const cd = fieldsNamed(headers, 'content-disposition')[0];
  if (cd !== undefined) {
    const { type, params } = headerParameters(headerValue(cd));
    if (type === 'attachment' || [...params.keys()].some((k) => k.startsWith('filename'))) {
      return true;
    }
  }
  const ct = fieldsNamed(headers, 'content-type')[0];
  return (
    ct !== undefined &&
    [...headerParameters(headerValue(ct)).params.keys()].some((k) => k.startsWith('name'))
  );
}

function parsePart(raw: Buffer): ParsedMessage {
  if (raw.subarray(0, 2).toString('latin1') === '\r\n' || raw.byteLength === 0) {
    return { headers: [], body: raw.subarray(2) };
  }
  return parseMessage(raw);
}

function inspectEntity(
  headers: readonly HeaderField[],
  body: Buffer,
  depth: number,
  finder: Finder,
): void {
  if (finder.found) return;
  finder.parts += 1;
  if (depth > MAX_DEPTH || finder.parts > MAX_PARTS) throw new Uninspectable();
  // 前置きと後置き、部分のヘッダーも企業へ届くので、生のまま一度見る。
  finder.bytes(body);
  if (isAttachment(headers)) throw new Uninspectable();
  const ct = fieldsNamed(headers, 'content-type')[0];
  const { type, params } = headerParameters(ct === undefined ? 'text/plain' : headerValue(ct));
  if (type.startsWith('multipart/')) {
    const boundary = params.get('boundary');
    if (boundary === undefined || boundary === '') throw new Uninspectable();
    for (const part of splitParts(body, boundary)) {
      const parsed = parsePart(part);
      inspectHeaders(parsed.headers, finder);
      inspectEntity(parsed.headers, parsed.body, depth + 1, finder);
    }
    return;
  }
  const decoded = transferDecoded(body, headers);
  if (type === 'message/rfc822' || type === 'message/global') {
    const inner = parseMessage(decoded);
    inspectHeaders(inner.headers, finder);
    inspectEntity(inner.headers, inner.body, depth + 1, finder);
    return;
  }
  if (!type.startsWith('text/')) throw new Uninspectable();
  const charset = (params.get('charset') ?? 'us-ascii').toLowerCase();
  finder.bytes(decoded, charset);
  if (type === 'text/html') {
    const text = decoderFor(charset).decode(decoded);
    // 属性や CSS の値の data: URI（埋め込んだ画像など）は、中身を確かめられない。
    if (/(=|url\()\s*["']?\s*data:/i.test(decodeReferences(text))) throw new Uninspectable();
  }
}

/**
 * 企業へ送る返信（残すヘッダーと本文）に、そのアドレスが含まれるか。含まれれば contains_address、
 * 含まれないが確かめられない部分があれば uninspectable、どちらでもなければ clean。
 */
export function inspectReply(
  outgoingHeaders: readonly HeaderField[],
  message: ParsedMessage,
  address: string,
): InspectResult {
  const finder = new Finder(address);
  let uninspectable = false;
  const guard = (task: () => void) => {
    try {
      task();
    } catch (error) {
      if (error instanceof Uninspectable) uninspectable = true;
      else throw error;
    }
  };
  for (const field of outgoingHeaders) guard(() => inspectHeaders([field], finder));
  guard(() => inspectEntity(message.headers, message.body, 0, finder));
  if (finder.found) return 'contains_address';
  return uninspectable ? 'uninspectable' : 'clean';
}
