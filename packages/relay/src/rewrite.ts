// 中継の衛生（plan 3-2、ADR 0021）。書き換えるのはヘッダーだけ。件名と本文は、元のバイト列のまま残す。
//
// 企業 → 利用者：
// - From を「〈登録簿の企業名〉 <返信用のアドレス>」にする。返信用のアドレスの先は、元の Reply-To（なければ From）。
//   利用者が返信しても、本物のアドレスから企業へ直接は届かない。受信側の DMARC は relay の署名で整合する。
// - To は別名だけにする。Cc は消す（ほかの宛先を見せない。全員に返信したときの漏れを防ぐ。plan より強い）。
// - List-Unsubscribe は最初の1つだけを読む。mailto: は返信用のアドレスに替え、https: はそのまま、それ以外は消す。
//   List-Unsubscribe-Post は、値が `List-Unsubscribe=One-Click` で、https: が残ったときだけ残す（RFC 8058。
//   受信側の事業者が POST するだけで、利用者のアドレスは企業に渡らない）。
// - 開封通知（Disposition-Notification-To、Return-Receipt-To）、Reply-To、Sender、Return-Path、
//   企業の DKIM-Signature と ARC の組、Authentication-Results、Received-SPF を消す。
//
// 利用者 → 企業（返信）：
// - 残すのは、件名、日付、MIME の項目、In-Reply-To と References だけ。それ以外（Received、DKIM-Signature、
//   X-* を含む）は消す。From は返信用のアドレス、To は企業の側のアドレス、Message-ID は relay で作り直す。
// - In-Reply-To と References からは、本物のアドレスのドメイン（とその下）の Message-ID を消す（利用者が自分の
//   送ったメールに返信したときに、独自ドメインや事業者の名前が企業へ渡らないようにする）。
// - X-Warifu-Unauthenticated を付ける（送り主が本人であることは確かめていない。plan 3-2）。

import {
  encodeWord,
  field,
  fieldsNamed,
  type HeaderField,
  headerValue,
  type ParsedMessage,
} from './mime.ts';

const DROP_TO_USER = new Set([
  'reply-to',
  'sender',
  'return-path',
  'cc',
  'bcc',
  'disposition-notification-to',
  'return-receipt-to',
  'dkim-signature',
  'arc-seal',
  'arc-message-signature',
  'arc-authentication-results',
  'authentication-results',
  'received-spf',
]);

const ONE_CLICK = 'List-Unsubscribe=One-Click';

const KEEP_TO_COMPANY = [
  'subject',
  'date',
  'mime-version',
  'content-type',
  'content-transfer-encoding',
  'content-language',
] as const;

const MESSAGE_ID_REFERENCES = [
  ['in-reply-to', 'In-Reply-To'],
  ['references', 'References'],
] as const;

export interface ToUserInput {
  readonly message: ParsedMessage;
  readonly displayName: string;
  /** 宛先の別名（受け取ったアドレスそのもの）。 */
  readonly alias: string;
  /** 返信の先（企業の側のアドレス）を受け取り、返信用のアドレスを返す。 */
  readonly threadFor: (target: string) => Promise<string>;
  /** 元の From のアドレス（送信元ロックで確かめたもの）。 */
  readonly fromAddress: string;
  readonly replyTo: string | undefined;
}

export async function rewriteToUser(input: ToUserInput): Promise<HeaderField[]> {
  const replyAddress = await input.threadFor(input.replyTo ?? input.fromAddress);
  const unsubscribe = fieldsNamed(input.message.headers, 'list-unsubscribe')[0];
  const entries: string[] = [];
  let keptHttps = false;
  if (unsubscribe !== undefined) {
    for (const [, uri] of headerValue(unsubscribe).matchAll(/<([^<>]*)>/g)) {
      if (uri === undefined) continue;
      if (/^https:\/\/[\x21-\x7e]+$/i.test(uri)) {
        entries.push(`<${uri}>`);
        keptHttps = true;
      } else if (/^mailto:/i.test(uri)) {
        const target = uri.slice('mailto:'.length).split('?')[0] ?? '';
        if (/^[^@\s<>]+@[^@\s<>]+$/.test(target)) {
          entries.push(`<mailto:${await input.threadFor(decodeURIComponent(target))}>`);
        }
      }
    }
  }
  const posts = fieldsNamed(input.message.headers, 'list-unsubscribe-post');
  const keepPost =
    keptHttps &&
    posts.length === 1 &&
    posts[0] !== undefined &&
    headerValue(posts[0]) === ONE_CLICK;

  const out: HeaderField[] = [];
  let wroteFrom = false;
  let wroteTo = false;
  let wroteUnsubscribe = false;
  for (const h of input.message.headers) {
    if (DROP_TO_USER.has(h.key)) continue;
    if (h.key === 'from') {
      if (!wroteFrom) out.push(field('From', `${encodeWord(input.displayName)} <${replyAddress}>`));
      wroteFrom = true;
      continue;
    }
    if (h.key === 'to') {
      if (!wroteTo) out.push(field('To', `<${input.alias}>`));
      wroteTo = true;
      continue;
    }
    if (h.key === 'list-unsubscribe') {
      if (!wroteUnsubscribe && entries.length > 0) {
        out.push(field('List-Unsubscribe', entries.join(', ')));
      }
      wroteUnsubscribe = true;
      continue;
    }
    if (h.key === 'list-unsubscribe-post') {
      if (keepPost) out.push(field('List-Unsubscribe-Post', ONE_CLICK));
      continue;
    }
    out.push(h);
  }
  if (!wroteTo) out.push(field('To', `<${input.alias}>`));
  return out;
}

export interface ToCompanyInput {
  readonly message: ParsedMessage;
  /** 返信用のアドレス（From にする）。 */
  readonly replyAddress: string;
  /** 企業の側のアドレス（To にする）。 */
  readonly target: string;
  /** relay で作り直す Message-ID。 */
  readonly messageId: string;
  /** 本物のアドレスのドメイン。In-Reply-To と References から、このドメインとその下の Message-ID を消す。 */
  readonly userDomain: string;
}

function referencesWithout(value: string, domain: string): string[] {
  const kept: string[] = [];
  for (const [id] of value.matchAll(/<[^<>\s]+>/g)) {
    const right = id.slice(id.lastIndexOf('@') + 1, -1).toLowerCase();
    if (!id.includes('@') || right === domain || right.endsWith(`.${domain}`)) continue;
    kept.push(id);
  }
  return kept;
}

export function rewriteToCompany(input: ToCompanyInput): HeaderField[] {
  const out: HeaderField[] = [
    field('From', `<${input.replyAddress}>`),
    field('To', `<${input.target}>`),
    field('Message-ID', `<${input.messageId}>`),
    field('X-Warifu-Unauthenticated', '1'),
  ];
  for (const key of KEEP_TO_COMPANY) {
    const first = fieldsNamed(input.message.headers, key)[0];
    if (first !== undefined) out.push(first);
  }
  const domain = input.userDomain.toLowerCase();
  for (const [key, name] of MESSAGE_ID_REFERENCES) {
    const first = fieldsNamed(input.message.headers, key)[0];
    if (first === undefined) continue;
    const kept = referencesWithout(headerValue(first), domain);
    if (kept.length > 0) out.push(field(name, kept.join(' ')));
  }
  return out;
}
