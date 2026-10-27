// 中継の衛生（plan 3-2・8章、plan 11章 テスト5、ADR 0021）。企業から利用者へ届けるメールは、ヘッダーだけを書き換え、
// 本文はバイト単位で変えない。開封通知、配信停止、全員に返信、署名の外の Reply-To から、本物のアドレスが企業へ漏れない。

import { authenticate } from 'mailauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseMessage } from '../../packages/relay/src/mime.ts';
import { THREAD_LOCAL_PART_PATTERN } from '../../packages/relay/src/relay.ts';
import {
  addUser,
  companyMail,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestCompany,
  type TestRelay,
  type TestUser,
} from '../setup/relay.ts';

let t: TestRelay;
let user: TestUser;
let company: TestCompany;
let alias: string;

beforeAll(async () => {
  t = await startTestRelay();
  user = await addUser(t.companies);
  const [c] = t.companies;
  const [a] = user.aliases;
  if (c === undefined || a === undefined) throw new Error('準備に失敗した');
  company = c;
  alias = a;
});

afterAll(async () => {
  await t.stop();
});

/** 企業から別名へ1通送り、利用者に届いたものを返す。 */
async function forward(raw: Buffer) {
  const before = t.outbound.all().length;
  const { data } = await sendMail(
    t.relay.smtpPort,
    { from: `bounce@${company.senderDomain}`, to: alias },
    raw,
  );
  await t.relay.idle();
  expect(data?.code).toBe(250);
  const got = t.outbound.all().slice(before);
  expect(got).toHaveLength(1);
  const [message] = got;
  if (message === undefined) throw new Error('届いていない');
  expect(message.rcptTo).toBe(user.email);
  return message;
}

function headerLines(raw: Buffer): string[] {
  return parseMessage(raw).headers.map((h) =>
    h.line.toString('latin1').replace(/\r\n[ \t]+/g, ' '),
  );
}

function named(raw: Buffer, key: string): string[] {
  return parseMessage(raw)
    .headers.filter((h) => h.key === key)
    .map((h) => {
      const text = h.line.toString('latin1').replace(/\r\n[ \t]+/g, ' ');
      return text.slice(text.indexOf(':') + 1).trim();
    });
}

function threadAddress(value: string): string {
  const match = value.match(/<([^<>]+)>/);
  const address = match?.[1] ?? '';
  const [local, domain] = address.split('@');
  expect(local).toMatch(THREAD_LOCAL_PART_PATTERN);
  expect(domain).toBe(company.relayDomain);
  return address;
}

describe('漏えい：中継の衛生（plan 11章 テスト5）', () => {
  it('開封通知、Cc、Bcc、Sender、Return-Path、企業の署名を消し、To を別名だけにする', async () => {
    // 攻撃者が持っている情報：企業の送信の経路（企業の中の者、または企業のメールを書ける者）
    // 試す経路：開封通知（Disposition-Notification-To、Return-Receipt-To）を自分のアドレスに向け、Cc と Bcc に
    //           ほかの宛先を入れ、Sender と Return-Path を付けたメールを、正しく署名して別名に送る
    // 期待する結果：利用者に届くメールには、どれも残らない。To は別名だけ。From は登録簿の企業名と返信用のアドレス。
    //               利用者のメールソフトが開封通知を返しても、全員に返信しても、本物のアドレスは企業に届かない
    // plan 11章：テスト5（開封通知、全員に返信）
    const raw = await signCompanyMail(
      company,
      companyMail(company, `"お客様" <${alias}>, <other-customer@${company.senderDomain}>`, [
        `Cc: <cc-${company.senderDomain}@watch.example>`,
        `Bcc: <bcc@${company.senderDomain}>`,
        `Disposition-Notification-To: <dnt@${company.senderDomain}>`,
        `Return-Receipt-To: <rrt@${company.senderDomain}>`,
        `Sender: <sender@${company.senderDomain}>`,
        `Return-Path: <rp@${company.senderDomain}>`,
      ]),
    );
    const message = await forward(raw);
    for (const key of [
      'cc',
      'bcc',
      'disposition-notification-to',
      'return-receipt-to',
      'sender',
      'return-path',
      'reply-to',
    ]) {
      expect(named(message.raw, key), key).toEqual([]);
    }
    expect(named(message.raw, 'to')).toEqual([`<${alias}>`]);
    const [from, ...moreFrom] = named(message.raw, 'from');
    expect(moreFrom).toEqual([]);
    expect(from).toMatch(/^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?= </);
    expect(
      Buffer.from(from?.match(/^=\?UTF-8\?B\?([^?]+)\?=/)?.[1] ?? '', 'base64').toString('utf8'),
    ).toBe(company.displayName);
    threadAddress(from ?? '');
    // 企業の DKIM-Signature は消え、relay の DKIM と ARC の組だけになる。
    const dkim = named(message.raw, 'dkim-signature');
    expect(dkim).toHaveLength(1);
    expect(dkim[0]).toContain(`d=${company.relayDomain}`);
    expect(named(message.raw, 'arc-seal')).toHaveLength(1);
    // ほかの宛先と企業の送信の経路は、ヘッダーのどこにも残らない。
    const text = headerLines(message.raw).join('\n');
    for (const needle of [
      'other-customer@',
      'watch.example',
      'bcc@',
      'dnt@',
      'rrt@',
      'sender@',
      'rp@',
    ]) {
      expect(text).not.toContain(needle);
    }
  });

  it('List-Unsubscribe の mailto: を返信用のアドレスに替え、https: と one-click は残し、ほかの形は消す', async () => {
    // 攻撃者が持っている情報：企業の送信の経路
    // 試す経路：List-Unsubscribe に mailto:（企業のアドレス）、https:、http:、ほかの形を並べて、別名に送る
    // 期待する結果：mailto: は返信用のアドレスに替わり、https: は残り、http: とほかの形は消える。
    //               利用者が配信停止のメールを送っても、本物のアドレスは企業に届かない（返信の中継を通る）。
    //               List-Unsubscribe-Post（One-Click）は、https: が残るので残る
    // plan 11章：テスト5（配信停止）
    const raw = await signCompanyMail(
      company,
      companyMail(company, alias, [
        `List-Unsubscribe: <mailto:unsub@${company.senderDomain}?subject=stop>, <https://${company.senderDomain}/u/opaque>, <http://${company.senderDomain}/u/plain>, <ftp://x.example/u>`,
        'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
      ]),
      {
        headerList:
          'From:From:To:To:Subject:Subject:Date:Message-ID:List-Unsubscribe:List-Unsubscribe-Post',
      },
    );
    const message = await forward(raw);
    const [unsubscribe, ...more] = named(message.raw, 'list-unsubscribe');
    expect(more).toEqual([]);
    const entries = (unsubscribe ?? '').split(', ');
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatch(/^<mailto:r-[a-z2-7]{26}@/);
    expect(entries[0]).toContain(`@${company.relayDomain}>`);
    expect(entries[1]).toBe(`<https://${company.senderDomain}/u/opaque>`);
    expect(unsubscribe).not.toContain(`unsub@${company.senderDomain}`);
    expect(named(message.raw, 'list-unsubscribe-post')).toEqual(['List-Unsubscribe=One-Click']);
  });

  it('https: が残らないときは、List-Unsubscribe-Post を消す', async () => {
    // 攻撃者が持っている情報：企業の送信の経路
    // 試す経路：mailto: だけの List-Unsubscribe に、List-Unsubscribe-Post を付けて送る
    // 期待する結果：List-Unsubscribe-Post は消える（POST の宛先がないので、受信側に自動の要求を作らせない）
    // plan 11章：テスト5（配信停止）
    const raw = await signCompanyMail(
      company,
      companyMail(company, alias, [
        `List-Unsubscribe: <mailto:unsub@${company.senderDomain}>`,
        'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
      ]),
    );
    const message = await forward(raw);
    expect(named(message.raw, 'list-unsubscribe')).toHaveLength(1);
    expect(named(message.raw, 'list-unsubscribe-post')).toEqual([]);
  });

  it('本文は、バイト単位で変えない', async () => {
    // 攻撃者が持っている情報：なし（中継が本文を壊さないことの確認）
    // 試す経路：8ビットの文字、長い行、行頭のドット、末尾の空行を含む本文を送る
    // 期待する結果：利用者に届いたメールの本文が、送ったものとバイト単位で同じ
    // plan 11章：テスト5（転送した本文はバイト単位で同じ）
    const body = `ご予約番号は下のとおりです。\r\n.先頭のドット\r\n${'x'.repeat(900)}\r\n\r\n\r\n`;
    const raw = await signCompanyMail(company, companyMail(company, alias, [], body));
    const message = await forward(raw);
    expect(parseMessage(message.raw).body.equals(parseMessage(raw).body)).toBe(true);
    expect(parseMessage(message.raw).body.equals(Buffer.from(body, 'utf8'))).toBe(true);
  });

  it('受信側で、relay の DKIM、ARC、DMARC（p=reject）が pass し、件名は元のまま', async () => {
    // 攻撃者が持っている情報：なし（届けたメールが受信側で拒否されないことの確認）
    // 試す経路：受信側の事業者の検証（mailauth で模擬。DNS は relay の公開鍵と DMARC の記録だけ）
    // 期待する結果：DKIM は relay のドメインで pass、ARC は pass、DMARC は pass。件名のバイト列は元のまま
    // plan 11章：テスト5（p=reject の送信元）
    const raw = await signCompanyMail(company, companyMail(company, alias));
    const message = await forward(raw);
    const result = await authenticate(message.raw, {
      ip: '192.0.2.25',
      helo: 'mx.relay.warifu.test',
      mta: 'mx.users.example',
      sender: message.mailFrom,
      resolver: t.dns(),
      disableBimi: true,
    } as Parameters<typeof authenticate>[1]);
    expect(result.dkim.results.map((r) => [r.signingDomain, r.status.result])).toEqual([
      [company.relayDomain, 'pass'],
    ]);
    expect((result.arc || undefined)?.status.result).toBe('pass');
    expect((result.dmarc || undefined)?.status.result).toBe('pass');
    expect(named(message.raw, 'subject')).toEqual(named(raw, 'subject'));
  });

  it('利用者に届けたメールの封筒と記録に、別名と本物のアドレスの組が平文で残らない', async () => {
    // 攻撃者が持っている情報：relay のログ（ログを読める運用者、またはログの漏えい）
    // 試す経路：企業から別名へ送り、relay が書いたログの全行を、本物のアドレスと別名で検索する
    // 期待する結果：ヒットが0件。封筒の MAIL FROM は relay のドメインの戻りのアドレス
    // plan 11章：テスト7 の一部（平文を残さない）
    const logged = t.logs.length;
    const message = await forward(await signCompanyMail(company, companyMail(company, alias)));
    expect(message.mailFrom).toBe(`bounces@${company.relayDomain}`);
    const lines = t.logs.slice(logged).join('\n');
    expect(lines).not.toContain(user.email);
    expect(lines).not.toContain(alias.split('@')[0] ?? alias);
  });
});
