// 返信の中継（plan 3-2、plan 11章 テスト5、ADR 0021）。利用者からの返信は、From が本物のアドレスで、そのドメインで
// DMARC が整合して pass したものだけを、やり取りごとの返信用のアドレスから企業へ届ける。中継したメールは本人の承認ではない
// （X-Warifu-Unauthenticated。RP-45）。本物のアドレスと、そのドメインは企業へ渡さない。

import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { authenticate } from 'mailauth';
import { dkimSign } from 'mailauth/lib/dkim/sign.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseMessage } from '../../packages/relay/src/mime.ts';
import {
  addUser,
  companyMail,
  NOTICE_DOMAIN,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestCompany,
  type TestRelay,
  type TestUser,
} from '../setup/relay.ts';

interface MailDomain {
  readonly domain: string;
  readonly selector: string;
  readonly key: KeyObject;
}

function mailDomain(prefix: string): MailDomain {
  return {
    domain: `${prefix}${randomBytes(4).toString('hex')}.example`,
    selector: 'mua',
    key: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey,
  };
}

function dnsOf(...domains: MailDomain[]): Record<string, string> {
  const records: Record<string, string> = {};
  for (const d of domains) {
    const spki = createPublicKey(d.key).export({ type: 'spki', format: 'der' }).toString('base64');
    records[`TXT:${d.selector}._domainkey.${d.domain}`] = `v=DKIM1; k=rsa; p=${spki}`;
    records[`TXT:_dmarc.${d.domain}`] = 'v=DMARC1; p=reject';
  }
  return records;
}

const userDomain = mailDomain('users');
const attackerDomain = mailDomain('attacker');
let clockOffset = 0;
let t: TestRelay;
let user: TestUser;
let company: TestCompany;
let other: TestCompany;
let alias: string;

beforeAll(async () => {
  t = await startTestRelay({
    companies: 2,
    replyDns: dnsOf(userDomain, attackerDomain),
    now: () => new Date(Date.now() + clockOffset),
  });
  user = await addUser(t.companies, `u${randomBytes(6).toString('hex')}@${userDomain.domain}`);
  const [c, o] = t.companies;
  const [a] = user.aliases;
  if (c === undefined || o === undefined || a === undefined) throw new Error('準備に失敗した');
  company = c;
  other = o;
  alias = a;
});

afterAll(async () => {
  await t.stop();
});

async function send(from: string, to: string, raw: Buffer) {
  const result = await sendMail(t.relay.smtpPort, { from, to }, raw);
  await t.relay.idle();
  return result;
}

function named(raw: Buffer, key: string): string[] {
  return parseMessage(raw)
    .headers.filter((h) => h.key === key)
    .map((h) => {
      const text = h.line.toString('latin1').replace(/\r\n[ \t]+/g, ' ');
      return text.slice(text.indexOf(':') + 1).trim();
    });
}

/** 企業から別名へ送り、利用者に届いたメールの From（返信用のアドレス）と Message-ID を返す。 */
async function openThread(options?: {
  readonly extraHeaders?: readonly string[];
  readonly headerList?: string;
}): Promise<{ readonly thread: string; readonly messageId: string }> {
  const before = t.outbound.all().length;
  const raw = await signCompanyMail(
    company,
    companyMail(
      company,
      alias,
      options?.extraHeaders ?? [`Reply-To: <support@${company.senderDomain}>`],
    ),
    options?.headerList === undefined ? undefined : { headerList: options.headerList },
  );
  const { data } = await send(`bounce@${company.senderDomain}`, alias, raw);
  expect(data?.code).toBe(250);
  const got = t.outbound.all().slice(before);
  expect(got.map((m) => m.rcptTo)).toEqual([user.email]);
  const message = got[0];
  if (message === undefined) throw new Error('届いていない');
  const thread = named(message.raw, 'from')[0]?.match(/<([^<>]+)>/)?.[1];
  const messageId = named(message.raw, 'message-id')[0];
  if (thread === undefined || messageId === undefined) throw new Error('返信用のアドレスがない');
  return { thread, messageId };
}

/** 利用者（またはそれを名乗る者）の返信。signer があれば、そのドメインの鍵で DKIM の署名を付ける。 */
async function reply(input: {
  readonly from: string;
  readonly to: string;
  readonly inReplyTo: string;
  readonly references?: string;
  readonly subject?: string;
  /** 本文の MIME のヘッダー（既定は text/plain の UTF-8）。 */
  readonly contentHeaders?: readonly string[];
  readonly body?: string;
  readonly signer?: MailDomain;
}): Promise<Buffer> {
  const raw = [
    'Received: from [198.51.100.7] (home.isp.example [198.51.100.7]) by mx.users.example',
    `From: <${input.from}>`,
    `To: <${input.to}>`,
    `Subject: ${input.subject ?? 'Re: =?UTF-8?B?44GU5LqI57SE44Gu56K66KqN?='}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomUUID()}@${input.from.split('@')[1]}>`,
    `In-Reply-To: ${input.inReplyTo}`,
    `References: ${input.references ?? input.inReplyTo}`,
    'X-Mailer: TestMUA 1.0',
    'MIME-Version: 1.0',
    ...(input.contentHeaders ?? ['Content-Type: text/plain; charset=utf-8']),
    '',
    input.body ?? '予約の時間を変えたいです。\r\n',
  ].join('\r\n');
  const bytes = Buffer.from(raw);
  if (input.signer === undefined) return bytes;
  const signed = await dkimSign(bytes, {
    canonicalization: 'relaxed/relaxed',
    signatureData: [
      {
        signingDomain: input.signer.domain,
        selector: input.signer.selector,
        privateKey: input.signer.key.export({ type: 'pkcs8', format: 'pem' }).toString(),
        headerList: 'From:To:Subject:Date:Message-ID:In-Reply-To:References',
      },
    ],
  });
  return Buffer.concat([Buffer.from(signed.signatures), bytes]);
}

interface ReplyShape {
  readonly subject?: string;
  readonly contentHeaders?: readonly string[];
  readonly body?: string;
}

const local = () => user.email.split('@')[0] ?? '';
const domain = () => user.email.split('@')[1] ?? '';

function base64Lines(bytes: Buffer): string {
  return `${(bytes.toString('base64').match(/.{1,76}/g) ?? []).join('\r\n')}\r\n`;
}

/** ASCII の印字できる文字を全角にする。 */
function fullwidth(text: string): string {
  return [...text]
    .map((c) => (c >= '!' && c <= '~' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c))
    .join('');
}

/** 「連絡先：」と、全角にしたアドレスを ISO-2022-JP で書いたバイト列（英小文字、数字、@、. だけを扱う）。 */
function iso2022jpFullwidth(address: string): Buffer {
  const out = [0x1b, 0x24, 0x42, 0x4f, 0x22, 0x4d, 0x6d, 0x40, 0x68, 0x21, 0x27];
  for (const c of address) {
    if (c === '@') out.push(0x21, 0x77);
    else if (c === '.') out.push(0x21, 0x25);
    else out.push(0x23, c.charCodeAt(0));
  }
  out.push(0x1b, 0x28, 0x42, 0x0d, 0x0a);
  return Buffer.from(out);
}

function multipart(type: string, parts: readonly (readonly string[])[]): ReplyShape {
  const boundary = `b${randomBytes(6).toString('hex')}`;
  return {
    contentHeaders: [`Content-Type: multipart/${type}; boundary="${boundary}"`],
    body: `${parts.map((p) => `--${boundary}\r\n${p.join('\r\n')}`).join('\r\n')}\r\n--${boundary}--\r\n`,
  };
}

const plainPart = (text = '予約の時間を変えたいです。') => [
  'Content-Type: text/plain; charset=utf-8',
  '',
  text,
];
const htmlPart = (html: string) => ['Content-Type: text/html; charset=utf-8', '', html];

/** 返信用のアドレスを開き、その形の返信を本物のアドレスから送って、送られたものを返す。 */
async function sendShapedReply(shape: ReplyShape) {
  const { thread, messageId } = await openThread();
  const raw = await reply({
    from: user.email,
    to: thread,
    inReplyTo: messageId,
    signer: userDomain,
    ...shape,
  });
  const before = t.outbound.all().length;
  const { data } = await send(user.email, thread, raw);
  expect(data?.code).toBe(250);
  return t.outbound.all().slice(before);
}

describe('漏えい：返信の中継（plan 11章 テスト5）', () => {
  it('本物のアドレスから DMARC が pass した返信だけを、返信用のアドレスから、署名された Reply-To へ届ける', async () => {
    // 攻撃者が持っている情報：なし（正規の経路の確認。企業が受け取るものに、本物のアドレスがないことを見る）
    // 試す経路：企業から届いたメールに、利用者が本物のアドレスから返信する（利用者のドメインで DKIM の署名あり）
    // 期待する結果：250。企業の Reply-To（署名されたもの）に1通届く。From は返信用のアドレス、
    //               X-Warifu-Unauthenticated: 1 が付き、Received、X-Mailer、利用者の DKIM は消える。
    //               本物のアドレスと、そのドメインは、メールのどこにもない。本文はバイト単位で同じ。
    //               企業の側の受信の検証で、relay のドメインの DKIM と DMARC が pass する
    // plan 11章：テスト5（X-Warifu-Unauthenticated、本物のアドレスが入らない）
    const { thread, messageId } = await openThread();
    const raw = await reply({
      from: user.email,
      to: thread,
      inReplyTo: messageId,
      signer: userDomain,
    });
    const before = t.outbound.all().length;
    const { rcpt, data } = await send(user.email, thread, raw);
    expect(rcpt.code).toBe(250);
    expect(data?.code).toBe(250);
    const got = t.outbound.all().slice(before);
    expect(got.map((m) => m.rcptTo)).toEqual([`support@${company.senderDomain}`]);
    const relayed = got[0];
    if (relayed === undefined) throw new Error('届いていない');
    expect(named(relayed.raw, 'from')).toEqual([`<${thread}>`]);
    expect(named(relayed.raw, 'to')).toEqual([`<support@${company.senderDomain}>`]);
    expect(named(relayed.raw, 'x-warifu-unauthenticated')).toEqual(['1']);
    expect(named(relayed.raw, 'in-reply-to')).toEqual([messageId]);
    expect(named(relayed.raw, 'message-id')[0]).toMatch(
      new RegExp(`^<[a-z2-7]{26}@${company.relayDomain.replaceAll('.', '\\.')}>$`),
    );
    for (const key of ['received', 'x-mailer']) expect(named(relayed.raw, key), key).toEqual([]);
    expect(relayed.mailFrom).toBe(`bounces@${company.relayDomain}`);
    const text = relayed.raw.toString('latin1').toLowerCase();
    expect(text).not.toContain(user.email.toLowerCase());
    expect(text).not.toContain(userDomain.domain);
    expect(text).not.toContain('198.51.100.7');
    expect(parseMessage(relayed.raw).body.equals(parseMessage(raw).body)).toBe(true);

    const result = await authenticate(relayed.raw, {
      ip: '192.0.2.25',
      helo: 'mx.relay.warifu.test',
      mta: `mx.${company.senderDomain}`,
      sender: relayed.mailFrom,
      resolver: t.dns(),
      disableBimi: true,
    } as Parameters<typeof authenticate>[1]);
    expect(result.dkim.results.map((r) => [r.signingDomain, r.status.result])).toEqual([
      [company.relayDomain, 'pass'],
    ]);
    expect((result.dmarc || undefined)?.status.result).toBe('pass');
  });

  it.each([
    ['署名のない、From を詐称した返信', () => ({ signer: undefined, from: user.email })],
    [
      '攻撃者のドメインで署名した、From を詐称した返信（DMARC が整合しない）',
      () => ({ signer: attackerDomain, from: user.email }),
    ],
    [
      '攻撃者自身のアドレスからの、DMARC が pass する返信（From が本物のアドレスでない）',
      () => ({ signer: attackerDomain, from: `a@${attackerDomain.domain}` }),
    ],
  ])('%s は、250 で受けて、企業にも利用者にも届けない', async (_, make) => {
    // 攻撃者が持っている情報：利用者の本物のアドレス（漏えいから）と、企業から利用者へのメールに載った返信用のアドレス
    //                         （利用者の受信箱か、転送の途中から得たもの）
    // 試す経路：返信用のアドレスへ、利用者を名乗る返信を送り、企業に「本人からの依頼」と見せかける
    // 期待する結果：DATA は 250（返信用のアドレスへの応答は一律）。企業には何も届かない。差し戻しの知らせも出ない
    // plan 11章：テスト5（From を詐称した返信は中継されない）
    const { thread, messageId } = await openThread();
    const { signer, from } = make();
    const raw = await reply({
      from,
      to: thread,
      inReplyTo: messageId,
      ...(signer === undefined ? {} : { signer }),
    });
    const before = t.outbound.all().length;
    const { rcpt, data } = await send(from, thread, raw);
    expect(rcpt.code).toBe(250);
    expect(data?.code).toBe(250);
    expect(t.outbound.all()).toHaveLength(before);
  });

  it('本文に本物のアドレスを含む返信は、企業へ送らず、利用者に差し戻す', async () => {
    // 攻撃者が持っている情報：なし（利用者が署名欄などで本物のアドレスを書いてしまう場面）
    // 試す経路：本文の末尾に本物のアドレスを書いた返信を、本物のアドレスから送る（quoted-printable でも同じ）
    // 期待する結果：企業には届かない。本物のアドレスに、割符の固定の知らせが1通届く（操作のリンクなし）
    // plan 11章：テスト5（本文に本物のアドレスがあれば差し戻す。plan 3-2）
    const { thread, messageId } = await openThread();
    const raw = await reply({
      from: user.email,
      to: thread,
      inReplyTo: messageId,
      body: `よろしくお願いします。\r\n-- \r\n${user.email.toUpperCase()}\r\n`,
      signer: userDomain,
    });
    const before = t.outbound.all().length;
    expect((await send(user.email, thread, raw)).data?.code).toBe(250);
    const got = t.outbound.all().slice(before);
    expect(got.map((m) => m.rcptTo)).toEqual([user.email]);
    const notice = got[0];
    if (notice === undefined) throw new Error('知らせがない');
    expect(named(notice.raw, 'from')[0]).toContain(`<notices@${NOTICE_DOMAIN}>`);
    const body = Buffer.from(
      parseMessage(notice.raw).body.toString('latin1').replace(/\s+/g, ''),
      'base64',
    ).toString('utf8');
    expect(body).not.toMatch(/https?:\/\//);
    expect(body).not.toContain(company.senderDomain);
  });

  it.each([
    [
      'HTML の数値文字参照（&#64;）',
      () => multipart('alternative', [plainPart(), htmlPart(`<p>${local()}&#64;${domain()}</p>`)]),
    ],
    [
      'HTML の16進の文字参照（&#x40;）',
      () => multipart('alternative', [plainPart(), htmlPart(`<p>${local()}&#x40;${domain()}</p>`)]),
    ],
    [
      'HTML の名前の文字参照（&commat; と &period;）',
      () =>
        multipart('alternative', [
          plainPart(),
          htmlPart(`<p>${local()}&commat;${domain().replaceAll('.', '&period;')}</p>`),
        ]),
    ],
    [
      'HTML のタグで区切ったもの',
      () =>
        multipart('alternative', [
          plainPart(),
          htmlPart(`<p>${local()}<span>@</span>${domain()}</p>`),
        ]),
    ],
    [
      'mailto: の %40',
      () =>
        multipart('alternative', [
          plainPart(),
          htmlPart(`<a href="mailto:${local()}%40${domain()}">連絡先</a>`),
        ]),
    ],
    [
      'quoted-printable の HTML の文字参照',
      () =>
        multipart('alternative', [
          plainPart(),
          [
            'Content-Type: text/html; charset=utf-8',
            'Content-Transfer-Encoding: quoted-printable',
            '',
            `<p>${local()}=26#64;${domain()}</p>`,
          ],
        ]),
    ],
    ['全角で書いたもの', () => ({ body: `連絡先：${fullwidth(user.email)}\r\n` })],
    ['ゼロ幅の空白を挟んだもの', () => ({ body: `連絡先：${local()}​@​${domain()}\r\n` })],
    [
      'ISO-2022-JP の全角を base64 にしたもの',
      () => ({
        contentHeaders: [
          'Content-Type: text/plain; charset=ISO-2022-JP',
          'Content-Transfer-Encoding: base64',
        ],
        body: base64Lines(iso2022jpFullwidth(user.email)),
      }),
    ],
    ['件名にそのまま書いたもの', () => ({ subject: `Re: ${user.email}` })],
    [
      '件名の encoded-word（B）',
      () => ({ subject: `Re: =?UTF-8?B?${Buffer.from(user.email).toString('base64')}?=` }),
    ],
    ['件名の encoded-word（Q）', () => ({ subject: `Re: =?UTF-8?Q?${local()}=40${domain()}?=` })],
    [
      '転送したメール（message/rfc822）の From',
      () =>
        multipart('mixed', [
          plainPart('前のメールを転送します。'),
          [
            'Content-Type: message/rfc822',
            '',
            `From: <${user.email}>`,
            'Subject: old',
            '',
            '前のメールです。',
          ],
        ]),
    ],
    [
      '部分のファイル名（RFC 2231 の %40）',
      () =>
        multipart('mixed', [
          [
            'Content-Type: text/plain; charset=utf-8',
            `Content-Disposition: inline; filename*=utf-8''${local()}%40${domain()}.txt`,
            '',
            'メモです。',
          ],
        ]),
    ],
  ])(
    '件名か本文に本物のアドレスがある返信（%s）は、企業へ送らず、利用者に差し戻す',
    async (_, shape) => {
      // 攻撃者が持っている情報：企業として受け取る返信（企業が侵害された場面）
      // 試す経路：利用者が、件名、HTML の本文、添付した文字の部分、転送したメールに、本物のアドレスを
      //           文字参照、タグ、%xx、全角、ゼロ幅の文字、ISO-2022-JP、encoded-word で書いて返信する
      // 期待する結果：企業には何も届かない。本物のアドレスに、差し戻しの知らせ（リンクなし）が1通だけ届く
      // plan 11章：テスト5（中継された返信に、本物のアドレスが入らない）
      const sent = await sendShapedReply(shape());
      expect(sent.map((m) => m.rcptTo)).toEqual([user.email]);
      const notice = sent[0];
      if (notice === undefined) throw new Error('知らせがない');
      const body = Buffer.from(
        parseMessage(notice.raw).body.toString('latin1').replace(/\s+/g, ''),
        'base64',
      ).toString('utf8');
      expect(body).toContain('メールアドレスが含まれていた');
      expect(body).not.toMatch(/https?:\/\//);
    },
  );

  it.each([
    [
      'PDF の添付ファイル',
      () =>
        multipart('mixed', [
          plainPart(),
          [
            'Content-Type: application/pdf; name="a.pdf"',
            'Content-Transfer-Encoding: base64',
            '',
            base64Lines(randomBytes(64)),
          ],
        ]),
    ],
    [
      '本文に埋め込んだ画像',
      () =>
        multipart('related', [
          htmlPart('<p>写真です。</p><img src="cid:p1">'),
          [
            'Content-Type: image/png',
            'Content-ID: <p1>',
            'Content-Transfer-Encoding: base64',
            '',
            base64Lines(randomBytes(64)),
          ],
        ]),
    ],
    [
      'HTML の data: URI の画像',
      () =>
        multipart('alternative', [
          plainPart(),
          htmlPart('<img src="data:image/png;base64,iVBORw0KGgo=">'),
        ]),
    ],
    [
      '知らない文字コード',
      () => ({ contentHeaders: ['Content-Type: text/plain; charset=x-unknown-charset'] }),
    ],
    [
      '知らない転送符号化',
      () => ({
        contentHeaders: [
          'Content-Type: text/plain; charset=utf-8',
          'Content-Transfer-Encoding: x-uuencode',
        ],
      }),
    ],
    [
      '境界のない multipart',
      () => ({ contentHeaders: ['Content-Type: multipart/mixed'], body: 'x\r\n' }),
    ],
    [
      '終わりの境界がない multipart（最後の部分に base64 の本物のアドレス）',
      () => {
        const boundary = `b${randomBytes(6).toString('hex')}`;
        return {
          contentHeaders: [`Content-Type: multipart/mixed; boundary="${boundary}"`],
          body: [
            `--${boundary}`,
            ...plainPart(),
            `--${boundary}`,
            'Content-Type: text/plain; charset=utf-8',
            'Content-Transfer-Encoding: base64',
            '',
            base64Lines(Buffer.from(`連絡先：${user.email}`)),
          ].join('\r\n'),
        };
      },
    ],
    [
      '文字の添付ファイル（attachment）',
      () =>
        multipart('mixed', [
          plainPart(),
          [
            'Content-Type: text/plain; charset=utf-8',
            'Content-Disposition: attachment; filename="memo.txt"',
            '',
            'メモです。',
          ],
        ]),
    ],
    [
      '件名の知らない文字コードの encoded-word',
      () => ({ subject: 'Re: =?x-unknown-charset?B?YWJj?=' }),
    ],
  ])(
    '中身を確かめられない部分を含む返信（%s）は、企業へ送らず、利用者に差し戻す',
    async (_, shape) => {
      // 攻撃者が持っている情報：企業として受け取る返信（企業が侵害された場面）
      // 試す経路：利用者が、添付ファイル、画像、知らない文字コードや転送符号化を含む返信を送る
      //           （その中に本物のアドレスがあっても、relay は確かめられない）
      // 期待する結果：企業には何も届かない。本物のアドレスに、確かめられない形式だったことの知らせが1通だけ届く
      // plan 11章：テスト5（中継された返信に、本物のアドレスが入らない。ADR 0021）
      const sent = await sendShapedReply(shape());
      expect(sent.map((m) => m.rcptTo)).toEqual([user.email]);
      const notice = sent[0];
      if (notice === undefined) throw new Error('知らせがない');
      const body = Buffer.from(
        parseMessage(notice.raw).body.toString('latin1').replace(/\s+/g, ''),
        'base64',
      ).toString('utf8');
      expect(body).toContain('中身を確かめられない部分');
    },
  );

  it('文字だけの multipart の返信（HTML と ISO-2022-JP を含む）は、そのまま企業へ届く', async () => {
    // 攻撃者が持っている情報：なし（検査が、本物のアドレスのない普通の返信を止めないことの確認）
    // 試す経路：text/plain（ISO-2022-JP）と text/html（文字参照、リンク、「metadata:」の文字）の multipart/alternative を返信する
    // 期待する結果：企業の Reply-To に1通届き、本文はバイト単位で同じ
    // plan 11章：テスト5（転送した本文はバイト単位で同じ）
    const shape = multipart('alternative', [
      [
        'Content-Type: text/plain; charset=ISO-2022-JP',
        'Content-Transfer-Encoding: 7bit',
        '',
        Buffer.from([
          0x1b, 0x24, 0x42, 0x4f, 0x22, 0x4d, 0x6d, 0x40, 0x68, 0x1b, 0x28, 0x42,
        ]).toString('latin1'),
      ],
      htmlPart(
        '<p>R&amp;D の件です。metadata: なし。<a href="https://company.example/faq">FAQ</a></p>',
      ),
    ]);
    const sent = await sendShapedReply(shape);
    expect(sent.map((m) => m.rcptTo)).toEqual([`support@${company.senderDomain}`]);
  });

  it('署名の外で足した Reply-To には、返信を向けない（署名された From に向ける）', async () => {
    // 攻撃者が持っている情報：企業から利用者へのメールを途中で書き換えられる位置（転送の途中）
    // 試す経路：企業の署名の h= に Reply-To がないメールに、攻撃者のアドレスの Reply-To を足して、別名に届ける。
    //           利用者がそれに返信する
    // 期待する結果：返信は、企業の署名した From（info@）に届き、攻撃者のアドレスには届かない
    // plan 11章：テスト5（plan 3-2 の返信の中継）
    const { thread, messageId } = await openThread({
      extraHeaders: [`Reply-To: <a@${attackerDomain.domain}>`],
      headerList: 'From:From:To:To:Subject:Subject:Date:Message-ID',
    });
    const raw = await reply({
      from: user.email,
      to: thread,
      inReplyTo: messageId,
      signer: userDomain,
    });
    const before = t.outbound.all().length;
    await send(user.email, thread, raw);
    expect(
      t.outbound
        .all()
        .slice(before)
        .map((m) => m.rcptTo),
    ).toEqual([`info@${company.senderDomain}`]);
  });

  it('References と In-Reply-To から、本物のアドレスのドメインの Message-ID を消す', async () => {
    // 攻撃者が持っている情報：企業として受け取る返信（企業が侵害された場面）
    // 試す経路：利用者が自分の送ったメールにも返信し、References に利用者のドメインの Message-ID が並ぶ
    // 期待する結果：企業に届く References には、企業と relay の Message-ID だけが残る
    // plan 11章：テスト5（本物のアドレスが入らない）
    const { thread, messageId } = await openThread();
    const own = `<${randomUUID()}@mail.${userDomain.domain}>`;
    const raw = await reply({
      from: user.email,
      to: thread,
      inReplyTo: own,
      references: `${messageId} ${own} <${randomUUID()}@${userDomain.domain}>`,
      signer: userDomain,
    });
    const before = t.outbound.all().length;
    await send(user.email, thread, raw);
    const relayed = t.outbound.all().slice(before)[0];
    if (relayed === undefined) throw new Error('届いていない');
    expect(named(relayed.raw, 'references')).toEqual([messageId]);
    expect(named(relayed.raw, 'in-reply-to')).toEqual([]);
    expect(relayed.raw.toString('latin1').toLowerCase()).not.toContain(userDomain.domain);
  });

  it('返信用のアドレスは、別のテナントのドメインでは使えず、期限が切れたら使えない', async () => {
    // 攻撃者が持っている情報：A社のやり取りの返信用のアドレス（B社も relay を使っていることを知っている）
    // 試す経路：同じローカル部を B社の relay のドメインに付けて送る。また、期限（30日）の後に送る
    // 期待する結果：どちらも 250 で受けて、どこにも届けない
    // plan 11章：テスト5、テスト4（テナントをまたいで使えない）
    const { thread, messageId } = await openThread();
    const crossTenant = `${thread.split('@')[0]}@${other.relayDomain}`;
    const before = t.outbound.all().length;
    const raw = await reply({
      from: user.email,
      to: crossTenant,
      inReplyTo: messageId,
      signer: userDomain,
    });
    expect((await send(user.email, crossTenant, raw)).data?.code).toBe(250);
    expect(t.outbound.all()).toHaveLength(before);

    clockOffset = 31 * 24 * 60 * 60 * 1000;
    try {
      const late = await reply({
        from: user.email,
        to: thread,
        inReplyTo: messageId,
        signer: userDomain,
      });
      expect((await send(user.email, thread, late)).data?.code).toBe(250);
      expect(t.outbound.all()).toHaveLength(before);
    } finally {
      clockOffset = 0;
    }
  });

  it('企業から返信用のアドレスへのメールは、送信元ロックを通れば利用者に届き、通らなければ届かない', async () => {
    // 攻撃者が持っている情報：返信用のアドレス
    // 試す経路：企業を名乗る、署名のないメールを返信用のアドレスに送る。続いて、企業が正しく署名したメールを送る
    // 期待する結果：どちらも 250。署名のないものは、どこにも届かない。署名したものだけが、本物のアドレスに届く
    // plan 11章：テスト5（送信元ロック）
    const { thread } = await openThread();
    const before = t.outbound.all().length;
    const unsigned = Buffer.from(companyMail(company, thread));
    expect((await send(`bounce@${company.senderDomain}`, thread, unsigned)).data?.code).toBe(250);
    expect(t.outbound.all()).toHaveLength(before);
    const signed = await signCompanyMail(company, companyMail(company, thread));
    expect((await send(`bounce@${company.senderDomain}`, thread, signed)).data?.code).toBe(250);
    expect(
      t.outbound
        .all()
        .slice(before)
        .map((m) => m.rcptTo),
    ).toEqual([user.email]);
  });
});

describe('返信の検証に使う DNS がないとき', () => {
  it('利用者からの返信を中継しない（確かめられないものは通さない）', async () => {
    // 攻撃者が持っている情報：利用者の本物のアドレスと、返信用のアドレス
    // 試す経路：DNS のリゾルバを渡していない relay（M5 で送信サービスにつなぐまでの構成）に、正しい返信を送る
    // 期待する結果：250 で受けて、企業には届けない
    // plan 11章：テスト5（ADR 0021）
    const bare = await startTestRelay();
    try {
      const someone = await addUser(
        bare.companies,
        `v${randomBytes(6).toString('hex')}@${userDomain.domain}`,
      );
      const [c] = bare.companies;
      const [a] = someone.aliases;
      if (c === undefined || a === undefined) throw new Error('準備に失敗した');
      await sendMail(
        bare.relay.smtpPort,
        { from: `bounce@${c.senderDomain}`, to: a },
        await signCompanyMail(c, companyMail(c, a)),
      );
      await bare.relay.idle();
      const first = bare.outbound.all()[0];
      const thread =
        first === undefined ? undefined : named(first.raw, 'from')[0]?.match(/<([^<>]+)>/)?.[1];
      if (thread === undefined) throw new Error('返信用のアドレスがない');
      const raw = await reply({
        from: someone.email,
        to: thread,
        inReplyTo: '<x@y.example>',
        signer: userDomain,
      });
      const result = await sendMail(bare.relay.smtpPort, { from: someone.email, to: thread }, raw);
      await bare.relay.idle();
      expect(result.data?.code).toBe(250);
      expect(bare.outbound.all()).toHaveLength(1);
    } finally {
      await bare.stop();
    }
  });
});
