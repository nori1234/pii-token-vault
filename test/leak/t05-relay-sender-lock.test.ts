// 送信元ロック（plan 3-2、plan 11章 テスト5、ADR 0021）。
// 企業から別名あてのメールは、登録した (d=, s=, 公開鍵) の DKIM で署名され、送信元ロックの条件を満たすものだけを届ける。

import { generateKeyPairSync } from 'node:crypto';
import { authenticate } from 'mailauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addUser,
  companyMail,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestRelay,
  type TestUser,
} from '../setup/relay.ts';

let t: TestRelay;
let user: TestUser;

beforeAll(async () => {
  t = await startTestRelay({ companies: 2 });
  user = await addUser(t.companies);
});

afterAll(async () => {
  await t.stop();
});

function company(i = 0) {
  const c = t.companies[i];
  if (c === undefined) throw new Error('企業がない');
  return c;
}

function alias(i = 0) {
  const a = user.aliases[i];
  if (a === undefined) throw new Error('別名がない');
  return a;
}

async function deliver(raw: Buffer, to = alias(), from = `bounce@${company().senderDomain}`) {
  const result = await sendMail(t.relay.smtpPort, { from, to }, raw);
  await t.relay.idle();
  return result;
}

function deliveredTo(address: string) {
  return t.outbound.all().filter((m) => m.rcptTo === address);
}

describe('漏えい：送信元ロック（plan 11章 テスト5）', () => {
  it('登録した鍵で正しく署名されたメールは、利用者の本物のアドレスに届き、受信側で DKIM・ARC・DMARC が pass する', async () => {
    // 攻撃者が持っている情報：なし（正規の経路の確認）
    // 試す経路：A社が、登録した鍵で署名したメールを、利用者のA社用の別名に送る
    // 期待する結果：250。本物のアドレスに1通届く。受信側（mailauth で模擬）で、relay のドメインの DKIM、ARC、
    //               DMARC（p=reject）が pass する（plan 11章テスト5「p=reject の送信元」の記録）
    // plan 11章：テスト5
    const before = deliveredTo(user.email).length;
    const raw = await signCompanyMail(company(), companyMail(company(), alias()));
    const { rcpt, data } = await deliver(raw);
    expect(rcpt.code).toBe(250);
    expect(data?.code).toBe(250);
    const got = deliveredTo(user.email);
    expect(got).toHaveLength(before + 1);
    const message = got.at(-1);
    if (message === undefined) throw new Error('届いていない');
    const result = await authenticate(message.raw, {
      ip: '192.0.2.25',
      helo: 'mx.relay.warifu.test',
      mta: 'mx.users.example',
      sender: message.mailFrom,
      resolver: t.dns(),
      disableBimi: true,
    } as Parameters<typeof authenticate>[1]);
    expect(result.dkim.results.find((r) => r.status.result === 'pass')?.signingDomain).toBe(
      company().relayDomain,
    );
    expect((result.arc || undefined)?.status.result).toBe('pass');
    expect((result.dmarc || undefined)?.status.result).toBe('pass');
  });

  it.each([
    ['署名なし', 'no_valid_signature', async () => Buffer.from(companyMail(company(), alias()))],
    [
      'd= が登録と違う',
      'no_valid_signature',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          signingDomain: `other.${company().senderDomain}`,
        }),
    ],
    [
      '登録していない鍵',
      'no_valid_signature',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          key: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey,
        }),
    ],
    [
      'l= 付き',
      'no_valid_signature',
      async () => signCompanyMail(company(), companyMail(company(), alias()), { maxBodyLength: 4 }),
    ],
    [
      'From を重ねて署名していない',
      'no_valid_signature',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          headerList: 'From:To:To:Subject:Subject:Date:Message-ID',
        }),
    ],
    [
      'h= に Date がない',
      'no_valid_signature',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          headerList: 'From:From:To:To:Subject:Subject:Message-ID',
        }),
    ],
    [
      'From が2つ',
      'header_count',
      async () =>
        signCompanyMail(
          company(),
          companyMail(company(), alias(), [`From: <evil@${company().senderDomain}>`]),
        ),
    ],
    [
      'To が2つ',
      'header_count',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias(), [`To: <${alias(1)}>`])),
    ],
    [
      'Subject が2つ',
      'header_count',
      async () => signCompanyMail(company(), companyMail(company(), alias(), ['Subject: second'])),
    ],
    [
      'From のドメインが d= と整合しない',
      'from_not_aligned',
      async () =>
        signCompanyMail(
          company(),
          companyMail(company(), alias()).replace(/^From: .*$/m, 'From: <info@unrelated.example>'),
        ),
    ],
    [
      '別の企業の鍵（B社の鍵でA社の別名に送る）',
      'no_valid_signature',
      async () =>
        signCompanyMail(company(1), companyMail(company(1), alias(0)), {
          signingDomain: company(1).senderDomain,
        }),
    ],
    [
      '署名が古すぎる（t= が8日前）',
      'signature_time',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          signTime: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
        }),
    ],
    [
      '署名の時刻が未来（t= が1時間後）',
      'signature_time',
      async () =>
        signCompanyMail(company(), companyMail(company(), alias()), {
          signTime: new Date(Date.now() + 60 * 60 * 1000),
        }),
    ],
  ])('%s のメールは 550 で拒否し、届けない（理由：%s）', async (_, reason, build) => {
    // 攻撃者が持っている情報：漏れた別名（企業から）と、企業を名乗るメールを作る手段（登録した鍵は持たない。
    //                         または、企業の鍵で署名させられるが、条件を外したもの）
    // 試す経路：送信元ロックの条件を1つずつ外したメールを、別名に送る
    // 期待する結果：DATA に 550。本物のアドレスには何も届かない。ログには理由の種類だけが残る
    // plan 11章：テスト5
    const before = t.outbound.all().length;
    const logged = t.logs.length;
    const { rcpt, data } = await deliver(await build());
    expect(rcpt.code).toBe(250);
    expect(data?.code).toBe(550);
    expect(t.outbound.all()).toHaveLength(before);
    const events = t.logs.slice(logged).map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      events.filter((e) => e.event === 'relay.sender_lock_failed').map((e) => e.reason),
    ).toEqual([reason]);
  });

  it('同じメールの再送（リプレイ）は 250 で受けて、届けない', async () => {
    // 攻撃者が持っている情報：企業が正しく署名したメール1通（受信箱や途中の経路から得たもの）
    // 試す経路：同じメールを、同じ別名にもう一度送る
    // 期待する結果：1回目だけ届く。2回目は 250 で受けて捨てる（送信元の再試行と区別できないため）
    // plan 11章：テスト5
    const raw = await signCompanyMail(company(), companyMail(company(), alias()));
    const before = deliveredTo(user.email).length;
    expect((await deliver(raw)).data?.code).toBe(250);
    expect((await deliver(raw)).data?.code).toBe(250);
    expect(deliveredTo(user.email)).toHaveLength(before + 1);
  });

  it('知らない別名あての正しいメールは、同じ 250 を返して、どこにも届けない', async () => {
    // 攻撃者が持っている情報：企業の正規の送信の経路（企業の中の者）と、推測した別名
    // 試す経路：存在しない別名あてに、正しく署名したメールを送る
    // 期待する結果：250（生きている別名と同じ）。何も届かない
    // plan 11章：テスト5、テスト10
    const fake = `${'a'.repeat(16)}@${company().relayDomain}`;
    const before = t.outbound.all().length;
    const raw = await signCompanyMail(company(), companyMail(company(), fake));
    const { rcpt, data } = await deliver(raw, fake);
    expect(rcpt.code).toBe(250);
    expect(data?.code).toBe(250);
    expect(t.outbound.all()).toHaveLength(before);
  });
});
