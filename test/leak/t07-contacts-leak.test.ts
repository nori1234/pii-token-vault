// テスト7（plan 11章）：本物のアドレス、別名、返信用のアドレス、ID トークンとアクセストークン、Message-ID、件名と本文を、
// 割符の DB（pg_dump。全サービスのスキーマ）とログと配送ログに残さない（不変条件4、ADR 0005、ADR 0021）。
// idp（宛先確認のメールは relay の内部配送 API を通す）と relay を立て、登録、宛先確認、企業への接続、企業から別名への
// 配送、利用者からの返信の中継を通した後で、DB を丸ごと取り出し、ログと合わせて、値の形を変えて探す。

import { createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { dkimSign } from 'mailauth/lib/dkim/sign.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RelayMailer } from '../../packages/idp/src/mailer.ts';
import { parseMessage } from '../../packages/relay/src/mime.ts';
import { userIdOf } from '../setup/approvals.ts';
import { dumpWorkerDatabase, formsOf, leaksIn, MIN_FORM_LENGTH } from '../setup/dump.ts';
import { Browser, codeFlow, startTestIdp, type TestIdp } from '../setup/idp.ts';
import {
  addUser,
  companyMail,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestRelay,
} from '../setup/relay.ts';

/** 利用者のメールのドメイン（返信の DKIM と DMARC を通すための鍵と DNS の記録）。 */
const userDomain = {
  domain: `users${randomBytes(4).toString('hex')}.example`,
  selector: 'mua',
  key: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey,
};

let relay: TestRelay;
let idp: TestIdp;

beforeAll(async () => {
  const spki = createPublicKey(userDomain.key)
    .export({ type: 'spki', format: 'der' })
    .toString('base64');
  relay = await startTestRelay({
    replyDns: {
      [`TXT:${userDomain.selector}._domainkey.${userDomain.domain}`]: `v=DKIM1; k=rsa; p=${spki}`,
      [`TXT:_dmarc.${userDomain.domain}`]: 'v=DMARC1; p=reject',
    },
  });
  idp = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, undefined, {
    mailer: new RelayMailer({
      socketPath: relay.relay.socketPath,
      credential: relay.idpCredential,
    }),
  });
});

afterAll(async () => {
  await idp?.stop();
  await relay?.stop();
});

/** ヘッダーの値（折り返しを戻したもの）。 */
function headerOf(raw: Buffer, key: string): string {
  const found = parseMessage(raw).headers.find((h) => h.key === key);
  if (found === undefined) throw new Error('ヘッダーがない');
  const text = found.line.toString('latin1').replace(/\r\n[ \t]+/g, ' ');
  return text.slice(text.indexOf(':') + 1).trim();
}

/** 山かっこの中のアドレスか Message-ID。 */
function bracketed(value: string): string {
  const match = value.match(/<([^>]+)>/);
  if (match?.[1] === undefined) throw new Error('山かっこがない');
  return match[1];
}

describe('テスト7：連絡先、別名、トークン、Message-ID、件名と本文を、DB とログに残さない', () => {
  it('検索の補助は、値を、そのまま・大文字と小文字の違い・16進・base64・base64url・URL の符号化のどれでも見つける', () => {
    // 攻撃者が持っている情報：なし（検査の道具そのものの確かめ。下のテストが、探し方の誤りで空振りしないように）
    // 試す経路：値を、それぞれの形に変えて埋め込んだテキストを、leaksIn に渡す
    // 期待する結果：どの形も見つかり、値の番号と場所だけが返る。短い値は、そのままの形を探さず、長い形（16進など）は探す
    // plan 11章：テスト7
    const value = `Secret.${randomBytes(8).toString('hex')}@users.example`;
    const bytes = Buffer.from(value, 'utf8');
    for (const text of [
      value,
      value.toUpperCase(),
      `\\x${bytes.toString('hex')}`,
      bytes.toString('base64'),
      bytes.toString('base64url'),
      encodeURIComponent(value),
    ]) {
      expect(leaksIn({ text: `head ${text} tail` }, [value])).toEqual(['0:text']);
    }
    expect(leaksIn({ text: 'head tail' }, [value])).toEqual([]);
    // 8桁の確認コードのような短い値は、そのままの形では探さない（大きな DB では、たまたま現れる）。
    const short = '12345678';
    expect(formsOf(short)).not.toContain(short);
    expect(formsOf(short).every((form) => form.length >= MIN_FORM_LENGTH)).toBe(true);
    expect(leaksIn({ text: `\\x${Buffer.from(short).toString('hex')}` }, [short])).toEqual([
      '0:text',
    ]);
  });

  it('登録、宛先確認、企業への接続、配送、返信の中継の後に、DB を丸ごと取り出しても、ログにも、値がない', async () => {
    // 攻撃者が持っている情報：割符の DB を丸ごと読める立場（pg_dump、ATK-06）と、idp と relay のログを読める立場
    // 試す経路：(1) idp でアカウントを作り、本物のアドレスを登録して確かめる（確認コードは、relay が本物のアドレスへ
    //           送る）。(2) 企業に接続し、ID トークン（email クレームは別名）とアクセストークンを受け取る。(3) 企業が
    //           別名へメールを送り、relay が本物のアドレスへ届ける。(4) 利用者が返信用のアドレスへ返信し、relay が企業へ
    //           届ける。その後で、DB を丸ごと取り出し、ログと合わせて、値の形を変えて探す
    // 期待する結果：どの値も、DB にもログにも出ない（暗号文と、照合用の MAC だけが残る）
    // plan 11章：テスト7
    const needles: string[] = [];

    // (1) 登録と宛先確認。
    const browser = new Browser(idp.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const address = `c${randomBytes(6).toString('hex')}@${userDomain.domain}`;
    needles.push(address);
    expect((await browser.post('/api/email/start', { email: address })).status).toBe(202);
    const notice = relay.outbound.lastTo(address);
    if (notice === undefined) throw new Error('確認コードが届いていない');
    const text = Buffer.from(
      parseMessage(notice.raw).body.toString('latin1').replace(/\s+/g, ''),
      'base64',
    ).toString('utf8');
    const match = text.match(/確認コード：([0-9]{4}) ([0-9]{4})/);
    if (match === null) throw new Error('確認コードがない');
    const code = `${match[1]}${match[2]}`;
    needles.push(code, `${match[1]} ${match[2]}`, bracketed(headerOf(notice.raw, 'message-id')));
    expect((await browser.post('/api/email/confirm', { code })).status).toBe(200);

    // (2) 企業への接続。ID トークンの email クレームは、企業ごとの別名。
    const client = idp.clients[0];
    const tenant = idp.tenants[0];
    if (client === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const flow = await codeFlow(idp, browser, client, { mode: 'session' });
    const alias = String(flow.claims.email);
    expect(alias.endsWith(`@${tenant.relayDomain}`)).toBe(true);
    needles.push(alias, alias.split('@')[0] ?? '', flow.idToken);
    for (const key of ['access_token', 'refresh_token'] as const) {
      const token = flow.tokenResponse[key];
      if (typeof token === 'string') needles.push(token);
    }

    // (3) 企業から別名への配送（relay の利用者は、idp と同じ境界で作る）。
    const user = await addUser(
      relay.companies,
      `u${randomBytes(6).toString('hex')}@${userDomain.domain}`,
    );
    const [company] = relay.companies;
    const [toAlias] = user.aliases;
    if (company === undefined || toAlias === undefined) throw new Error('準備に失敗した');
    needles.push(user.email, toAlias, toAlias.split('@')[0] ?? '');
    const bodyMarker = `本文の目印-${randomBytes(8).toString('hex')}`;
    const original = companyMail(
      company,
      toAlias,
      [`Reply-To: <support@${company.senderDomain}>`],
      `${bodyMarker}\r\n`,
    );
    needles.push(bodyMarker, bracketed(headerOf(Buffer.from(original), 'message-id')));
    const sent = await sendMail(
      relay.relay.smtpPort,
      { from: `bounce@${company.senderDomain}`, to: toAlias },
      await signCompanyMail(company, original),
    );
    await relay.relay.idle();
    expect(sent.data?.code).toBe(250);
    const delivered = relay.outbound.lastTo(user.email);
    if (delivered === undefined) throw new Error('利用者に届いていない');
    const thread = bracketed(headerOf(delivered.raw, 'from'));
    const deliveredId = headerOf(delivered.raw, 'message-id');
    needles.push(thread, thread.split('@')[0] ?? '', bracketed(deliveredId));

    // (4) 利用者からの返信（本物のアドレスから、返信用のアドレスへ。利用者のドメインの DKIM で署名する）。
    const subjectMarker = `件名の目印-${randomBytes(8).toString('hex')}`;
    const replyBody = `返信の目印-${randomBytes(8).toString('hex')}`;
    const replyId = `${randomUUID()}@${userDomain.domain}`;
    needles.push(subjectMarker, replyBody, replyId);
    const unsigned = Buffer.from(
      [
        `From: <${user.email}>`,
        `To: <${thread}>`,
        `Subject: Re: ${subjectMarker}`,
        `Date: ${new Date().toUTCString()}`,
        `Message-ID: <${replyId}>`,
        `In-Reply-To: ${deliveredId}`,
        `References: ${deliveredId}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        '',
        `${replyBody}\r\n`,
      ].join('\r\n'),
    );
    const signed = await dkimSign(unsigned, {
      canonicalization: 'relaxed/relaxed',
      signatureData: [
        {
          signingDomain: userDomain.domain,
          selector: userDomain.selector,
          privateKey: userDomain.key.export({ type: 'pkcs8', format: 'pem' }).toString(),
          headerList: 'From:To:Subject:Date:Message-ID:In-Reply-To:References',
        },
      ],
    });
    const before = relay.outbound.all().length;
    const replied = await sendMail(
      relay.relay.smtpPort,
      { from: user.email, to: thread },
      Buffer.concat([Buffer.from(signed.signatures), unsigned]),
    );
    await relay.relay.idle();
    expect(replied.data?.code).toBe(250);
    const forwarded = relay.outbound.all().slice(before);
    expect(forwarded.map((m) => m.rcptTo)).toEqual([`support@${company.senderDomain}`]);
    const [reply] = forwarded;
    if (reply === undefined) throw new Error('企業に届いていない');
    needles.push(bracketed(headerOf(reply.raw, 'message-id')));

    // DB を丸ごと取り出したものと、ログ。
    const dump = await dumpWorkerDatabase();
    const logs = { idp: idp.logLines().join('\n'), relay: relay.logs.join('\n') };
    // 取り出したものとログが、この流れの行を実際に含んでいることを先に確かめる（空振りで通らないように）。
    // 利用者 ID は秘密ではなく、平文で残る。配送ログと、返信の中継の表は、行がある。
    expect(leaksIn({ dump }, [userIdOf(browser.authenticator), user.userId])).toEqual([
      '0:dump',
      '1:dump',
    ]);
    for (const table of ['relay.delivery_log', 'relay.threads', 'contacts.email']) {
      expect(dump).toMatch(
        new RegExp(`COPY ${table.replace('.', '\\.')} \\([^)]*\\) FROM stdin;\\n[^\\\\]`),
      );
    }
    expect(logs.relay).toContain('relay.ready');
    expect(needles.every((needle) => needle.length > 0)).toBe(true);
    expect(leaksIn({ dump, ...logs }, needles)).toEqual([]);
  });
});
