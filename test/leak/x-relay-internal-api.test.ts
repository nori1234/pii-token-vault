// relay の内部配送 API（不変条件3、CAP-38、ADR 0021）。idp は本物のアドレスを持たず、利用者 ID と種類だけを relay に渡す。
// relay がその利用者の範囲で暗号文を読み、復号して、固定の文面で送る。呼べるのは idp の資格情報だけ。

import { randomBytes, randomUUID } from 'node:crypto';
import { stat } from 'node:fs/promises';
import { request } from 'node:http';
import { dirname } from 'node:path';
import { authenticate } from 'mailauth';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RelayMailer } from '../../packages/idp/src/mailer.ts';
import { parseMessage } from '../../packages/relay/src/mime.ts';
import { DELIVERY_ERROR_BODY } from '../../packages/warifu-core/src/relay/protocol.ts';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { NOTICE_DOMAIN, startTestRelay, type TestRelay } from '../setup/relay.ts';

let relay: TestRelay;
let idp: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  relay = await startTestRelay();
  idp = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
    mailer: new RelayMailer({
      socketPath: relay.relay.socketPath,
      credential: relay.idpCredential,
    }),
  });
});

afterAll(async () => {
  await idp.stop();
  await relay.stop();
});

interface RawResult {
  readonly status: number;
  readonly text: string;
}

/** 型を通さない生の要求（攻撃の段で使う）。宛先はテストの中で立てた relay のソケットだけ。 */
function rawCall(input: {
  readonly method?: string;
  readonly path?: string;
  readonly authorization?: string;
  readonly body?: string | Buffer;
}): Promise<RawResult> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: relay.relay.socketPath,
        method: input.method ?? 'POST',
        path: input.path ?? '/v1/deliver',
        headers: {
          'content-type': 'application/json',
          ...(input.authorization === undefined ? {} : { authorization: input.authorization }),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end(input.body ?? '');
  });
}

const deliver = (body: unknown) =>
  rawCall({ authorization: `Bearer ${relay.idpCredential}`, body: JSON.stringify(body) });

function bodyText(raw: Buffer): string {
  return Buffer.from(
    parseMessage(raw).body.toString('latin1').replace(/\s+/g, ''),
    'base64',
  ).toString('utf8');
}

function headerOf(raw: Buffer, key: string): string[] {
  return parseMessage(raw)
    .headers.filter((h) => h.key === key)
    .map((h) => {
      const text = h.line.toString('latin1').replace(/\r\n[ \t]+/g, ' ');
      return text.slice(text.indexOf(':') + 1).trim();
    });
}

describe('漏えい：relay の内部配送 API（CAP-38）', () => {
  it('idp 以外の資格情報と、壊れた資格情報は、同じ 401 で断る', async () => {
    // 攻撃者が持っている情報：relay のソケットに届く位置（同じホストの別のサービスが侵害された場面）と、
    //                         別のサービスの資格情報の形
    // 試す経路：資格情報なし、company-api や relay を名乗るもの、idp の形で秘密が違うもの、長さが違うもの、Basic で、
    //           実在する形の要求を送る
    // 期待する結果：すべて 401 で、本文はバイト単位で同じ。何も送られない
    // plan 11章：テスト8（復号できる経路を relay の外に作らない）、CAP-38
    const before = relay.outbound.all().length;
    const body = JSON.stringify({ kind: 'email_changed_notice', userId: randomUUID() });
    const secret = randomBytes(32).toString('base64url');
    const results = await Promise.all(
      [
        undefined,
        `Bearer company-api.${secret}`,
        `Bearer relay.${secret}`,
        `Bearer idp.${secret}`,
        `Bearer idp.${secret.slice(1)}`,
        `Bearer idp.${secret}A`,
        `Bearer ${relay.idpCredential.slice(4)}`,
        `Basic ${Buffer.from(`idp:${relay.idpCredential}`).toString('base64')}`,
        `bearer ${relay.idpCredential}`,
      ].map((authorization) =>
        rawCall({ body, ...(authorization === undefined ? {} : { authorization }) }),
      ),
    );
    expect(results.map((r) => r.status)).toEqual(results.map(() => 401));
    expect(new Set(results.map((r) => r.text))).toEqual(new Set([DELIVERY_ERROR_BODY.forbidden]));
    expect(relay.outbound.all()).toHaveLength(before);
  });

  it('POST /v1/deliver 以外は 404。形の違う要求は、同じ 400 で断る', async () => {
    // 攻撃者が持っている情報：idp の資格情報（idp が侵害された場面）
    // 試す経路：ほかのパスとメソッド、クエリ付きのパス、知らない種類、余計な項目（宛先のアドレスなど）、
    //           形の違うコード、利用者 ID でないもの、JSON でないもの、1KB を超える本文
    // 期待する結果：パスとメソッドの違いは 404、本文の違いは 400 で、どちらも固定の本文。何も送られない。
    //               idp の資格情報でも、宛先のアドレスや文面を指定する口はない
    // plan 11章：テスト8、CAP-38
    const before = relay.outbound.all().length;
    const auth = `Bearer ${relay.idpCredential}`;
    const notFound = await Promise.all([
      rawCall({ method: 'GET', authorization: auth }),
      rawCall({ method: 'PUT', authorization: auth }),
      rawCall({ path: '/v1/deliver?to=x@example.com', authorization: auth }),
      rawCall({ path: '/v1/decrypt', authorization: auth }),
      rawCall({ path: '/', authorization: auth }),
    ]);
    expect(notFound.map((r) => [r.status, r.text])).toEqual(
      notFound.map(() => [404, DELIVERY_ERROR_BODY.not_found]),
    );
    const userId = randomUUID();
    const invalid = await Promise.all([
      deliver({ kind: 'raw_mail', userId }),
      deliver({ kind: 'email_changed_notice', userId, to: 'x@example.com' }),
      deliver({ kind: 'email_verification', userId, code: '1234567' }),
      deliver({ kind: 'email_verification', userId, code: '１２３４５６７８' }),
      deliver({ kind: 'email_verification', userId, code: '12345678', subject: 'x' }),
      deliver({ kind: 'email_changed_notice', userId: 'not-a-uuid' }),
      deliver([{ kind: 'email_changed_notice', userId }]),
      rawCall({ authorization: auth, body: 'kind=email_changed_notice' }),
      rawCall({
        authorization: auth,
        body: JSON.stringify({ kind: 'email_changed_notice', userId, pad: 'x'.repeat(2048) }),
      }),
    ]);
    expect(invalid.map((r) => [r.status, r.text])).toEqual(
      invalid.map(() => [400, DELIVERY_ERROR_BODY.invalid_request]),
    );
    expect(relay.outbound.all()).toHaveLength(before);
  });

  it('知らない利用者でも、アドレスのない利用者でも、同じ 202 を返して、何も送らない', async () => {
    // 攻撃者が持っている情報：idp の資格情報（idp が侵害された場面）と、推測した利用者 ID
    // 試す経路：存在しない利用者 ID で、宛先確認と旧アドレスへの知らせを頼む
    // 期待する結果：202 で同じ本文。何も送られない（利用者がいるかどうか、アドレスがあるかどうかを返さない）
    // plan 11章：テスト10（列挙させない）
    const before = relay.outbound.all().length;
    const results = await Promise.all([
      deliver({ kind: 'email_verification', userId: randomUUID(), code: '12345678' }),
      deliver({ kind: 'email_changed_notice', userId: randomUUID() }),
    ]);
    expect(results.map((r) => [r.status, r.text])).toEqual([
      [202, '{"ok":true}'],
      [202, '{"ok":true}'],
    ]);
    expect(relay.outbound.all()).toHaveLength(before);
  });

  it('ソケットの親のディレクトリは、このプロセスの利用者だけが開ける', async () => {
    // 攻撃者が持っている情報：同じホストの別の利用者のアカウント
    // 試す経路：relay のソケットの親のディレクトリの権限を見る
    // 期待する結果：group と other の権限がない（TCP では待ち受けない。ソケットだけ）
    // plan 11章：テスト8（spec 04 4章）
    const dir = await stat(dirname(relay.relay.socketPath));
    expect(dir.mode & 0o077).toBe(0);
    expect((await stat(relay.relay.socketPath)).isSocket()).toBe(true);
  });
});

describe('idp → relay の配送（plan 4章、不変条件3）', () => {
  it('宛先確認のコードは確認中のアドレスに、変更の知らせは旧アドレスにだけ届き、知らせにはリンクも新しいアドレスもない', async () => {
    // 攻撃者が持っている情報：なし（正規の経路の確認。idp が本物のアドレスを持たずに送れることを見る）
    // 試す経路：PWA でアカウントを作り、アドレス A を登録する（コードは relay が A に送る）。step-up の後、
    //           アドレス B に変える（コードは B に、知らせは A に）
    // 期待する結果：A に確認コード、B に確認コード、A に変更の知らせの順に届く。どれも割符の通知のドメインから、
    //               relay の DKIM で署名されている。知らせには、リンク、コード、B のアドレスが入らない。
    //               idp のログに、A も B もコードも出ない
    // plan 11章：テスト10 の前提、テスト7 の一部（平文を残さない）
    const browser = new Browser(idp.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const a = `a${randomBytes(6).toString('hex')}@users.example`;
    const b = `b${randomBytes(6).toString('hex')}@users.example`;
    const codeFor = (address: string) => {
      const message = relay.outbound.lastTo(address);
      if (message === undefined) throw new Error('届いていない');
      const match = bodyText(message.raw).match(/確認コード：([0-9]{4}) ([0-9]{4})/);
      if (match === null) throw new Error('コードがない');
      return `${match[1]}${match[2]}`;
    };

    const before = relay.outbound.all().length;
    expect((await browser.post('/api/email/start', { email: a })).status).toBe(202);
    const codeA = codeFor(a);
    expect((await browser.post('/api/email/confirm', { code: codeA })).status).toBe(200);
    clock += 16 * 60 * 1000;
    expect((await browser.stepUp()).status).toBe(200);
    expect((await browser.post('/api/email/start', { email: b })).status).toBe(202);
    const codeB = codeFor(b);
    expect((await browser.post('/api/email/confirm', { code: codeB })).status).toBe(200);

    const sent = relay.outbound.all().slice(before);
    expect(sent.map((m) => m.rcptTo)).toEqual([a, b, a]);
    const notice = sent[2];
    if (notice === undefined) throw new Error('知らせがない');
    const text = bodyText(notice.raw);
    expect(text).toContain('別のアドレスに変更されました');
    expect(text).not.toMatch(/https?:\/\/|[0-9]{4} [0-9]{4}/);
    expect(notice.raw.toString('latin1')).not.toContain(b);
    for (const message of sent) {
      expect(headerOf(message.raw, 'from')[0]).toContain(`<notices@${NOTICE_DOMAIN}>`);
      const result = await authenticate(message.raw, {
        ip: '192.0.2.25',
        helo: 'mx.relay.warifu.test',
        mta: 'mx.users.example',
        sender: message.mailFrom,
        resolver: relay.dns(),
        disableBimi: true,
      } as Parameters<typeof authenticate>[1]);
      expect(result.dkim.results.map((r) => [r.signingDomain, r.status.result])).toEqual([
        [NOTICE_DOMAIN, 'pass'],
      ]);
      expect((result.dmarc || undefined)?.status.result).toBe('pass');
    }
    const logs = [...idp.logLines(), ...relay.logs].join('\n');
    for (const needle of [a, b, codeA, codeB]) expect(logs).not.toContain(needle);
  });
});
