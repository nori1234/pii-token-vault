// 送信サービスの内部 API（不変条件7、CAP-38、ADR 0022）。呼べるのは relay（配送と名前解決）と company-api（Webhook）
// だけで、呼び出し元ごとに口を分ける。宛先の検査は呼び出し元から外せない（t11-sender-ssrf）。

import { randomBytes } from 'node:crypto';
import { stat } from 'node:fs/promises';
import { request } from 'node:http';
import { dirname } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SENDER_ERROR_BODY } from '../../packages/warifu-core/src/sender/protocol.ts';
import { makeTlsFixture, PUBLIC_V4, startTestSender, type TestSender } from '../setup/sender.ts';

let t: TestSender;

beforeAll(async () => {
  t = await startTestSender(
    {
      A: { 'hooks.company.example': [PUBLIC_V4] },
      TXT: { '_dmarc.users.example': [['v=DMARC1; p=reject']] },
    },
    await makeTlsFixture(),
  );
});

afterAll(async () => {
  await t.stop();
});

function raw(input: {
  readonly method?: string;
  readonly path: string;
  readonly authorization?: string;
  readonly body?: string;
}): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: t.sender.socketPath,
        method: input.method ?? 'POST',
        path: input.path,
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

const SET = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln';
const webhookBody = JSON.stringify({ url: 'https://hooks.company.example/hook', set: SET });
const dnsBody = JSON.stringify({ name: '_dmarc.users.example', type: 'TXT' });

describe('漏えい：送信サービスの内部 API（CAP-38）', () => {
  it('資格情報のない要求、ほかのサービスの資格情報、壊れた資格情報は、同じ 401 で断り、何も送らない', async () => {
    // 攻撃者が持っている情報：sender のソケットに届く位置（同じホストの別のサービスが侵害された場面、ATK-07）と、
    //                         別のサービスの資格情報の形
    // 試す経路：資格情報なし、idp や keysvc を名乗るもの、形が company-api で秘密が違うもの、長さが違うもの、Basic
    // 期待する結果：すべて 401 で、本文はバイト単位で同じ。名前解決も接続もしない
    // plan 11章：テスト11、CAP-38
    const secret = randomBytes(32).toString('base64url');
    const results = await Promise.all(
      [
        undefined,
        `Bearer idp.${secret}`,
        `Bearer keysvc.${secret}`,
        `Bearer company-api.${secret}`,
        `Bearer ${t.credentials['company-api'].slice(0, -1)}`,
        `Bearer ${t.credentials['company-api']}A`,
        `Basic ${Buffer.from(t.credentials['company-api']).toString('base64')}`,
        `bearer ${t.credentials['company-api']}`,
      ].map((authorization) =>
        raw({
          path: '/v1/webhook',
          body: webhookBody,
          ...(authorization ? { authorization } : {}),
        }),
      ),
    );
    expect(results.map((r) => [r.status, r.text])).toEqual(
      results.map(() => [401, SENDER_ERROR_BODY.forbidden]),
    );
    expect(t.resolver.queries).toEqual([]);
    expect(t.connections).toEqual([]);
  });

  it('呼び出し元に許していない口は 401。relay は Webhook を、company-api は配送と名前解決を呼べない', async () => {
    // 攻撃者が持っている情報：侵害した relay か company-api の資格情報（ATK-07）
    // 試す経路：relay の資格情報で /v1/webhook、company-api の資格情報で /v1/mail と /v1/dns を呼ぶ
    // 期待する結果：すべて 401。何も送らず、名前も引かない
    // plan 11章：テスト11、CAP-38
    const mailBody = JSON.stringify({
      mailFrom: 'b@relay.example',
      rcptTo: 'u@users.example',
      raw: Buffer.from('x').toString('base64'),
    });
    const results = await Promise.all([
      raw({
        path: '/v1/webhook',
        authorization: `Bearer ${t.credentials.relay}`,
        body: webhookBody,
      }),
      raw({
        path: '/v1/mail',
        authorization: `Bearer ${t.credentials['company-api']}`,
        body: mailBody,
      }),
      raw({
        path: '/v1/dns',
        authorization: `Bearer ${t.credentials['company-api']}`,
        body: dnsBody,
      }),
    ]);
    expect(results.map((r) => [r.status, r.text])).toEqual(
      results.map(() => [401, SENDER_ERROR_BODY.forbidden]),
    );
    expect(t.resolver.queries).toEqual([]);
    expect(t.connections).toEqual([]);
  });

  it('ほかのパスとメソッドは 404。形の違う本文は 400', async () => {
    // 攻撃者が持っている情報：company-api の資格情報（ATK-07）
    // 試す経路：GET、ほかのパス、クエリ付きのパス、余計な項目（ヘッダーや接続先の IP を指定する口）、
    //           JWS でない SET、大きすぎる SET、JSON でないもの
    // 期待する結果：パスとメソッドの違いは 404、本文の違いは 400。接続先を指定する口はない
    // plan 11章：テスト11、CAP-38
    const auth = `Bearer ${t.credentials['company-api']}`;
    const notFound = await Promise.all([
      raw({ method: 'GET', path: '/v1/webhook', authorization: auth }),
      raw({ path: '/v1/fetch', authorization: auth, body: webhookBody }),
      raw({ path: '/v1/webhook?ip=127.0.0.1', authorization: auth, body: webhookBody }),
      raw({ path: '/', authorization: auth }),
    ]);
    expect(notFound.map((r) => [r.status, r.text])).toEqual(
      notFound.map(() => [404, SENDER_ERROR_BODY.not_found]),
    );
    const invalid = await Promise.all(
      [
        JSON.stringify({
          url: 'https://hooks.company.example/hook',
          set: SET,
          address: '127.0.0.1',
        }),
        JSON.stringify({
          url: 'https://hooks.company.example/hook',
          set: SET,
          headers: { a: 'b' },
        }),
        JSON.stringify({ url: 'https://hooks.company.example/hook', set: 'not a jws\r\nX: y' }),
        JSON.stringify({ url: 'https://hooks.company.example/hook', set: 'a'.repeat(9000) }),
        JSON.stringify({ url: 'https://hooks.company.example/hook' }),
        'url=https://hooks.company.example/hook',
      ].map((body) => raw({ path: '/v1/webhook', authorization: auth, body })),
    );
    expect(invalid.map((r) => [r.status, r.text])).toEqual(
      invalid.map(() => [400, SENDER_ERROR_BODY.invalid_request]),
    );
    expect(t.connections).toEqual([]);
  });

  it('relay は名前解決の口で TXT を引ける。localhost や IP の形の名前は引かない', async () => {
    // 攻撃者が持っている情報：relay の資格情報（返信の DMARC の判定の経路）
    // 試す経路：_dmarc の TXT を引く。localhost、1つのラベル、IP の形、知らない種類（PTR、ANY）を引かせる
    // 期待する結果：TXT は答えが返る。名前の形が違えば EBADNAME で、問い合わせない。知らない種類は 400
    // plan 11章：テスト11
    const auth = `Bearer ${t.credentials.relay}`;
    const ok = await raw({ path: '/v1/dns', authorization: auth, body: dnsBody });
    expect([ok.status, JSON.parse(ok.text)]).toEqual([
      200,
      { ok: true, records: [['v=DMARC1; p=reject']] },
    ]);
    const before = t.resolver.queries.length;
    for (const name of ['localhost', 'intranet', '169.254.169.254', 'x.localhost']) {
      const r = await raw({
        path: '/v1/dns',
        authorization: auth,
        body: JSON.stringify({ name, type: 'A' }),
      });
      expect([name, r.status, JSON.parse(r.text)]).toEqual([
        name,
        200,
        { ok: false, code: 'EBADNAME' },
      ]);
    }
    expect(t.resolver.queries.length).toBe(before);
    for (const type of ['PTR', 'ANY', 'SRV']) {
      const r = await raw({
        path: '/v1/dns',
        authorization: auth,
        body: JSON.stringify({ name: 'users.example', type }),
      });
      expect(r.status).toBe(400);
    }
  });

  it('ソケットの親のディレクトリは、このプロセスの利用者だけが開ける', async () => {
    // 攻撃者が持っている情報：同じホストの別の利用者のアカウント
    // 試す経路：sender のソケットの親のディレクトリの権限を見る
    // 期待する結果：group と other の権限がない（TCP では待ち受けない。ソケットだけ）
    // plan 11章：テスト11（spec 04 4章）
    const dir = await stat(dirname(t.sender.socketPath));
    expect(dir.mode & 0o077).toBe(0);
    expect((await stat(t.sender.socketPath)).isSocket()).toBe(true);
  });
});
