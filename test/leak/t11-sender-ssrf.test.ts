// 送信サービスの SSRF 対策（不変条件7、plan 2章、CAP-20〜26、RP-51、ADR 0022）。plan 11章 テスト11。
// sender の宛先の検査（URL の形、名前解決、公開のアドレスか）は本物のまま動かす。差し替えるのは、確かめた後の
// 最後の接続だけで、接続先はテストの中で立てた 127.0.0.1 のサーバー。どのアドレスにつなごうとしたかを見る。

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { isPublicAddress } from '../../packages/sender/src/address.ts';
import {
  createSenderMailClient,
  createSenderWebhookClient,
} from '../../packages/warifu-core/src/sender/client.ts';
import {
  makeTlsFixture,
  PUBLIC_V4,
  PUBLIC_V6,
  startTestSender,
  type TestSender,
  type TlsFixture,
  WEBHOOK_HOST,
} from '../setup/sender.ts';

const SET = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0.c2lnbmF0dXJl';

let fixture: TlsFixture;
let t: TestSender;

beforeAll(async () => {
  fixture = await makeTlsFixture();
});

beforeEach(async () => {
  await t?.stop();
  t = await startTestSender({ A: { [WEBHOOK_HOST]: [PUBLIC_V4] } }, fixture);
});

afterAll(async () => {
  await t?.stop();
});

const webhook = () =>
  createSenderWebhookClient({
    socketPath: t.sender.socketPath,
    credential: t.credentials['company-api'],
  });
const mail = () =>
  createSenderMailClient({ socketPath: t.sender.socketPath, credential: t.credentials.relay });

describe('漏えい：送信サービスの SSRF 対策（plan 11章 テスト11）', () => {
  it('公開のユニキャストでないアドレスは、すべて接続先として拒否する', () => {
    // 攻撃者が持っている情報：Webhook の URL や MX を登録・指定できる立場（悪意のあるテナント ATK-03、
    //                         利用者のドメインの DNS を操る者）
    // 試す経路：IMDS、プライベート、ループバック、CGN、リンクローカル、文書用、マルチキャスト、IPv4 を埋め込んだ
    //           IPv6（::ffff:0:0/96、NAT64、6to4）、ULA、ゾーン ID 付き
    // 期待する結果：すべて false。公開のアドレスだけ true
    // plan 11章：テスト11
    for (const address of [
      '169.254.169.254',
      '169.254.170.2',
      '10.0.0.1',
      '172.16.5.4',
      '192.168.1.1',
      '127.0.0.1',
      '0.0.0.0',
      '100.64.0.1',
      '192.0.0.170',
      '192.0.2.1',
      '198.18.0.1',
      '198.51.100.1',
      '203.0.113.9',
      '224.0.0.251',
      '255.255.255.255',
      '::',
      '::1',
      '::ffff:169.254.169.254',
      '::ffff:10.0.0.1',
      '64:ff9b::a9fe:a9fe',
      '2002:a9fe:a9fe::1',
      '2001:db8::1',
      'fc00::1',
      'fd00:ec2::254',
      'fe80::1',
      'fe80::1%eth0',
      'ff02::1',
      'not-an-ip',
    ]) {
      expect([address, isPublicAddress(address)]).toEqual([address, false]);
    }
    for (const address of [PUBLIC_V4, PUBLIC_V6, '1.1.1.1', '2a00:1450:4001:80b::200e']) {
      expect([address, isPublicAddress(address)]).toEqual([address, true]);
    }
  });

  it('https で 443 番の、名前のホストでない URL には、名前も引かずに断る', async () => {
    // 攻撃者が持っている情報：Webhook の URL を登録できる立場（悪意のあるテナント ATK-03）
    // 試す経路：http、ほかのポート、利用者情報、IP の直書き（IMDS、ループバック、IPv6）、localhost、
    //           1つのラベルの名前、file: と gopher:
    // 期待する結果：すべて invalid_destination。名前解決も接続もしない
    // plan 11章：テスト11
    for (const url of [
      `http://${WEBHOOK_HOST}/hook`,
      `https://${WEBHOOK_HOST}:8443/hook`,
      `https://user:pass@${WEBHOOK_HOST}/hook`,
      'https://169.254.169.254/latest/meta-data/',
      'https://127.0.0.1/hook',
      'https://[::1]/hook',
      'https://[fd00:ec2::254]/hook',
      'https://localhost/hook',
      'https://metadata.localhost/hook',
      'https://intranet/hook',
      'file:///etc/passwd',
      'gopher://hooks.company.example/',
      `https://${WEBHOOK_HOST}/hook#frag`,
    ]) {
      expect([url, await webhook().postSet({ url, set: SET })]).toEqual([
        url,
        { ok: false, reason: 'invalid_destination' },
      ]);
    }
    expect(t.resolver.queries).toEqual([]);
    expect(t.connections).toEqual([]);
  });

  it('名前が公開でないアドレスを1つでも指せば、つながない（IMDS、内部の API、プライベート IP）', async () => {
    // 攻撃者が持っている情報：Webhook の URL のホストの DNS を操れる立場（悪意のあるテナント ATK-03）
    // 試す経路：A や AAAA が IMDS、プライベート、ループバック、ULA を指す名前。公開と内部を混ぜた答え
    // 期待する結果：blocked_address。どこにもつながない
    // plan 11章：テスト11
    for (const [a, aaaa] of [
      [['169.254.169.254'], undefined],
      [['10.1.2.3'], undefined],
      [['127.0.0.1'], undefined],
      [undefined, ['::1']],
      [undefined, ['fd00:ec2::254']],
      [[PUBLIC_V4, '192.168.0.10'], undefined],
      [[PUBLIC_V4], ['fe80::1']],
    ] as const) {
      t.resolver.table = {
        ...(a === undefined ? {} : { A: { [WEBHOOK_HOST]: [...a] } }),
        ...(aaaa === undefined ? {} : { AAAA: { [WEBHOOK_HOST]: [...aaaa] } }),
      };
      expect(await webhook().postSet({ url: `https://${WEBHOOK_HOST}/hook`, set: SET })).toEqual({
        ok: false,
        reason: 'blocked_address',
      });
    }
    expect(t.connections).toEqual([]);
    t.resolver.table = {};
    expect(await webhook().postSet({ url: `https://${WEBHOOK_HOST}/hook`, set: SET })).toEqual({
      ok: false,
      reason: 'no_address',
    });
  });

  it('DNS rebinding：確かめたアドレスに直接つなぎ、接続のときに名前を引き直さない', async () => {
    // 攻撃者が持っている情報：Webhook のホストの DNS を操り、問い合わせのたびに答えを変えられる（ATK-03）
    // 試す経路：1回目の A は公開のアドレス、2回目以降は IMDS を返すようにして送らせる
    // 期待する結果：A と AAAA を1回ずつ引くだけ。接続先は1回目の公開のアドレスだけ。届いた要求の Host は名前、
    //               本文は SET、content-type は application/secevent+jwt
    // plan 11章：テスト11
    const original = t.resolver.resolve4.bind(t.resolver);
    let calls = 0;
    t.resolver.resolve4 = async (name) => {
      calls += 1;
      return calls === 1 ? original(name) : ['169.254.169.254'];
    };
    expect(await webhook().postSet({ url: `https://${WEBHOOK_HOST}/hook?x=1`, set: SET })).toEqual({
      ok: true,
    });
    expect(calls).toBe(1);
    expect(t.connections).toEqual([{ kind: 'tls', address: PUBLIC_V4 }]);
    expect(t.requests).toHaveLength(1);
    expect(t.requests[0]).toMatchObject({
      method: 'POST',
      url: '/hook?x=1',
      body: SET,
      headers: { host: WEBHOOK_HOST, 'content-type': 'application/secevent+jwt' },
    });
  });

  it('リダイレクトに従わない。証明書が名前に合わなければ送らない', async () => {
    // 攻撃者が持っている情報：Webhook の受け口を操れる立場（ATK-03）
    // 試す経路：302 で IMDS へ、307 で内部の名前へ転送させる。証明書の名前が違うホストとして送らせる
    // 期待する結果：redirect で失敗し、2回目の接続をしない。証明書が合わなければ connect_failed
    // plan 11章：テスト11
    for (const [status, location] of [
      [302, 'http://169.254.169.254/latest/meta-data/'],
      [307, 'https://intranet.internal/admin'],
    ] as const) {
      t.respondWith(status, { location });
      expect(await webhook().postSet({ url: `https://${WEBHOOK_HOST}/hook`, set: SET })).toEqual({
        ok: false,
        reason: 'redirect',
      });
    }
    expect(t.connections).toHaveLength(2);
    expect(t.connections.every((c) => c.address === PUBLIC_V4)).toBe(true);
    t.respondWith(202);
    t.resolver.table = { A: { 'other.company.example': [PUBLIC_V4] } };
    expect(
      await webhook().postSet({ url: 'https://other.company.example/hook', set: SET }),
    ).toEqual({ ok: false, reason: 'connect_failed' });
  });

  it('MX が内部の IP を指すアドレスへは、配送しない', async () => {
    // 攻撃者が持っている情報：利用者のメールのドメインの DNS を操れる立場（返信の先、ATK-03）
    // 試す経路：MX のホストが IMDS、プライベート、ループバックを指す。MX がない名前の A が内部を指す。
    //           null MX。MX が localhost。MX の1つ目が内部、2つ目が公開
    // 期待する結果：内部を指すものには、つながない（blocked_address）。null MX は null_mx。
    //               1つ目が内部で2つ目が公開なら、公開の方にだけ送る
    // plan 11章：テスト11
    const raw = Buffer.from('From: <x@relay.example>\r\nTo: <u@users.example>\r\n\r\nbody\r\n');
    const send = (rcptTo: string) =>
      mail().sendMail({ mailFrom: 'bounce@relay.example', rcptTo, raw: raw.toString('base64') });
    t.resolver.table = {
      MX: {
        'imds.example': [{ exchange: 'mx.imds.example', priority: 10 }],
        'private.example': [{ exchange: 'mx.private.example', priority: 10 }],
        'null.example': [{ exchange: '', priority: 0 }],
        'local.example': [{ exchange: 'localhost', priority: 10 }],
        'mixed.example': [
          { exchange: 'mx1.mixed.example', priority: 10 },
          { exchange: 'mx2.mixed.example', priority: 20 },
        ],
      },
      A: {
        'mx.imds.example': ['169.254.169.254'],
        'mx.private.example': ['10.0.0.25'],
        'nomx.example': ['127.0.0.1'],
        'mx1.mixed.example': ['192.168.10.25'],
        'mx2.mixed.example': [PUBLIC_V4],
      },
      TXT: { 'nomx.example': [['v=spf1 -all']] },
    };
    expect(await send('u@imds.example')).toEqual({ ok: false, reason: 'blocked_address' });
    expect(await send('u@private.example')).toEqual({ ok: false, reason: 'blocked_address' });
    expect(await send('u@nomx.example')).toEqual({ ok: false, reason: 'blocked_address' });
    expect(await send('u@null.example')).toEqual({ ok: false, reason: 'null_mx' });
    expect(await send('u@local.example')).toEqual({ ok: false, reason: 'invalid_destination' });
    expect(await send('u@[127.0.0.1]')).toEqual({ ok: false, reason: 'invalid_destination' });
    expect(t.connections).toEqual([]);
    expect(await send('u@mixed.example')).toEqual({ ok: true });
    expect(t.connections).toEqual([{ kind: 'tcp', address: PUBLIC_V4 }]);
    expect(t.mails).toHaveLength(1);
    expect(t.mails[0]?.to).toEqual(['u@mixed.example']);
    expect(t.mails[0]?.raw.equals(raw)).toBe(true);
  });

  it('ログに URL、宛先、アドレスを残さない', async () => {
    // 攻撃者が持っている情報：sender のログを読める立場（ATK-06）
    // 試す経路：送れた要求と、断った要求の後のログを検索する
    // 期待する結果：ホスト名、パス、IP、宛先のアドレスが出ない。出るのは理由の種類だけ
    // plan 11章：テスト11（テスト7の一部）
    await webhook().postSet({ url: `https://${WEBHOOK_HOST}/secret-path`, set: SET });
    t.resolver.table = { A: { [WEBHOOK_HOST]: ['169.254.169.254'] } };
    await webhook().postSet({ url: `https://${WEBHOOK_HOST}/secret-path`, set: SET });
    const logs = t.logs.join('\n');
    expect(logs).toContain('blocked_address');
    for (const needle of [WEBHOOK_HOST, 'secret-path', PUBLIC_V4, '169.254', SET]) {
      expect(logs).not.toContain(needle);
    }
  });
});
