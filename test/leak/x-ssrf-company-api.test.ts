// 悪意のあるテナント（ATK-03）が SET の受け口を内部に向けるときの、company-api から送信サービスまでの横断
// （M10 の SSRF の横断。不変条件7、plan 2章「SSRF を防ぐ」、plan 11章 テスト11、ADR 0022）。
// 送信サービスの宛先の検査そのもの（アドレスの種類の全表、URL の形、証明書、MX）は t11-sender-ssrf で確かめる。
// ここでは、本物の company-api と送信サービス（模擬の DNS と、確かめた後の最後の接続だけを差し替えたもの）で、
// company-api の SET の配送が送信サービスを通り、送信サービスが断ったときに、どこにもつながず、送り直しに残し、
// ログに宛先を残さないことを確かめる。このプロセスの外へのつなぎが0件であることは、見張り（test/setup/egress.ts）が
// 確かめる。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { startTestCompanyApi, type TestCompanyApi, type TestTenant } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import { takeEgressAttempts } from '../setup/egress.ts';
import {
  type DnsTable,
  makeTlsFixture,
  PUBLIC_V4,
  startTestSender,
  type TestSender,
  WEBHOOK_HOST,
} from '../setup/sender.ts';

const IMDS = '169.254.169.254';

/** 内部を指す受け口（URL と、その名前の模擬の DNS の答え）。最後は、URL を IP の形で登録したもの。 */
const INTERNAL: readonly {
  readonly url: string;
  readonly a?: readonly string[];
  readonly aaaa?: readonly string[];
}[] = [
  { url: 'https://imds.hooks.example/set', a: [IMDS] },
  { url: 'https://private.hooks.example/set', a: ['10.0.0.1'] },
  { url: 'https://loopback.hooks.example/set', a: ['127.0.0.1'] },
  { url: 'https://ula.hooks.example/set', aaaa: ['fd00:ec2::254'] },
  { url: 'https://mixed.hooks.example/set', a: [PUBLIC_V4, '192.168.0.1'] },
  { url: `https://${IMDS}/latest/meta-data/` },
];

function tableOf(): DnsTable {
  const table: Required<Pick<DnsTable, 'A' | 'AAAA'>> = {
    A: { [WEBHOOK_HOST]: [PUBLIC_V4] },
    AAAA: {},
  };
  for (const target of INTERNAL) {
    const host = new URL(target.url).hostname;
    if (target.a !== undefined) table.A[host] = [...target.a];
    if (target.aaaa !== undefined) table.AAAA[host] = [...target.aaaa];
  }
  return table;
}

let sender: TestSender;
let api: TestCompanyApi;

beforeAll(async () => {
  sender = await startTestSender(tableOf(), await makeTlsFixture());
  api = await startTestCompanyApi({
    tenants: [
      ...INTERNAL.map((target) => ({ webhookUrl: target.url })),
      { webhookUrl: `https://${WEBHOOK_HOST}/set` },
    ],
    sender: { socketPath: sender.sender.socketPath, credential: sender.credentials['company-api'] },
  });
});

afterAll(async () => {
  await api?.stop();
  await sender?.stop();
});

async function requestVerification(tenant: TestTenant): Promise<void> {
  const token = await api.accessToken(tenant);
  const res = await api.request({ path: '/v1/events/verification', token, json: {} });
  expect(res.status).toBe(202);
}

async function pending(tenant: TestTenant): Promise<number> {
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(tenant.tenantId, (tx) =>
      tx.query(sql`SELECT event_id FROM company_api.set_outbox`),
    );
    return rows.length;
  } finally {
    await db.close();
  }
}

function tenantAt(index: number): TestTenant {
  const tenant = api.tenants[index];
  if (tenant === undefined) throw new Error('準備に失敗した');
  return tenant;
}

describe('M10：SET の受け口を内部に向けるテナント（SSRF の横断。company-api → 送信サービス）', () => {
  it('受け口が内部のアドレスを指すテナントの SET は、どこにもつながず、送り直しに残し、ログに宛先を残さない', async () => {
    // 攻撃者が持っている情報：割符に登録した自社の SET の受け口の URL と、その名前の DNS を操れる立場（悪意のある
    //                         テナント ATK-03）
    // 試す経路：受け口の名前が、IMDS、プライベート、ループバック、IPv6 の ULA、公開と内部の混在を指すテナントと、
    //           受け口の URL を IMDS の IP の形で登録したテナントが、company-api に検証の SET を頼み、company-api に
    //           送信待ちを送らせる
    // 期待する結果：依頼は 202 だが、送信サービスはどこにもつながず（接続の記録も、受け口に届いた要求も0件）、IP の
    //               形の URL では名前も引かない。company-api は、送れなかったものとして送り直しに残す（retry）。
    //               company-api と送信サービスのログには、理由の種類（blocked_address、invalid_destination）だけが
    //               残り、名前、URL、アドレスは残らない。見張りの記録も0件
    // plan 11章：テスト11（M10 の SSRF の横断）
    const attackers = INTERNAL.map((_target, index) => tenantAt(index));
    for (const tenant of attackers) await requestVerification(tenant);
    expect(await api.api.deliverDue()).toEqual({
      delivered: 0,
      retry: INTERNAL.length,
      dropped: 0,
      reissue: 0,
      held: 0,
    });
    expect(sender.connections).toEqual([]);
    expect(sender.requests).toEqual([]);
    // 名前の受け口は A と AAAA を引くだけ。IP の形の受け口は、名前を引かずに断る。
    expect(
      [...new Set(sender.resolver.queries.map((q) => q.replace(/^[A-Z]+:/, '')))].sort(),
    ).toEqual(
      INTERNAL.map((target) => new URL(target.url).hostname)
        .filter((host) => host !== IMDS)
        .sort(),
    );
    expect(sender.resolver.queries.every((q) => /^(A|AAAA):/.test(q))).toBe(true);
    for (const tenant of attackers) expect(await pending(tenant)).toBe(1);

    const companyLogs = api.logs.join('\n');
    const senderLogs = sender.logs.join('\n');
    expect(companyLogs).toContain('company_api.set_not_delivered');
    expect(companyLogs).toContain('blocked_address');
    expect(companyLogs).toContain('invalid_destination');
    expect(senderLogs).toContain('sender.webhook_rejected');
    for (const needle of [
      ...INTERNAL.flatMap((target) => [
        new URL(target.url).hostname,
        new URL(target.url).pathname,
        ...(target.a ?? []),
        ...(target.aaaa ?? []),
      ]),
      '169.254',
      'meta-data',
    ]) {
      expect([needle, companyLogs.includes(needle)]).toEqual([needle, false]);
      expect([needle, senderLogs.includes(needle)]).toEqual([needle, false]);
    }
    expect(takeEgressAttempts()).toEqual([]);
  });

  it('答えを後から内部に変えても（DNS rebinding）、リダイレクトで内部へ向けても、内部にはつながない', async () => {
    // 攻撃者が持っている情報：自社の SET の受け口と、その名前の DNS を操れる立場（ATK-03）
    // 試す経路：公開のアドレスを指す受け口に、1件目の SET を届けさせる。名前の答えを IMDS に変えてから、2件目を
    //           送らせる。答えを公開のアドレスに戻し、受け口が 302 で IMDS へ転送して、3件目を送らせる
    // 期待する結果：1件目は届く。2件目は、送信サービスが断り（blocked_address）、送り直しに残る。3件目は、確かめた
    //               公開のアドレスに1回だけつなぎ、転送の先へはつながず（redirect）、送り直しに残る。接続の記録は、
    //               公開のアドレスへの2回だけ。見張りの記録も0件
    // plan 11章：テスト11（M10 の SSRF の横断）
    const tenant = tenantAt(INTERNAL.length);
    const connections = sender.connections.length;
    await requestVerification(tenant);
    expect(await api.api.deliverDue()).toMatchObject({ delivered: 1, retry: 0 });
    expect(sender.connections.slice(connections)).toEqual([{ kind: 'tls', address: PUBLIC_V4 }]);

    const table = sender.resolver.table;
    sender.resolver.table = { ...table, A: { ...table.A, [WEBHOOK_HOST]: [IMDS] } };
    await requestVerification(tenant);
    expect(await api.api.deliverDue()).toMatchObject({ delivered: 0, retry: 1 });
    expect(await pending(tenant)).toBe(1);
    expect(sender.connections.slice(connections)).toEqual([{ kind: 'tls', address: PUBLIC_V4 }]);

    sender.resolver.table = table;
    sender.respondWith(302, { location: `http://${IMDS}/latest/meta-data/` });
    try {
      const requests = sender.requests.length;
      await requestVerification(tenant);
      // 2件目は、間を空けるまで送り直さない。送るのは3件目だけ。
      expect(await api.api.deliverDue()).toMatchObject({ delivered: 0, retry: 1 });
      expect(sender.requests.length - requests).toBe(1);
    } finally {
      sender.respondWith(202);
    }
    expect(await pending(tenant)).toBe(2);
    expect(sender.connections.slice(connections)).toEqual([
      { kind: 'tls', address: PUBLIC_V4 },
      { kind: 'tls', address: PUBLIC_V4 },
    ]);
    expect(api.logs.join('\n')).toContain('redirect');
    for (const needle of [WEBHOOK_HOST, IMDS, 'meta-data']) {
      expect([needle, api.logs.join('\n').includes(needle)]).toEqual([needle, false]);
      expect([needle, sender.logs.join('\n').includes(needle)]).toEqual([needle, false]);
    }
    expect(takeEgressAttempts()).toEqual([]);
  });
});
