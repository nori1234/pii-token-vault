// 企業に送る SET（RFC 8417、RFC 8935、RP-50・51、ADR 0022）。company-api → sender → 企業の受け口までを通す。
// 送る宛先の検査は sender（t11-sender-ssrf）。ここでは、SET の中身、送り直し、緊急停止、ログと DB に残すものを見る。

import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { startTestCompanyApi, type TestCompanyApi } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import {
  makeTlsFixture,
  PUBLIC_V4,
  startTestSender,
  type TestSender,
  WEBHOOK_HOST,
} from '../setup/sender.ts';

const VERIFICATION = 'https://schemas.openid.net/secevent/ssf/event-type/verification';
let sender: TestSender;
let api: TestCompanyApi;
let clock = Date.now();

beforeAll(async () => {
  sender = await startTestSender({ A: { [WEBHOOK_HOST]: [PUBLIC_V4] } }, await makeTlsFixture());
  api = await startTestCompanyApi({
    tenants: [
      { webhookUrl: `https://${WEBHOOK_HOST}/set/a` },
      { webhookUrl: `https://${WEBHOOK_HOST}/set/b` },
      {},
    ],
    sender: { socketPath: sender.sender.socketPath, credential: sender.credentials['company-api'] },
    now: () => new Date(clock),
  });
});

afterAll(async () => {
  await api.stop();
  await sender.stop();
});

async function outboxCount(tenantId: string): Promise<number> {
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(tenantId as never, (tx) =>
      tx.query(sql`SELECT event_id FROM company_api.set_outbox`),
    );
    return rows.length;
  } finally {
    await db.close();
  }
}

describe('漏えい：企業に送る SET（RP-50、RP-51）', () => {
  it('検証の SET は、割符の鍵の ES256 で署名され、aud は自分のテナント、jti はテナントをまたいで独立', async () => {
    // 攻撃者が持っている情報：2社の受け口に届いた SET（企業をまたいで突き合わせようとする者。テスト12の土台）
    // 試す経路：2社がそれぞれ検証の SET を頼み、届いた SET を /jwks の鍵で検証する
    // 期待する結果：typ は secevent+jwt、alg は ES256、iss は company-api、aud は各社のテナント ID。
    //               jti は128ビットの乱数で、2社で違う。events は検証のイベントと state だけ。sub も別名も入らない
    // plan 11章：テスト12の土台（突き合わせの防止は M9 で確かめる）
    const [a, b] = api.tenants;
    if (a === undefined || b === undefined) throw new Error('準備に失敗した');
    for (const [tenant, state] of [
      [a, 'state-a'],
      [b, 'state-b'],
    ] as const) {
      const token = await api.accessToken(tenant);
      const res = await api.request({ path: '/v1/events/verification', token, json: { state } });
      expect(res.status).toBe(202);
    }
    expect(await api.api.deliverDue()).toEqual({ delivered: 2, retry: 0, dropped: 0 });
    const jwks = (await api.request({ method: 'GET', path: '/jwks' })).json() as { keys: object[] };
    const received = sender.requests.slice(-2);
    expect(received.map((r) => r.url).sort()).toEqual(['/set/a', '/set/b']);
    const jtis = new Set<string>();
    for (const request of received) {
      expect(request.headers['content-type']).toBe('application/secevent+jwt');
      const tenant = request.url === '/set/a' ? a : b;
      const { payload, protectedHeader } = await jwtVerify(
        request.body,
        createLocalJWKSet(jwks as never),
        {
          algorithms: ['ES256'],
          issuer: 'http://localhost:4400',
          audience: tenant.tenantId,
          typ: 'secevent+jwt',
        },
      );
      expect(protectedHeader.alg).toBe('ES256');
      expect(Object.keys(payload).sort()).toEqual(['aud', 'events', 'iat', 'iss', 'jti']);
      expect(payload.events).toEqual({
        [VERIFICATION]: { state: tenant === a ? 'state-a' : 'state-b' },
      });
      expect(String(payload.jti)).toMatch(/^[A-Za-z0-9_-]{22}$/);
      jtis.add(String(payload.jti));
    }
    expect(jtis.size).toBe(2);
    expect(await outboxCount(a.tenantId)).toBe(0);
  });

  it('受け口が受け取らなければ、同じ jti で間を空けて送り直し、6回で諦める', async () => {
    // 攻撃者が持っている情報：自社の受け口を操れる立場（ATK-03）
    // 試す経路：受け口が 500 を返し続ける。時刻を進めながら送り直させる
    // 期待する結果：送り直しの SET の jti と iat は同じ。間を空ける前には送らない。6回で送信待ちから消え、
    //               ログには理由の種類と件数だけが残る（URL、SET を残さない）
    // plan 11章：番号なし（RFC 8935 の再送。ADR 0022）
    const [a] = api.tenants;
    if (a === undefined) throw new Error('準備に失敗した');
    sender.respondWith(500);
    const token = await api.accessToken(a);
    expect((await api.request({ path: '/v1/events/verification', token, json: {} })).status).toBe(
      202,
    );
    const before = sender.requests.length;
    const outcomes = [];
    for (let i = 0; i < 6; i += 1) {
      outcomes.push(await api.api.deliverDue());
      // 間を空ける前には、もう一度送らない。
      expect(await api.api.deliverDue()).toEqual({ delivered: 0, retry: 0, dropped: 0 });
      clock += 7 * 3_600_000;
    }
    expect(outcomes).toEqual([
      ...Array(5).fill({ delivered: 0, retry: 1, dropped: 0 }),
      { delivered: 0, retry: 0, dropped: 1 },
    ]);
    const bodies = sender.requests.slice(before).map((r) => r.body);
    expect(bodies).toHaveLength(6);
    const claims = bodies.map((body) =>
      JSON.parse(Buffer.from(body.split('.')[1] ?? '', 'base64url').toString('utf8')),
    );
    expect(new Set(claims.map((c) => c.jti)).size).toBe(1);
    expect(new Set(claims.map((c) => c.iat)).size).toBe(1);
    expect(await outboxCount(a.tenantId)).toBe(0);
    const logs = api.logs.join('\n');
    expect(logs).toContain('company_api.set_dropped');
    for (const needle of [WEBHOOK_HOST, '/set/a', ...bodies]) expect(logs).not.toContain(needle);
    sender.respondWith(202);
    clock = Date.now();
  });

  it('受け口を登録していないテナントは 409。DB には署名した SET を置かない', async () => {
    // 攻撃者が持っている情報：company-api の DB を読める立場（pg_dump、ATK-06）
    // 試す経路：受け口のないテナントで依頼する。送信待ちの表の列を見る
    // 期待する結果：409 webhook_not_registered。送信待ちの表に、SET や署名の列がない
    // plan 11章：テスト7の一部（トークン（SET）を平文で残さない）
    const [, , c] = api.tenants;
    if (c === undefined) throw new Error('準備に失敗した');
    const token = await api.accessToken(c);
    const res = await api.request({ path: '/v1/events/verification', token, json: { state: 's' } });
    expect([res.status, res.text]).toEqual([409, '{"error":"webhook_not_registered"}']);
    const db = await serviceDb('company-api');
    try {
      const rows = await db.withTenant(c.tenantId, (tx) =>
        tx.query<{ column_name: string }>(
          sql`SELECT column_name FROM information_schema.columns
               WHERE table_schema = 'company_api' AND table_name = 'set_outbox' ORDER BY column_name`,
        ),
      );
      expect(rows.map((r) => r.column_name)).toEqual([
        'attempts',
        'created_at',
        'deliver_after',
        'event_id',
        'event_type',
        'issued_at',
        'jti',
        'state',
        'tenant_id',
      ]);
    } finally {
      await db.close();
    }
  });
});
