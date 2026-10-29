// テスト12：窓口の取消の SET の配送（plan 11章 テスト12、ADR 0026 の O-67。仕様案 v0.7 の D-14、D-21、D-26〜D-28、D-32）。
// 取消は受理した時点で有効で、配送の失敗で失わない。202 だけを配送できたことにし、set_too_old は新しい jti と iat で
// 送り直し、時計・認証・形式の失敗は保留する。2社に送る SET からは、受理の時刻や jti で突き合わせられない。

import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import { serviceDb } from '../setup/db.ts';
import {
  cancelDeskItem,
  connectedUser,
  type DeskWorld,
  deskDetail,
  deskFlow,
  deskItems,
  startDeskWorld,
} from '../setup/desk.ts';
import { codeFlow } from '../setup/idp.ts';

const DESK_CANCELLATION = 'urn:warifu:secevent:desk-cancellation';
const JSON_TYPE = { 'content-type': 'application/json' };
let world: DeskWorld;
let clock = Date.now();
let user: Awaited<ReturnType<typeof connectedUser>>;
const subs: string[] = [];

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [{ tenant: 0 }, { tenant: 1 }],
    now: () => new Date(clock),
  });
  user = await connectedUser(world, client(0));
  subs.push(user.sub);
  subs.push(
    String((await codeFlow(world.t, user.browser, client(1), { mode: 'session' })).claims.sub),
  );
});

afterAll(async () => {
  await world?.stop();
});

function client(index: number) {
  const found = world.t.clients[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

/** 作成を承認させ、利用者が取り消す。変更ID を返す。 */
async function cancelledChange(index = 0): Promise<string> {
  // 受信箱の項目は新しい順。同じ時刻に作ると順が決まらないので、時計を進めておく。
  clock += 1000;
  const flow = await deskFlow(world, user, client(index), deskDetail(subs[index] ?? ''));
  if (flow.approvalJwt === undefined) {
    throw new Error(`承認できない（${flow.approve.status} ${flow.approve.text}）`);
  }
  await user.approval.approvalLogin();
  const [item] = await deskItems(user.approval);
  const result = await cancelDeskItem(user.approval, String(item?.id));
  if (result.status !== 200) throw new Error(`取り消せない（${result.status}）`);
  return String(decodeJwt(String(flow.approvalJwt)).change_id);
}

interface OutboxRow {
  event_type: string;
  deliver_after: Date;
  attempts: number;
  held: boolean;
  reissues: number;
  jti: string | null;
}

async function outbox(index = 0): Promise<OutboxRow[]> {
  const db = await serviceDb('company-api');
  try {
    return await db.withTenant(world.company.tenants[index]?.tenantId as TenantId, (tx) =>
      tx.query<OutboxRow>(
        sql`SELECT event_type, deliver_after, attempts, held, reissues, jti FROM company_api.set_outbox
             WHERE event_type = 'desk_cancellation' ORDER BY deliver_after`,
      ),
    );
  } finally {
    await db.close();
  }
}

async function clearOutbox(): Promise<void> {
  const db = await serviceDb('company-api');
  try {
    for (const tenant of world.company.tenants) {
      await db.withTenant(tenant.tenantId, (tx) =>
        tx.execute(sql`DELETE FROM company_api.set_outbox WHERE event_type = 'desk_cancellation'`),
      );
    }
  } finally {
    await db.close();
  }
}

function eventOf(set: string) {
  const claims = decodeJwt(set);
  return {
    claims,
    event: (claims.events as Record<string, Record<string, string>>)[DESK_CANCELLATION],
  };
}

async function deliver() {
  return world.company.api.deliverDue();
}

describe('漏えい：窓口の取消の SET の配送（plan 11章 テスト12）', () => {
  it('初めて送るのは受理から0〜60秒の後で、2社の SET の jti と送る時刻は独立している', async () => {
    // 攻撃者が持っている情報：2社に届いた取消の SET（企業をまたいで、同じ利用者の取消を突き合わせようとする者）
    // 試す経路：同じ利用者が、2社の作成をそれぞれ取り消す。送信待ちの送る時刻と、届いた SET を比べる
    // 期待する結果：送る時刻は受理から0〜60秒の間で、送るたびに独立の乱数。SET の aud は各社のテナント、jti は別、
    //               中身に受理の時刻はない（変更ID、取消要求ID、within_window だけ）。exp はない
    // plan 11章：テスト12（D-14）
    await clearOutbox();
    world.sender.respondWith(202);
    await cancelledChange(0);
    const firstAccepted = clock;
    await cancelledChange(1);
    const secondAccepted = clock;
    const delays = [
      ...(await outbox(0)).map((row) => row.deliver_after.getTime() - firstAccepted),
      ...(await outbox(1)).map((row) => row.deliver_after.getTime() - secondAccepted),
    ];
    expect(delays).toHaveLength(2);
    for (const delay of delays) {
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(60_000);
    }
    clock += 61_000;
    const before = world.sender.requests.length;
    expect((await deliver()).delivered).toBe(2);
    const sets = world.sender.requests.slice(before).map((r) => eventOf(r.body));
    expect(sets.map((s) => s.claims.aud).sort()).toEqual(
      world.company.tenants.map((t) => t.tenantId).sort(),
    );
    expect(new Set(sets.map((s) => s.claims.jti)).size).toBe(2);
    for (const { claims, event } of sets) {
      expect(claims).not.toHaveProperty('exp');
      expect(Object.keys(event ?? {}).sort()).toEqual(['accepted', 'cancellation_id', 'change_id']);
      expect(event?.accepted).toBe('within_window');
    }
  });

  it('受け口が set_too_old で断ると、同じ取消を新しい jti と iat で送り直し、適用は1回', async () => {
    // 攻撃者が持っている情報：配送の経路を遅らせられる立場（受け口の受信の規則の300秒を超えさせる）
    // 試す経路：受け口が 400 {"err":"invalid_request","warifu_reason":"set_too_old"} を返す。次は 202 を返す
    // 期待する結果：送り直した SET は、jti と iat が新しく、変更ID と取消要求ID は同じ。取消は失われない
    // plan 11章：テスト12（D-21、D-26）
    await clearOutbox();
    await cancelledChange(0);
    clock += 61_000;
    world.sender.respondWith(
      400,
      JSON_TYPE,
      JSON.stringify({ err: 'invalid_request', description: 'x', warifu_reason: 'set_too_old' }),
    );
    const before = world.sender.requests.length;
    expect((await deliver()).reissue).toBe(1);
    // 同じ回の中では送り直さない。5秒の後に、新しい jti と iat で送る。
    expect((await deliver()).delivered).toBe(0);
    clock += 6000;
    world.sender.respondWith(202);
    expect((await deliver()).delivered).toBe(1);
    const [first, second] = world.sender.requests.slice(before).map((r) => eventOf(r.body));
    expect(second?.claims.jti).not.toBe(first?.claims.jti);
    expect(Number(second?.claims.iat)).toBeGreaterThan(Number(first?.claims.iat));
    expect(second?.event).toEqual(first?.event);
    expect(await outbox(0)).toEqual([]);
  });

  it('set_too_old が3回続くと保留にし、それ以上は自動で送らない。取消は受理されたまま', async () => {
    // 攻撃者が持っている情報：受け口の時計を狂わせられる立場（ATK-03）。再署名を繰り返させたい
    // 試す経路：受け口が、何度送っても set_too_old を返す
    // 期待する結果：3回で保留になり、その後は送らない。正本は cancel_requested のままで、企業の照会は
    //               cancellation_pending（取消の権利は失われない）
    // plan 11章：テスト12（D-26）
    await clearOutbox();
    const changeId = await cancelledChange(0);
    clock += 61_000;
    world.sender.respondWith(
      400,
      JSON_TYPE,
      JSON.stringify({ err: 'invalid_request', warifu_reason: 'set_too_old' }),
    );
    const outcomes = [];
    for (let i = 0; i < 3; i += 1) {
      outcomes.push(await deliver());
      clock += 6000;
    }
    expect(outcomes.map((o) => [o.reissue, o.held])).toEqual([
      [1, 0],
      [1, 0],
      [0, 1],
    ]);
    const before = world.sender.requests.length;
    clock += 7 * 3_600_000;
    await deliver();
    expect(world.sender.requests.length).toBe(before);
    expect(await outbox(0)).toEqual([expect.objectContaining({ held: true, reissues: 3 })]);
    const token = await world.company.accessToken(world.company.tenants[0] as never, 'desk');
    const status = await world.company.request({
      path: '/v1/desk/cancellation-status',
      json: { change_id: changeId },
      token,
    });
    expect(status.json()).toEqual({ state: 'cancellation_pending' });
  });

  it.each([
    [
      'iat_in_future の 400',
      400,
      JSON.stringify({ err: 'invalid_request', warifu_reason: 'iat_in_future' }),
    ],
    ['ほかの 400', 400, JSON.stringify({ err: 'invalid_key' })],
    ['401', 401, '{}'],
    ['202 でない 2xx（200）', 200, '{}'],
  ] as const)('%s は保留にする（自動で送り直さない）', async (_name, status, body) => {
    // 攻撃者が持っている情報：受け口を操れる立場（ATK-03）。契約の外の応答で、取消を済んだことにさせたい
    // 試す経路：受け口が、時刻の未来側の失敗、ほかの形の失敗、認証の失敗、202 以外の成功を返す
    // 期待する結果：どれも保留（held）。送信待ちは消さず、配送できたことにもしない
    // plan 11章：テスト12（D-28）
    await clearOutbox();
    await cancelledChange(0);
    clock += 61_000;
    world.sender.respondWith(status, JSON_TYPE, body);
    const result = await deliver();
    expect([result.delivered, result.held]).toEqual([0, 1]);
    expect(await outbox(0)).toEqual([expect.objectContaining({ held: true })]);
    world.sender.respondWith(202);
  });

  it('5xx が続いても諦めずに送り直し、間が空いたら新しい iat で送る', async () => {
    // 攻撃者が持っている情報：受け口を止められる立場（企業の障害、または妨害）
    // 試す経路：受け口が 503 を返し続ける（検証の SET なら6回で諦める回数を超える）。最後に 202 を返す
    // 期待する結果：諦めて消すことはなく、毎回 retry。届いた SET の iat は、送った時刻に近い（4分より古い iat は
    //               送らない）。取消は1回だけ届いたことになる
    // plan 11章：テスト12（D-27、D-28）
    await clearOutbox();
    await cancelledChange(0);
    clock += 61_000;
    world.sender.respondWith(503);
    for (let i = 0; i < 8; i += 1) {
      const result = await deliver();
      expect([result.retry, result.dropped]).toEqual([1, 0]);
      // 間は最長6時間に、20% までの揺らぎを足したもの。
      clock += 8 * 3_600_000;
    }
    world.sender.respondWith(202);
    const before = world.sender.requests.length;
    expect((await deliver()).delivered).toBe(1);
    const [last] = world.sender.requests.slice(before).map((r) => eventOf(r.body));
    expect(Math.abs(Number(last?.claims.iat) - Math.floor(clock / 1000))).toBeLessThanOrEqual(1);
    expect(await outbox(0)).toEqual([]);
  });

  it('取消の結果の報告が 202 より先に届いても、状態は戻らない', async () => {
    // 攻撃者が持っている情報：配送の順序を入れ替えられる立場
    // 試す経路：SET を送る前に、企業が取消の適用を報告する（取消要求ID は、送る前の SET と同じ値を、テストの中で
    //           先に得る）。その後で SET が 202 で届く
    // 期待する結果：報告で cancelled になり、後の配送で cancellation_pending に戻らない
    // plan 11章：テスト12（D-32）
    await clearOutbox();
    const changeId = await cancelledChange(0);
    clock += 61_000;
    world.sender.respondWith(500);
    const before = world.sender.requests.length;
    await deliver();
    const [early] = world.sender.requests.slice(before).map((r) => eventOf(r.body));
    const token = await world.company.accessToken(world.company.tenants[0] as never, 'desk');
    const reported = await world.company.request({
      path: '/v1/desk/cancellation-results',
      json: {
        change_id: changeId,
        cancellation_id: early?.event?.cancellation_id,
        result: 'applied',
      },
      token,
    });
    expect(reported.status).toBe(204);
    world.sender.respondWith(202);
    clock += 2 * 60_000;
    expect((await deliver()).delivered).toBe(1);
    const status = await world.company.request({
      path: '/v1/desk/cancellation-status',
      json: { change_id: changeId },
      token,
    });
    expect(status.json()).toEqual({ state: 'cancelled' });
  });

  it('ログに、変更ID、取消要求ID、SET を出さない', async () => {
    // 攻撃者が持っている情報：company-api と sender のログを読める立場（ATK-06）
    // 試す経路：取消の SET を送った後の、company-api と sender のログを検索する
    // 期待する結果：変更ID、取消要求ID、SET の本文は出ない
    // plan 11章：テスト12（テスト7の一部。不変条件4）
    await clearOutbox();
    const changeId = await cancelledChange(0);
    clock += 61_000;
    const before = world.sender.requests.length;
    await deliver();
    const [sent] = world.sender.requests.slice(before);
    const { event } = eventOf(String(sent?.body));
    const logs = [...world.company.logs, ...world.sender.logs, ...world.t.logLines()].join('\n');
    for (const needle of [changeId, String(event?.cancellation_id), String(sent?.body)]) {
      expect(logs).not.toContain(needle);
    }
  });
});
