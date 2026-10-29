// 窓口の値を平文で残さない（不変条件4、plan 11章 テスト7の一部、ADR 0026 の O-64。仕様案 v0.7 の D-25）。
// 申請ID、変更ID、取消要求ID、操作ごとの承認の JWT、PAR の request_uri、取消の SET を、通常・拒否・失敗・再送の
// 経路に通し、DB の行（idp と company-api の境界で読めるすべての窓口の表と監査ログ）と、idp・company-api・sender の
// ログを検索する。

import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { TenantId, WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { userIdOf } from '../setup/approvals.ts';
import { serviceDb } from '../setup/db.ts';
import {
  approveDesk,
  arriveAtDesk,
  cancelDeskItem,
  connectedUser,
  type DeskWorld,
  deskDetail,
  deskItems,
  pushRequest,
  startDeskWorld,
} from '../setup/desk.ts';

let world: DeskWorld;
let clock = Date.now();

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0 }],
    now: () => new Date(clock),
  });
});

afterAll(async () => {
  await world?.stop();
});

/** 窓口の表と監査ログの行を、テキストにして返す（アプリと同じ境界で読む）。 */
async function dumpRows(tenantId: TenantId, userIds: readonly WarifuUserId[]): Promise<string> {
  const out: string[] = [];
  const company = await serviceDb('company-api');
  try {
    await company.withTenant(tenantId, async (tx) => {
      for (const statement of [
        sql`SELECT row_to_json(t)::text AS line FROM company_api.desk_changes AS t`,
        sql`SELECT row_to_json(t)::text AS line FROM company_api.set_outbox AS t`,
        sql`SELECT row_to_json(t)::text AS line FROM audit.events AS t`,
      ]) {
        for (const row of await tx.query<{ line: string }>(statement)) out.push(row.line);
      }
    });
  } finally {
    await company.close();
  }
  const idp = await serviceDb('idp');
  try {
    for (const userId of userIds) {
      await idp.withWarifuUser(userId, async (tx) => {
        for (const statement of [
          sql`SELECT row_to_json(t)::text AS line FROM idp.desk_items AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.inbox AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM audit.events AS t`,
        ]) {
          for (const row of await tx.query<{ line: string }>(statement)) out.push(row.line);
        }
      });
    }
    await idp.withTenant(tenantId, async (tx) => {
      for (const row of await tx.query<{ line: string }>(
        sql`SELECT row_to_json(t)::text AS line FROM audit.events AS t`,
      )) {
        out.push(row.line);
      }
    });
  } finally {
    await idp.close();
  }
  return out.join('\n');
}

describe('漏えい：窓口の値を平文で残さない（不変条件4）', () => {
  it('承認、拒否、失敗、再送、取消の後の DB とログに、申請ID・変更ID・取消要求ID・JWT・request_uri・SET がない', async () => {
    // 攻撃者が持っている情報：割符の DB を読める立場（pg_dump、ATK-06）と、各サービスのログを読める立場
    // 試す経路：作成の承認と、作成の知らせ（2回）と、取消と、取消の SET の配送（set_too_old の後の送り直しを含む）と、
    //           取消の結果の報告を行う。別の申請を「心当たりがない」で終える。別の利用者で承認に失敗する。
    //           企業向けのルートに、知らない ID と形の違う本文を送る。その後で、DB の行とログを検索する
    // 期待する結果：どの値も、DB の行にもログにも出ない（照合用の MAC だけが残る）
    // plan 11章：テスト7の一部（D-25）
    const client = world.t.clients[0];
    const tenant = world.company.tenants[0];
    if (client === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const user = await connectedUser(world, client);
    const other = await connectedUser(world, client);
    const needles: string[] = [];

    // 承認、作成の知らせ（再送を含む）、取消、配送、結果の報告。
    const detail = deskDetail(user.sub);
    needles.push(String(detail.identifier));
    const par = await pushRequest(world.t, client, [detail]);
    needles.push(String(par.requestUri));
    const arrived = await arriveAtDesk(user.browser, client, String(par.requestUri));
    const approved = await approveDesk(user.approval, String(arrived.uid));
    const finished = await user.browser.follow(String(approved.json.redirectTo));
    const { redeemCode } = await import('../setup/idp.ts');
    const redeemed = await redeemCode(
      world.t,
      client,
      finished.external as URL,
      par.verifier,
      par.state,
    );
    const jwt = String(
      (redeemed.tokenResponse.authorization_details as { approval: string }[])[0]?.approval,
    );
    needles.push(jwt, redeemed.idToken);
    const changeId = String(decodeJwt(jwt).change_id);
    needles.push(changeId);
    const token = await world.company.accessToken(tenant, 'desk');
    for (let i = 0; i < 2; i += 1) {
      await world.company.request({
        path: '/v1/desk/change-notices',
        token,
        json: { request_id: detail.identifier, change_id: changeId },
      });
    }
    await user.approval.approvalLogin();
    const [item] = await deskItems(user.approval);
    await cancelDeskItem(user.approval, String(item?.id));
    clock += 61_000;
    world.sender.respondWith(
      400,
      { 'content-type': 'application/json' },
      JSON.stringify({ err: 'invalid_request', warifu_reason: 'set_too_old' }),
    );
    const before = world.sender.requests.length;
    await world.company.api.deliverDue();
    clock += 6000;
    world.sender.respondWith(202);
    await world.company.api.deliverDue();
    const sets = world.sender.requests.slice(before).map((r) => r.body);
    expect(sets).toHaveLength(2);
    needles.push(...sets);
    const cancellationId = String(
      (decodeJwt(String(sets[1])).events as Record<string, Record<string, string>>)[
        'urn:warifu:secevent:desk-cancellation'
      ]?.cancellation_id,
    );
    needles.push(cancellationId);
    await world.company.request({
      path: '/v1/desk/cancellation-results',
      token,
      json: { change_id: changeId, cancellation_id: cancellationId, result: 'applied' },
    });

    // 心当たりがない、別の利用者の失敗、知らない ID と形の違う本文。
    const declined = deskDetail(user.sub);
    needles.push(String(declined.identifier));
    const par2 = await pushRequest(world.t, client, [declined]);
    needles.push(String(par2.requestUri));
    const arrived2 = await arriveAtDesk(user.browser, client, String(par2.requestUri));
    await user.approval.post('/api/desk/decline', { uid: arrived2.uid, reason: 'unrecognized' });
    const failed = deskDetail(user.sub);
    needles.push(String(failed.identifier));
    const par3 = await pushRequest(world.t, client, [failed]);
    needles.push(String(par3.requestUri));
    const arrived3 = await arriveAtDesk(other.browser, client, String(par3.requestUri));
    await approveDesk(other.approval, String(arrived3.uid));
    const bogus = `${changeId.slice(0, 40)}xyz`;
    needles.push(bogus);
    await world.company.request({
      path: '/v1/desk/cancellation-status',
      token,
      json: { change_id: bogus },
    });
    await world.company.request({
      path: '/v1/desk/change-notices',
      token,
      json: { request_id: failed.identifier, change_id: changeId, extra: failed.identifier },
    });

    const rows = await dumpRows(tenant.tenantId, [
      userIdOf(user.browser.authenticator) as WarifuUserId,
      userIdOf(other.browser.authenticator) as WarifuUserId,
    ]);
    expect(rows).toContain('desk');
    const logs = [...world.t.logLines(), ...world.company.logs, ...world.sender.logs].join('\n');
    // 検索するログが、窓口の処理のログを実際に含んでいることを先に確かめる（空のログで通らないように）。
    for (const event of [
      'idp.desk_approved',
      'idp.desk_cancel_requested',
      'company_api.desk_change_recorded',
      'company_api.desk_cancel_accepted',
      'sender.webhook_delivered',
    ]) {
      expect(logs).toContain(event);
    }
    for (const needle of needles) {
      expect(needle.length).toBeGreaterThan(20);
      expect([needle.slice(0, 12), rows.includes(needle)]).toEqual([needle.slice(0, 12), false]);
      expect([needle.slice(0, 12), logs.includes(needle)]).toEqual([needle.slice(0, 12), false]);
    }
  });
});
