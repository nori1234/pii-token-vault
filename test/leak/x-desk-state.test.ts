// 窓口の作成の正本の状態と保存期間（ADR 0026 の O-63、O-66、O-69。仕様案 v0.7 の D-08、D-13、D-40、D-43〜D-45）。
// 状態の変更は同じ行の中で原子的に決まり、再送は同じ結果を返し、食い違う報告は 409。終端でない行は期限が過ぎても
// 消さず、終端から7日で消す。M6 の受信箱の30日・90日の決まりは、窓口の項目には当てはめない。

import { randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { createDeskClient } from '../../packages/warifu-core/src/desk/client.ts';
import {
  parseTenantId,
  parseWarifuUserId,
  type TenantId,
  type WarifuUserId,
} from '../../packages/warifu-core/src/ids.ts';
import { userIdOf } from '../setup/approvals.ts';
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

const DAY = 24 * 3600 * 1000;
let world: DeskWorld;
let clock = Date.now();
let user: Awaited<ReturnType<typeof connectedUser>>;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0 }],
    now: () => new Date(clock),
  });
  user = await connectedUser(world, client());
});

afterAll(async () => {
  await world?.stop();
});

function client() {
  const found = world.t.clients[0];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

async function call(path: string, json: unknown) {
  const token = await world.company.accessToken(world.company.tenants[0] as never, 'desk');
  return world.company.request({ path, token, json });
}

async function approved() {
  clock += 1000;
  const detail = deskDetail(user.sub);
  const flow = await deskFlow(world, user, client(), detail);
  return {
    requestId: String(detail.identifier),
    changeId: String(decodeJwt(String(flow.approvalJwt)).change_id),
  };
}

async function changeRows(): Promise<{ state: string; purge_after: Date | null }[]> {
  const db = await serviceDb('company-api');
  try {
    return await db.withTenant(world.company.tenants[0]?.tenantId as TenantId, (tx) =>
      tx.query(sql`SELECT state, purge_after FROM company_api.desk_changes ORDER BY approved_at`),
    );
  } finally {
    await db.close();
  }
}

async function itemRows(): Promise<{ state: string; purge_after: Date | null }[]> {
  const db = await serviceDb('idp');
  try {
    return await db.withWarifuUser(userIdOf(user.browser.authenticator) as WarifuUserId, (tx) =>
      tx.query(sql`SELECT state, purge_after FROM idp.desk_items ORDER BY created_at`),
    );
  } finally {
    await db.close();
  }
}

describe('漏えい：窓口の作成の正本の状態と保存期間', () => {
  it('作成の知らせの再送は同じ結果を返し、別の申請との組み合わせは 409', async () => {
    // 攻撃者が持っている情報：企業の正規のトークン（scope desk）と、2つの変更の ID
    // 試す経路：同じ作成の知らせを2回送る。変更 A の ID と申請 B の ID を組み合わせて送る
    // 期待する結果：2回目も同じ 200 と同じ取消期限（期限は延びない）。組み合わせの差し替えは 409
    // plan 11章：番号なし（D-39、D-40）
    const a = await approved();
    const b = await approved();
    const first = await call('/v1/desk/change-notices', {
      request_id: a.requestId,
      change_id: a.changeId,
    });
    clock += 60_000;
    const again = await call('/v1/desk/change-notices', {
      request_id: a.requestId,
      change_id: a.changeId,
    });
    expect([again.status, again.json()]).toEqual([200, first.json()]);
    const swapped = await call('/v1/desk/change-notices', {
      request_id: b.requestId,
      change_id: a.changeId,
    });
    expect([swapped.status, swapped.text]).toEqual([409, '{"error":"conflict"}']);
  });

  it('未作成の報告は、作成の知らせの前だけ。再送は 204、作成の後は 409', async () => {
    // 攻撃者が持っている情報：企業の正規のトークン
    // 試す経路：承認を受けて作らなかった申請を、未作成と報告する（2回）。作成の知らせの後の申請も未作成と報告する
    // 期待する結果：知らせの前は 204 で、再送も 204。知らせの後は 409。受信箱は「作成されませんでした」
    // plan 11章：番号なし（D-43、D-44）
    const unused = await approved();
    expect(
      (
        await call('/v1/desk/execution-results', {
          request_id: unused.requestId,
          result: 'not_created',
        })
      ).status,
    ).toBe(204);
    expect(
      (
        await call('/v1/desk/execution-results', {
          request_id: unused.requestId,
          result: 'not_created',
        })
      ).status,
    ).toBe(204);
    const made = await approved();
    await call('/v1/desk/change-notices', { request_id: made.requestId, change_id: made.changeId });
    expect(
      (
        await call('/v1/desk/execution-results', {
          request_id: made.requestId,
          result: 'not_created',
        })
      ).status,
    ).toBe(409);
    await user.approval.approvalLogin();
    const states = (await deskItems(user.approval)).map((item) => item.state);
    expect(states).toContain('not_created');
  });

  it('取消の結果は、受理した取消の ID だけで、別の ID や取消のない変更は 409', async () => {
    // 攻撃者が持っている情報：企業の正規のトークン（虚偽の完了を報告したい企業）
    // 試す経路：取消のない変更に取消の結果を報告する。取消のある変更に、別の取消要求ID で報告する
    // 期待する結果：どちらも 409。正本の状態は変わらない
    // plan 11章：番号なし（D-31、D-32）
    const made = await approved();
    const plain = await call('/v1/desk/cancellation-results', {
      change_id: made.changeId,
      cancellation_id: 'A'.repeat(43),
      result: 'applied',
    });
    expect(plain.status).toBe(409);
    await user.approval.approvalLogin();
    const [item] = await deskItems(user.approval);
    expect((await cancelDeskItem(user.approval, String(item?.id))).status).toBe(200);
    const wrong = await call('/v1/desk/cancellation-results', {
      change_id: made.changeId,
      cancellation_id: 'B'.repeat(43),
      result: 'applied',
    });
    expect(wrong.status).toBe(409);
    const status = await call('/v1/desk/cancellation-status', { change_id: made.changeId });
    expect(status.json()).toEqual({ state: 'cancellation_pending' });
  });

  it('正本に記録できたのに idp が応答を受け取れなかった項目も、受信箱から取り消せる', async () => {
    // 攻撃者が持っている情報：なし（障害の場面。company-api が記録した直後に、idp への応答が失われた。ADR 0026 の O-63）
    // 試す経路：idp の項目を approving のまま置き、同じ内部のレコード ID で company-api の内部 API に承認を記録する
    //           （idp は応答を受け取らなかったことにする）。その後、利用者が承認用のオリジンで項目を読み、取り消す
    // 期待する結果：項目は「承認済み（作成の知らせ待ち）」で取り消せて、取消は 200。正本は取消の受理（企業には
    //               cancellation_pending）になる
    // plan 11章：番号なし（ADR 0026 の O-63「利用者は、受信箱の項目から取り消せる」）
    clock += 1000;
    const userId = parseWarifuUserId(userIdOf(user.browser.authenticator));
    const tenantId = parseTenantId(String(world.company.tenants[0]?.tenantId));
    const changeRef = randomUUID();
    const idp = await serviceDb('idp');
    try {
      await idp.withWarifuUser(userId, (tx) =>
        tx.execute(
          sql`INSERT INTO idp.desk_items (item_id, user_id, tenant_id, change_ref, action, state, created_at)
              VALUES (${randomUUID()}, ${userId}, ${tenantId}, ${changeRef}, 'desk.case.create', 'approving', ${new Date(clock)})`,
        ),
      );
    } finally {
      await idp.close();
    }
    const desk = createDeskClient({
      socketPath: world.deskSocketPath,
      credential: world.deskCredential,
    });
    const recorded = await desk.approve({
      tenantId,
      userId,
      changeRef,
      requestId: randomBytes(16).toString('base64url'),
      action: 'desk.case.create',
    });
    expect(recorded.ok).toBe(true);
    await user.approval.approvalLogin();
    const item = (await deskItems(user.approval)).find(
      (entry) => entry.state === 'awaiting_notice',
    );
    expect(item).toMatchObject({ cancellable: true });
    expect((await cancelDeskItem(user.approval, String(item?.id))).status).toBe(200);
    if (!recorded.ok) throw new Error('記録に失敗した');
    expect(
      (await call('/v1/desk/cancellation-status', { change_id: recorded.changeId })).json(),
    ).toEqual({
      state: 'cancellation_pending',
    });
  });

  it('終端でない行は、30日・90日を過ぎても消えず、受信箱から取り消せる', async () => {
    // 攻撃者が持っている情報：企業の作成の知らせを遅らせられる立場（D-45）
    // 試す経路：承認の後、作成の知らせも結果も来ないまま、100日を過ぎてから受信箱を読み、取り消す
    // 期待する結果：正本の行も idp の項目も残っていて、受信箱に「承認済み（作成の知らせ待ち）」が出て、取り消せる
    // plan 11章：番号なし（D-45。ADR 0026 の O-69）
    await approved();
    clock += 100 * DAY;
    await user.approval.approvalLogin();
    const [item] = await deskItems(user.approval);
    expect(item).toMatchObject({ state: 'awaiting_notice', cancellable: true });
    expect((await cancelDeskItem(user.approval, String(item?.id))).status).toBe(200);
  });

  it('終端の行は、終端から7日を過ぎたら、正本と idp の両方から消える', async () => {
    // 攻撃者が持っている情報：DB を後から読める立場（ATK-06）。古い窓口の記録を集めたい
    // 試す経路：未作成を報告して終端にした後、8日を過ぎてから、企業の窓口のルートと受信箱を使う
    // 期待する結果：終端の行は消える（正本も idp の項目も）。終端でない行は残る
    // plan 11章：番号なし（D-13。ADR 0026 の O-69）
    const ended = await approved();
    await call('/v1/desk/execution-results', {
      request_id: ended.requestId,
      result: 'not_created',
    });
    await user.approval.approvalLogin();
    await deskItems(user.approval);
    const terminalBefore = (await changeRows()).filter((row) => row.purge_after !== null).length;
    expect(terminalBefore).toBeGreaterThan(0);
    clock += 8 * DAY;
    // 消すのは、そのテナントの窓口の処理で行を書き換えるときと、受信箱を読むとき。
    await approved();
    await user.approval.approvalLogin();
    await deskItems(user.approval);
    await deskItems(user.approval);
    const changes = await changeRows();
    const items = await itemRows();
    // 8日前に終端になった行は、正本からも idp の項目からも消えた（消す予定の時刻を過ぎた行は残らない）。
    for (const row of [...changes, ...items]) {
      if (row.purge_after !== null) expect(row.purge_after.getTime()).toBeGreaterThan(clock);
    }
    expect(changes.filter((row) => row.purge_after !== null)).toHaveLength(0);
    // 終端でない行（取消を受理して、企業の結果を待っているもの）は残る。
    expect(changes.some((row) => row.state === 'cancel_requested')).toBe(true);
    expect(items.some((row) => row.state === 'approved')).toBe(true);
  });
});
