// テスト1：窓口の操作別承認と、中継の詐欺（plan 11章 テスト1、ADR 0019、ADR 0026）。
// 攻撃者が被害者の sub・別名・氏名・予約番号を知っていても、被害者のパスキーの承認なしには、窓口の担当者に許可が
// 渡らないこと。相手からの電話で求められたら承認を中止すること。承認できるのは照会と一般問い合わせの作成だけで、
// 高リスクの操作には使えないこと。作成は全端末の受信箱に知らされ、取消が企業に届くことを確かめる。
// 企業の側（受付番号、担当者の画面、対象の固定）はテストの中の企業の役が行う（M9 で demo-rp と rp-kit にする）。

import { createLocalJWKSet, decodeJwt, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { serviceDb } from '../setup/db.ts';
import {
  approveDesk,
  arriveAtDesk,
  cancelDeskItem,
  connectedUser,
  type DeskWorld,
  deskDetail,
  deskFlow,
  deskItems,
  pushRequest,
  pwaLogin,
  startDeskWorld,
  verifyOpApproval,
} from '../setup/desk.ts';

const DESK_CANCELLATION = 'urn:warifu:secevent:desk-cancellation';
let world: DeskWorld;
let clock = Date.now();
/** 被害者と攻撃者（アカウントの作成には IP ごとの上限があるので、ファイルの中で使い回す）。 */
let victim: Awaited<ReturnType<typeof connectedUser>>;
let attacker: Awaited<ReturnType<typeof connectedUser>>;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0 }],
    now: () => new Date(clock),
  });
  victim = await connectedUser(world, client());
  attacker = await connectedUser(world, client());
});

afterAll(async () => {
  await world?.stop();
});

function client() {
  const found = world.t.clients[0];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

function companyTenant() {
  const found = world.company.tenants[0];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

async function companyCall(path: string, json: unknown) {
  const token = await world.company.accessToken(companyTenant(), 'desk');
  return world.company.request({ path, token, json });
}

async function deskRowCount(): Promise<number> {
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(companyTenant().tenantId, (tx) =>
      tx.query(sql`SELECT change_ref FROM company_api.desk_changes`),
    );
    return rows.length;
  } finally {
    await db.close();
  }
}

describe('漏えい：窓口の操作別承認と中継（plan 11章 テスト1）', () => {
  it('被害者の sub を知っていても、攻撃者自身の割符の承認では、担当者に許可が渡らない', async () => {
    // 攻撃者が持っている情報：被害者の sub、別名、氏名、予約番号（漏れた企業のデータ）と、攻撃者自身の割符の
    //                       アカウント。企業の窓口に、被害者を名乗って連絡する
    // 試す経路：窓口が被害者の sub で申請を作り、PAR で送る。攻撃者が自分のブラウザで request_uri を開き、
    //           承認用のオリジンで、自分のパスキーで承認する（3回まで）
    // 期待する結果：sub が申請の subject と違うので、どれも 401 の同じ応答。3回の後は承認の選択肢も出ない。
    //               操作ごとの承認は作られず、企業には access_denied が返る。正本にも受信箱にも行は増えない
    // plan 11章：テスト1（D-30、D-11）
    const before = await deskRowCount();
    const par = await pushRequest(world.t, client(), [deskDetail(victim.sub)]);
    expect(par.status).toBe(201);
    const arrived = await arriveAtDesk(attacker.browser, client(), String(par.requestUri));
    expect(arrived.uid).toBeDefined();
    const uid = String(arrived.uid);
    for (let i = 0; i < 3; i += 1) {
      const result = await approveDesk(attacker.approval, uid);
      expect([result.status, result.text]).toEqual([401, '{"error":"failed"}']);
    }
    const blocked = await attacker.approval.post('/api/desk/approve/options', {
      uid,
      call: 'self',
    });
    expect(blocked.status).toBe(400);
    const finished = await attacker.browser.follow(`/interaction/${uid}/desk/finish`);
    expect(finished.external?.searchParams.get('error')).toBe('access_denied');
    expect(finished.external?.searchParams.get('code')).toBeNull();
    expect(await deskRowCount()).toBe(before);
    await attacker.approval.approvalLogin();
    expect(await deskItems(attacker.approval)).toEqual([]);
  });

  it('相手からかかってきた電話だと答えると、承認を中止し、企業には access_denied が返る', async () => {
    // 攻撃者が持っている情報：攻撃者が自分で得た受付番号。企業を名乗って被害者に電話し、その番号を被害者の
    //                       企業アプリに入力させた（中継の詐欺。D-38）
    // 試す経路：被害者の企業アプリが申請を作り、被害者が承認用のオリジンを開く。問いに「はい、相手から
    //           かかってきました」と答える。続けて、問いに答えないまま承認の選択肢を求める
    // 期待する結果：申請は承認しないで終わり、企業には access_denied（理由は区別しない）。問いに「自分から」と
    //               答えない要求には、承認の選択肢を出さない（400）。操作ごとの承認は作られない
    // plan 11章：テスト1（D-38）
    const par = await pushRequest(world.t, client(), [deskDetail(victim.sub)]);
    const { uid } = await arriveAtDesk(victim.browser, client(), String(par.requestUri));
    const skipped = await victim.approval.post('/api/desk/approve/options', { uid });
    expect(skipped.status).toBe(400);
    const declined = await victim.approval.post('/api/desk/decline', {
      uid,
      reason: 'incoming_call',
    });
    expect(declined.status).toBe(200);
    const after = await approveDesk(victim.approval, String(uid));
    expect(after.status).toBe(400);
    const finished = await victim.browser.follow(String(declined.json.redirectTo));
    expect(finished.external?.searchParams.get('error')).toBe('access_denied');
    expect(finished.external?.searchParams.get('code')).toBeNull();
  });

  it.each(['denied', 'unrecognized'])(
    '「承認しない」「心当たりがない」（%s）も、パスキーなしで申請を終え、access_denied になる',
    async (reason) => {
      // 攻撃者が持っている情報：攻撃者が作らせた申請（被害者の企業アプリに受付番号を入力させた）
      // 試す経路：被害者が承認用のオリジンで「承認しない」か「心当たりがない」を選ぶ
      // 期待する結果：企業には access_denied。理由の違いは企業に返さない（監査にだけ残す）
      // plan 11章：テスト1（D-35）
      const par = await pushRequest(world.t, client(), [deskDetail(victim.sub)]);
      const { uid } = await arriveAtDesk(victim.browser, client(), String(par.requestUri));
      const declined = await victim.approval.post('/api/desk/decline', { uid, reason });
      const finished = await victim.browser.follow(String(declined.json.redirectTo));
      expect(finished.external?.searchParams.get('error')).toBe('access_denied');
      expect(finished.external?.searchParams.get('error_description')).toBe(
        'the end-user did not approve the request',
      );
    },
  );

  it('窓口の申請で、高リスクの操作や、決めていない操作は求められない', async () => {
    // 攻撃者が持っている情報：企業の窓口の担当者の立場（または企業のサーバーを操れる立場。ATK-03）
    // 試す経路：返金、届け先の変更、解約、パスキーの変更、種別の変更など、決めていない操作の名前で PAR を送る
    // 期待する結果：どれも PAR の受け口で invalid_authorization_details（400）。request_uri は出ない
    // plan 11章：テスト1（D-03、D-06、D-16、D-36）
    for (const action of [
      'desk.refund.create',
      'desk.address.update',
      'desk.contract.cancel',
      'desk.passkey.update',
      'desk.case.category.update',
      'desk.case.language.update',
      'delivery.change',
    ]) {
      const par = await pushRequest(world.t, client(), [
        deskDetail(victim.sub, { actions: [action] }),
      ]);
      expect([action, par.status, par.body.error]).toEqual([
        action,
        400,
        'invalid_authorization_details',
      ]);
      expect(par.requestUri).toBeUndefined();
    }
  });

  it('照会の承認は、用途 desk のその1操作だけに結び付き、変更ID を持たない', async () => {
    // 攻撃者が持っている情報：利用者が窓口の照会のために承認した、操作ごとの承認の JWT（担当者の手元で漏れた）
    // 試す経路：JWT の中身を読み、高リスクの操作や作成に使えるかを、企業の側の検査で確かめる
    // 期待する結果：purpose は desk、action は照会の1つ、request_id は企業の申請。change_id はない。
    //               期限は5分。ID トークンの鍵では検証できない（ID トークンとしても使えない）
    // plan 11章：テスト1（D-09、D-22、D-36）
    const user = victim;
    const detail = deskDetail(user.sub, { actions: ['desk.order.status.read'] });
    delete detail.choices;
    const flow = await deskFlow(world, user, client(), detail);
    expect(flow.approvalJwt).toBeDefined();
    const payload = await verifyOpApproval(world.t, String(flow.approvalJwt), {
      clientId: client().clientId,
    });
    expect(payload).toMatchObject({
      purpose: 'desk',
      action: 'desk.order.status.read',
      request_id: detail.identifier,
      sub: user.sub,
    });
    expect(payload).not.toHaveProperty('change_id');
    expect(Number(payload.exp) - Number(payload.iat)).toBe(300);
    const idTokenKeys = (await (await fetch(`${world.t.issuer}/jwks`)).json()) as JSONWebKeySet;
    await expect(
      jwtVerify(String(flow.approvalJwt), createLocalJWKSet(idTokenKeys), {
        algorithms: ['ES256'],
      }),
    ).rejects.toThrow();
    // ID トークンには、承認の中身を入れない（取り違えない）。
    expect(flow.claims).not.toHaveProperty('purpose');
    expect(flow.claims).not.toHaveProperty('request_id');
  });

  it('作成は、全端末の受信箱に知らされ、利用者がパスキーで取り消すと、取消の SET が企業に届く', async () => {
    // 攻撃者が持っている情報：中継の詐欺で、被害者に一般問い合わせの作成を承認させた（D-38 の残るリスク）
    // 試す経路：作成を承認させ、企業が作成の知らせを送る。被害者が受信箱を見て、承認用のオリジンでパスキーで
    //           取り消す。企業は SET を受け、取消の適用を報告する
    // 期待する結果：受信箱（PWA と承認用のオリジン）に「作成されました」と取消期限（知らせから24時間）が出る。
    //               取消は受理され、SET（変更ID、取消要求ID、within_window。exp なし）が企業の受け口に届く。
    //               報告の後、受信箱は「取り消しました」、企業の照会は cancelled
    // plan 11章：テスト1（D-07、D-10、D-14）
    const detail = deskDetail(victim.sub);
    // 受信箱の項目は新しい順。同じ時刻に作ると順が決まらないので、時計を進めておく。
    clock += 1000;
    const flow = await deskFlow(world, victim, client(), detail);
    const payload = await verifyOpApproval(world.t, String(flow.approvalJwt), {
      clientId: client().clientId,
    });
    const changeId = String(payload.change_id);
    expect(changeId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const noticeAt = clock;
    const notice = await companyCall('/v1/desk/change-notices', {
      request_id: detail.identifier,
      change_id: changeId,
    });
    expect(notice.status).toBe(200);
    expect(notice.json()).toEqual({
      state: 'window_open',
      cancel_deadline: new Date(noticeAt + 24 * 3600 * 1000).toISOString(),
    });
    expect((await pwaLogin(victim.browser)).status).toBe(200);
    const pwa = await victim.browser.get('/api/inbox');
    expect(pwa.json.desk).toEqual([
      expect.objectContaining({
        company: 'テスト企業1',
        operation: '一般問い合わせを作成する',
        state: 'created',
        cancellable: true,
        cancelDeadline: new Date(noticeAt + 24 * 3600 * 1000).toISOString(),
        warning: 'E',
      }),
    ]);
    await victim.approval.approvalLogin();
    const [item] = await deskItems(victim.approval);
    const cancelled = await cancelDeskItem(victim.approval, String(item?.id));
    expect([cancelled.status, cancelled.json]).toEqual([
      200,
      { ok: true, state: 'cancel_requested' },
    ]);
    // 初めて送るのは、受理から0〜60秒の後。
    clock += 61_000;
    const before = world.sender.requests.length;
    expect((await world.company.api.deliverDue()).delivered).toBe(1);
    const [received] = world.sender.requests.slice(before);
    const companyKeys = (await world.company.request({ method: 'GET', path: '/jwks' })).json() as {
      keys: object[];
    };
    const { payload: set, protectedHeader } = await jwtVerify(
      String(received?.body),
      createLocalJWKSet({ keys: companyKeys.keys as never }),
      { algorithms: ['ES256'], audience: companyTenant().tenantId, typ: 'secevent+jwt' },
    );
    expect(protectedHeader.typ).toBe('secevent+jwt');
    expect(set).not.toHaveProperty('exp');
    const event = (set.events as Record<string, Record<string, string>>)[DESK_CANCELLATION];
    expect(event).toEqual({
      change_id: changeId,
      cancellation_id: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      accepted: 'within_window',
    });
    const reported = await companyCall('/v1/desk/cancellation-results', {
      change_id: changeId,
      cancellation_id: event?.cancellation_id,
      result: 'applied',
    });
    expect(reported.status).toBe(204);
    const status = await companyCall('/v1/desk/cancellation-status', { change_id: changeId });
    expect(status.json()).toEqual({ state: 'cancelled' });
    expect((await deskItems(victim.approval))[0]).toMatchObject({
      state: 'cancelled',
      cancellable: false,
    });
  });

  it('作成の知らせの前に取り消すと、後から来た知らせで状態が戻らない', async () => {
    // 攻撃者が持っている情報：中継で承認させた作成（企業の作成の知らせが遅れている。D-42）
    // 試す経路：承認の直後、知らせの前に、被害者が受信箱から取り消す。その後で、企業の作成の知らせが届く
    // 期待する結果：取消は受理される（作成の知らせ待ちでも取り消せる）。後から来た知らせは記録するが、状態は
    //               cancellation_pending のまま。企業は未作成を報告でき、受信箱は「作成されませんでした」
    // plan 11章：テスト1（D-42、D-43）
    const detail = deskDetail(victim.sub);
    // 受信箱の項目は新しい順。同じ時刻に作ると順が決まらないので、時計を進めておく。
    clock += 1000;
    const flow = await deskFlow(world, victim, client(), detail);
    const { change_id: changeId } = decodeJwt(String(flow.approvalJwt));
    await victim.approval.approvalLogin();
    const [item] = await deskItems(victim.approval);
    expect(item).toMatchObject({ state: 'awaiting_notice', cancellable: true });
    expect((await cancelDeskItem(victim.approval, String(item?.id))).status).toBe(200);
    const late = await companyCall('/v1/desk/change-notices', {
      request_id: detail.identifier,
      change_id: changeId,
    });
    expect(late.status).toBe(200);
    expect((late.json() as { state: string }).state).toBe('cancellation_pending');
    const notCreated = await companyCall('/v1/desk/execution-results', {
      request_id: detail.identifier,
      result: 'not_created',
    });
    // 知らせを記録した後なので、未作成の報告は食い違う（409）。企業は取消の適用を報告する。
    expect(notCreated.status).toBe(409);
    clock += 61_000;
    await world.company.api.deliverDue();
    const set = world.sender.requests.at(-1);
    const event = (decodeJwt(String(set?.body)).events as Record<string, Record<string, string>>)[
      DESK_CANCELLATION
    ];
    expect(
      (
        await companyCall('/v1/desk/cancellation-results', {
          change_id: changeId,
          cancellation_id: event?.cancellation_id,
          result: 'already_applied',
        })
      ).status,
    ).toBe(204);
    expect((await deskItems(victim.approval))[0]).toMatchObject({ state: 'cancelled' });
  });

  it('取消期限を過ぎると、取り消せず、企業の照会で受付を終える', async () => {
    // 攻撃者が持っている情報：中継で承認させた作成（被害者が24時間のうちに気付かなかった）
    // 試す経路：作成の知らせから24時間を過ぎた後に、被害者が取り消す。企業が取消の受付の状態を照会する
    // 期待する結果：取消は 409 で断る。企業の照会は closed_without_cancellation。受信箱は「受付を終えました」
    // plan 11章：テスト1（D-34）
    const detail = deskDetail(victim.sub);
    // 受信箱の項目は新しい順。同じ時刻に作ると順が決まらないので、時計を進めておく。
    clock += 1000;
    const flow = await deskFlow(world, victim, client(), detail);
    const { change_id: changeId } = decodeJwt(String(flow.approvalJwt));
    await companyCall('/v1/desk/change-notices', {
      request_id: detail.identifier,
      change_id: changeId,
    });
    clock += 24 * 3600 * 1000 + 1000;
    await victim.approval.approvalLogin();
    const items = await deskItems(victim.approval);
    expect(items[0]).toMatchObject({ state: 'closed', cancellable: false });
    const id = String(items[0]?.id);
    const refused = await victim.approval.post('/api/desk-items/cancel/options', { id });
    // 項目は正本の終端を受けて片付いたので、取消の選択肢も出ない。
    expect(refused.status).toBe(400);
    const status = await companyCall('/v1/desk/cancellation-status', { change_id: changeId });
    expect(status.json()).toEqual({ state: 'closed_without_cancellation' });
  });

  it('担当者の画面や企業の自由文は、割符の承認画面に出ない', async () => {
    // 攻撃者が持っている情報：窓口の担当者の立場。自由文で利用者を急がせたい
    // 試す経路：authorization_details に自由文、受付番号、注文番号を足して PAR を送る。正しい申請の承認画面の
    //           中身を読む
    // 期待する結果：余分な項目のある申請は 400。承認画面は、登録簿の企業名、固定の操作ラベル、固定の種別と言語の
    //               ラベル、固定の文と警告文 A-1 の ID だけ（受付番号も企業の文も出ない）
    // plan 11章：テスト1（D-02、D-12）
    const user = victim;
    for (const extra of [
      { note: '至急承認してください' },
      { reception_number: '12345678' },
      { order_number: 'A-1001' },
      { locations: ['https://example.com'] },
    ]) {
      const par = await pushRequest(world.t, client(), [deskDetail(user.sub, extra)]);
      expect(par.status).toBe(400);
    }
    const par = await pushRequest(world.t, client(), [deskDetail(user.sub)]);
    const { uid } = await arriveAtDesk(user.browser, client(), String(par.requestUri));
    const view = await user.approval.post('/api/desk/view', { uid });
    expect(view.status).toBe(200);
    expect(view.json).toEqual({
      company: 'テスト企業1',
      operation: '一般問い合わせを作成する',
      lines: [
        { label: '種別', value: '一般的なお問い合わせ' },
        { label: '希望する言語', value: '日本語' },
      ],
      scope: expect.stringContaining('一般問い合わせを1件作成します'),
      validity: '承認してから5分の間、この1回の操作にだけ使えます。',
      change:
        '承認の後に窓口で行われた変更は、この端末に通知され、通知から24時間まで取り消せます。',
      createdAt: expect.any(String),
      device: expect.any(String),
      expiresAt: expect.any(String),
      warning: 'A-1',
    });
    // 別の利用者のブラウザ（承認用のオリジン）からは、uid を知っていても承認できない（上のテスト）。
    // ここでは、承認しないで終える。
    await user.approval.post('/api/desk/decline', { uid, reason: 'denied' });
  });
});
