// 既存会員の初回紐付けの、company-api の正本（ADR 0020、ADR 0028 の O-86〜O-92、O-103）。
// 企業向けのルート（仮申請、証跡、企業の側の取消、結果の報告）と、idp の内部 API が呼ぶ操作（承認、最終の承認、
// 状態、利用者の取消）を、company-api の中で確かめる。idp を通した端から端までは、idp の初回紐付けのテストで確かめる。
// 待機の知らせの SET に 202 が返ったことは、送信待ちが呼ぶ startWaiting を直接呼んで模す。

import { type KeyObject, randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  acceptUserCancel,
  type InitialLinkDeps,
  recordApproval,
  recordFinalApproval,
  startWaiting,
  statusOf,
} from '../../packages/company-api/src/initial-link.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { parseWarifuUserId, type TenantId } from '../../packages/warifu-core/src/ids.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import { startTestCompanyApi, type TestCompanyApi, type TestTenant } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import {
  initialLinkProof,
  newMemberRef,
  newRequestId,
  TEST_INITIAL_LINK,
} from '../setup/initial-link.ts';
import { keysvcConnection } from '../setup/keys.ts';

const HOUR = 3600 * 1000;
let clock = Date.now();
const now = () => new Date(clock);
let api: TestCompanyApi;
let deps: InitialLinkDeps;
const INITIAL_LINK = TEST_INITIAL_LINK;

beforeAll(async () => {
  api = await startTestCompanyApi({
    now,
    tenants: [
      {
        scopes: ['initial_link'],
        initialLink: INITIAL_LINK,
        participation: 'migrating',
        migrationDeadline: '2027-05-14',
        webhookUrl: 'https://hooks.company-a.example/set',
      },
      {
        scopes: ['initial_link'],
        initialLink: INITIAL_LINK,
        webhookUrl: 'https://hooks.company-b.example/set',
      },
      // 移行プロファイルのないテナント（scope initial_link を持てない）。
      { scopes: ['company_api'] },
    ],
  });
  deps = { db: api.api.db, keys: createCompanyApiKeyClient(keysvcConnection('company-api')), now };
});

afterAll(async () => {
  await api?.stop();
});

function tenant(index: number): TestTenant {
  const found = api.tenants[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

function registered(index: number) {
  const found = api.api.config.tenants.get(tenant(index).tenantId);
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

const b64 = (bytes: Buffer) => bytes.toString('base64url');

function proof(
  t: TestTenant,
  claims: Record<string, unknown>,
  options: { readonly typ?: string; readonly key?: KeyObject; readonly lifetime?: number } = {},
): Promise<string> {
  return initialLinkProof(t, claims, { ...options, nowMs: clock });
}

async function call(index: number, path: string, json: unknown) {
  const token = await api.accessToken(tenant(index), 'initial_link');
  return api.request({ path: `/v1/initial-link/${path}`, token, json });
}

async function prepared(index = 0, memberRef = newMemberRef()) {
  const requestId = newRequestId();
  const res = await call(index, 'prepare', { request_id: requestId, member_ref: memberRef });
  expect(res.status).toBe(200);
  const body = res.json() as { initial_link_id: string; state: string };
  return { requestId, memberRef, id: body.initial_link_id };
}

/** 仮申請、初回の証跡、本人の承認、待機の知らせの 202 まで進める。 */
async function waiting(index = 0) {
  const p = await prepared(index);
  const initial = await call(index, 'proofs', {
    proof: await proof(tenant(index), { initial_link_id: p.id, member_ref: p.memberRef }),
  });
  expect(initial.status).toBe(204);
  const userId = parseWarifuUserId(randomUUID());
  const itemRef = randomUUID();
  const approved = await recordApproval(deps, registered(index), {
    userId,
    itemRef,
    initialLinkId: p.id,
  });
  expect(approved).toMatchObject({ ok: true, state: 'pending_notice' });
  const linkRef = approved.ok ? approved.linkRef : '';
  await deps.db.withTenant(tenant(index).tenantId, (tx) => startWaiting(tx, deps, linkRef));
  return { ...p, userId, itemRef, linkRef };
}

async function outboxTypes(tenantId: TenantId): Promise<string[]> {
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(tenantId, (tx) =>
      tx.query<{ event_type: string }>(
        sql`SELECT event_type FROM company_api.set_outbox ORDER BY created_at, event_id`,
      ),
    );
    return rows.map((r) => r.event_type);
  } finally {
    await db.close();
  }
}

describe('初回紐付けの正本（ADR 0028）', () => {
  it('仮申請：同じ申請ID の再送は同じ移行専用ID。会員参照が違えば 409。別のテナントでは別の値', async () => {
    // 攻撃者が持っている情報：A社の申請ID（企業のサーバーの記録から漏れた）
    // 試す経路：A社の資格情報で、同じ申請ID を別の会員参照で出し直す。B社で同じ申請ID と会員参照を出す
    // 期待する結果：別の会員参照は 409。B社の移行専用ID は A社と違う（不変条件5）。DB に申請ID の原値はない
    // plan 11章：テスト4（企業に渡る値の独立）、テスト7（平文を残さない）
    const a = await prepared(0);
    const again = await call(0, 'prepare', { request_id: a.requestId, member_ref: a.memberRef });
    expect([again.status, (again.json() as { initial_link_id: string }).initial_link_id]).toEqual([
      200,
      a.id,
    ]);
    const other = await call(0, 'prepare', { request_id: a.requestId, member_ref: newMemberRef() });
    expect([other.status, other.text]).toEqual([409, '{"error":"conflict"}']);
    const b = await call(1, 'prepare', { request_id: a.requestId, member_ref: a.memberRef });
    expect(b.status).toBe(200);
    expect((b.json() as { initial_link_id: string }).initial_link_id).not.toBe(a.id);
    const db = await serviceDb('company-api');
    try {
      const dump = await db.withTenant(tenant(0).tenantId, (tx) =>
        tx.query<Record<string, unknown>>(sql`SELECT * FROM company_api.initial_links`),
      );
      const text = JSON.stringify(dump);
      expect(text).not.toContain(a.requestId);
      expect(text).not.toContain(a.memberRef);
      expect(text).not.toContain(a.id);
    } finally {
      await db.close();
    }
  });

  it('移行プロファイルのないテナントには scope initial_link を出さない。形の違う申請は 400', async () => {
    // 攻撃者が持っている情報：移行プロファイルを認められていない企業の正規の資格情報
    // 試す経路：scope initial_link のトークンを頼む。A社で、短い申請ID と短い会員参照で仮申請する
    // 期待する結果：トークンは出ない（400）。形の違う仮申請は 400
    // plan 11章：テスト6
    const res = await api.token(tenant(2), { scope: 'initial_link' });
    expect(res.status).toBe(400);
    const bad = await call(0, 'prepare', { request_id: 'short', member_ref: 'short' });
    expect([bad.status, bad.text]).toEqual([400, '{"error":"invalid_request"}']);
  });

  it('証跡：typ、鍵、クレーム、版、jti、会員参照が違えば断る', async () => {
    // 攻撃者が持っている情報：A社の移行専用ID と会員参照、または client assertion（別の用途の JWT）
    // 試す経路：typ を変える、別の鍵で署名する、許可リストにないクレーム（email）を足す、移行プロファイルの版を
    //           変える、有効期間を5分より長くする、同じ jti で2回出す、別の会員参照で出す
    // 期待する結果：どれも 400 か 409。正しい証跡だけ 204。メールなどのクレームは受け付けない（不変条件1(d)）
    // plan 11章：テスト9（紐付けの攻撃）
    const p = await prepared(0);
    const base = { initial_link_id: p.id, member_ref: p.memberRef };
    const other = tenant(1);
    for (const jws of [
      await proof(tenant(0), base, { typ: 'JWT' }),
      await proof(tenant(0), base, { key: other.client.privateKey }),
      await proof(tenant(0), { ...base, email: 'old-member@example.com' }),
      await proof(tenant(0), { ...base, profile_version: 2 }),
      await proof(tenant(0), { ...base, eligibility: 'not_eligible' }),
      await proof(tenant(0), base, { lifetime: 600 }),
    ]) {
      const res = await call(0, 'proofs', { proof: jws });
      expect([res.status, res.text]).toEqual([400, '{"error":"invalid_request"}']);
    }
    // 大きすぎる証跡は、確かめる前に 400（鍵サービスの上限に届かせない）。
    const huge = await call(0, 'proofs', { proof: `${'A'.repeat(4000)}.${'B'.repeat(10)}.C` });
    expect([huge.status, huge.text]).toEqual([400, '{"error":"invalid_request"}']);
    const wrongMember = await call(0, 'proofs', {
      proof: await proof(tenant(0), { ...base, member_ref: newMemberRef() }),
    });
    expect(wrongMember.status).toBe(409);
    const jti = b64(randomBytes(16));
    const ok = await call(0, 'proofs', { proof: await proof(tenant(0), { ...base, jti }) });
    expect(ok.status).toBe(204);
    const replay = await call(0, 'proofs', { proof: await proof(tenant(0), { ...base, jti }) });
    expect(replay.status).toBe(400);
  });

  it('待機：202 の前は待機が進まず、24時間で満ち、最終の証跡と最終の承認の後に結果を受ける', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー（旧会員の側の証跡を出せる）と、自分の割符のアカウント
    // 試す経路：本人の承認の後、待機の知らせの SET が届く前と、待機の間に、最終の承認を求める
    // 期待する結果：待機が満ちるまで not_ready。満ちた後も、最終の証跡がなければ not_ready。そろえば approved で
    //               移行専用ID を返し、linked の報告で続く記録が1件できる。同じ利用者は2つ目を紐付けられない
    // plan 11章：テスト9（紐付けの攻撃）、ADR 0028 の O-103
    const w = await waiting(0);
    const t = registered(0);
    expect(await recordFinalApproval(deps, t, { userId: w.userId, itemRef: w.itemRef })).toEqual({
      ok: false,
      reason: 'not_ready',
    });
    clock += 24 * HOUR + 1000;
    expect(await recordFinalApproval(deps, t, { userId: w.userId, itemRef: w.itemRef })).toEqual({
      ok: false,
      reason: 'not_ready',
    });
    const final = await call(0, 'proofs', {
      proof: await proof(tenant(0), {
        initial_link_id: w.id,
        member_ref: w.memberRef,
        stage: 'final',
      }),
    });
    expect(final.status).toBe(204);
    // 別の利用者は、この項目で最終の承認をできない（BOLA）。
    expect(
      await recordFinalApproval(deps, t, {
        userId: parseWarifuUserId(randomUUID()),
        itemRef: w.itemRef,
      }),
    ).toEqual({ ok: false, reason: 'not_found' });
    expect(await recordFinalApproval(deps, t, { userId: w.userId, itemRef: w.itemRef })).toEqual({
      ok: true,
      initialLinkId: w.id,
    });
    const linked = await call(0, 'results', { initial_link_id: w.id, result: 'linked' });
    expect(linked.status).toBe(204);
    expect((await call(0, 'results', { initial_link_id: w.id, result: 'linked' })).status).toBe(
      204,
    );
    const [status] = await statusOf(deps, t, { userId: w.userId, itemRefs: [w.itemRef] });
    expect(status?.state).toBe('linked');

    // 同じ利用者の2つ目の紐付けは、承認の時点で断る（続く記録がある）。
    const second = await prepared(0);
    await call(0, 'proofs', {
      proof: await proof(tenant(0), { initial_link_id: second.id, member_ref: second.memberRef }),
    });
    expect(
      await recordApproval(deps, t, {
        userId: w.userId,
        itemRef: randomUUID(),
        initialLinkId: second.id,
      }),
    ).toEqual({ ok: false, reason: 'conflict' });
  });

  it('待機中に旧会員の側の認証世代が変われば、最終の証跡で申請を終える', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー。待機中に、本当の持ち主が旧会員の側で認証器を変えた
    // 試す経路：初回と違う auth_epoch の最終の証跡を出す
    // 期待する結果：409 で申請は expired。最終の承認は出ない
    // plan 11章：テスト9、ADR 0028 の O-88
    const w = await waiting(0);
    clock += 24 * HOUR + 1000;
    const res = await call(0, 'proofs', {
      proof: await proof(tenant(0), {
        initial_link_id: w.id,
        member_ref: w.memberRef,
        stage: 'final',
        auth_epoch: 8,
      }),
    });
    expect(res.status).toBe(409);
    const [status] = await statusOf(deps, registered(0), {
      userId: w.userId,
      itemRefs: [w.itemRef],
    });
    expect(status?.state).toBe('expired');
  });

  it('利用者の取消：取消の SET を入れ、待機の知らせは消す。取消の後の linked は 409', async () => {
    // 攻撃者が持っている情報：企業のサーバーの権限（取消を無視して紐付けたい）
    // 試す経路：利用者が待機中に取り消した後、企業が linked を報告する
    // 期待する結果：取消の SET が送信待ちに入る。linked は 409（防御の停止と調査）。cancelled の報告で終わる
    // plan 11章：テスト9、ADR 0028 の O-90・O-91
    const p = await prepared(1);
    await call(1, 'proofs', {
      proof: await proof(tenant(1), { initial_link_id: p.id, member_ref: p.memberRef }),
    });
    const userId = parseWarifuUserId(randomUUID());
    const itemRef = randomUUID();
    await recordApproval(deps, registered(1), { userId, itemRef, initialLinkId: p.id });
    expect(await outboxTypes(tenant(1).tenantId)).toContain('initial_link_waiting');
    expect(await acceptUserCancel(deps, registered(1), { userId, itemRef })).toEqual({
      ok: true,
      state: 'cancel_requested',
    });
    const types = await outboxTypes(tenant(1).tenantId);
    expect(types).toContain('initial_link_cancellation');
    expect(types).not.toContain('initial_link_waiting');
    const linked = await call(1, 'results', { initial_link_id: p.id, result: 'linked' });
    expect(linked.status).toBe(409);
    expect(api.logs.join('\n')).toContain('company_api.initial_link.linked_after_cancel');
    expect((await call(1, 'results', { initial_link_id: p.id, result: 'cancelled' })).status).toBe(
      204,
    );
  });

  it('本人の承認の前に、知らせの SET が届かないまま24時間たてば期限切れ', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー。企業の受け口が止まっていて、旧会員の側に知らせが出ない
    // 試す経路：本人の承認の後、待機の知らせの SET が届かないまま24時間たってから最終の承認を求める
    // 期待する結果：待機は進まず、申請は expired（旧会員の側に知らせが出ないまま紐付けない。O-103）
    // plan 11章：テスト9
    const p = await prepared(0);
    await call(0, 'proofs', {
      proof: await proof(tenant(0), { initial_link_id: p.id, member_ref: p.memberRef }),
    });
    const userId = parseWarifuUserId(randomUUID());
    const itemRef = randomUUID();
    await recordApproval(deps, registered(0), { userId, itemRef, initialLinkId: p.id });
    clock += 24 * HOUR + 1000;
    expect(await recordFinalApproval(deps, registered(0), { userId, itemRef })).toEqual({
      ok: false,
      reason: 'conflict',
    });
    const [status] = await statusOf(deps, registered(0), { userId, itemRefs: [itemRef] });
    expect(status?.state).toBe('expired');
  });
});
