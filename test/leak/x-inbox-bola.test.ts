// 受信箱と承認待ちの、利用者どうしの BOLA（plan 2章「利用者の境界」、spec 03 の TH-31、CAP-33、ADR 0023）。
// plan 11章 テスト6（利用者 U1 は U2 のものに触れない）。

import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover, PICKUP_DETAILS, TEST_DEVICE_TYPE } from '../setup/approvals.ts';
import { startTestIdp, type TestIdp } from '../setup/idp.ts';
import { SoftAuthenticator } from '../setup/soft-authenticator.ts';

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, undefined, {
    approvalTypes: [TEST_DEVICE_TYPE],
  });
});

afterAll(async () => {
  await t.stop();
});

async function requestFor(userId: Awaited<ReturnType<typeof newApprover>>['userId']) {
  const result = await t.idp.requestApproval({
    userId,
    tenantId: t.tenants[0]?.tenantId as TenantId,
    type: TEST_DEVICE_TYPE.type,
    details: PICKUP_DETAILS,
    ttlSeconds: 300,
  });
  if (!result.ok) throw new Error('承認待ちを作れなかった');
  return result.itemId;
}

describe('漏えい：受信箱と承認待ちの BOLA（plan 11章 テスト6）', () => {
  it('U2 は、U1 の承認待ちを見ることも、選ぶことも、確定させることもできない', async () => {
    // 攻撃者が持っている情報：U2 自身の正規のアカウントとパスキー。U1 の承認待ちの ID（画面のスクリーンショットや
    //                         ログから漏れたもの）。U1 が取った承認の儀式の ID
    // 試す経路：U2 の承認用のセッションで、一覧を読む。U1 の ID で選択肢を取る。U1 の儀式に、U2 のアサーションを送る
    // 期待する結果：一覧に U1 のものは出ない。選択肢は、存在しない ID と同じ 400。U1 の儀式は 401。
    //               U1 の承認待ちは承認待ちのまま
    // plan 11章：テスト6（利用者 U1 は U2 のものに触れない）
    const u1 = await newApprover(t);
    const u2 = await newApprover(t);
    const id = await requestFor(u1.userId);
    expect(((await u2.approval.get('/api/approvals')).json.approvals as unknown[]).length).toBe(0);

    const foreign = await u2.approval.post('/api/approvals/decide/options', {
      id,
      decision: 'approved',
    });
    const missing = await u2.approval.post('/api/approvals/decide/options', {
      id: randomUUID(),
      decision: 'approved',
    });
    expect([foreign.status, foreign.text]).toEqual([missing.status, missing.text]);
    expect(foreign.status).toBe(400);

    const u1Options = await u1.approval.post('/api/approvals/decide/options', {
      id,
      decision: 'approved',
    });
    const u2Response = u2.approval.authenticator.get(u1Options.json.options as never, undefined, {
      origin: t.approvalOrigin,
    });
    const hijack = await u2.approval.post('/api/approvals/decide/verify', {
      ceremonyId: u1Options.json.ceremonyId,
      response: u2Response,
    });
    expect(hijack.status).toBe(401);
    const state = (await u1.pwa.get('/api/inbox')).json.items as { id: string; state: string }[];
    expect(state.find((item) => item.id === id)?.state).toBe('pending');
  });

  it('U2 は、U1 の受信箱を読むことも、U1 の知らせを既読にすることもできない', async () => {
    // 攻撃者が持っている情報：U2 自身の PWA のセッション。U1 の知らせの ID
    // 試す経路：U2 の受信箱を読む。U1 の知らせの ID で既読にする
    // 期待する結果：U2 の受信箱に U1 の項目は出ない。既読にする操作は、存在しない ID と同じ 400 で、U1 の知らせは未読のまま
    // plan 11章：テスト6（利用者 U1 は U2 のものに触れない）
    const u1 = await newApprover(t);
    const u2 = await newApprover(t);
    const second = new SoftAuthenticator(t.origin);
    const options = await u1.pwa.post('/api/passkeys/options');
    const added = await u1.pwa.post('/api/passkeys/verify', {
      ceremonyId: options.json.ceremonyId,
      response: second.create(options.json.options as never),
    });
    expect(added.status).toBe(200);
    await requestFor(u1.userId);
    const u1Items = (await u1.pwa.get('/api/inbox')).json.items as { id: string; kind: string }[];
    const notice = u1Items.find((item) => item.kind === 'notice');
    expect(notice).toBeDefined();
    expect(u1Items).toHaveLength(2);

    const u2Items = (await u2.pwa.get('/api/inbox')).json.items as { id: string }[];
    expect(u2Items.filter((item) => u1Items.some((own) => own.id === item.id))).toEqual([]);

    const foreign = await u2.pwa.post('/api/inbox/read', { id: notice?.id });
    const missing = await u2.pwa.post('/api/inbox/read', { id: randomUUID() });
    expect([foreign.status, foreign.text]).toEqual([missing.status, missing.text]);
    expect(foreign.status).toBe(400);
    const after = (await u1.pwa.get('/api/inbox')).json.items as { id: string; state: string }[];
    expect(after.find((item) => item.id === notice?.id)?.state).toBe('unread');
  });
});
