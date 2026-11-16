// 出金先の変更の参照実装の単体検査（spec 02 の RP-09、ADR 0030 の O-115）。企業の3つの責務を確かめる。
// 1. 申請のときに全体を固定し、書き換えられない。2. 内容を変えたら、新しい申請が要る（前の申請は使えない）。
// 3. 変更の実行と、申請を使い済みにする更新は、まとめて確定する（同時の実行、再送、途中の失敗でも食い違わない）。
// 割符の承認の検証と合わせた流れは、test/leak/t01-demo-rp-payout で確かめる。

import { describe, expect, it } from 'vitest';
import {
  completePayoutChange,
  createPayoutRequest,
  displayOf,
  findUsableRequest,
  PAYOUT_REQUEST_TTL_MS,
} from '../src/payout.ts';
import { type Account, type DemoState, emptyState } from '../src/state.ts';
import { MemoryStore, type StoreOptions } from '../src/store.ts';

const NOW = 1_800_000_000_000;
const KEY_A = 'https://idp.example/oidc|subA';
const KEY_B = 'https://idp.example/oidc|subB';
const FIRST = { bankCode: '9991', branchCode: '101', accountNumber: '1234567' };
/** 金融機関、支店、末尾4桁が FIRST と同じ、別の口座。割符の画面では見分けられない。 */
const SAME_LAST4 = { bankCode: '9991', branchCode: '101', accountNumber: '9994567' };

function account(key: string, recoveredAt: number | null = null): Account {
  const [iss, sub] = key.split('|') as [string, string];
  return {
    key,
    iss,
    sub,
    createdAt: NOW,
    payoutDestination: null,
    recoveredAt,
    legacyMemberId: null,
  };
}

function storeWith(accounts: Account[], options?: StoreOptions): MemoryStore<DemoState> {
  const state = emptyState();
  for (const a of accounts) state.accounts.set(a.key, a);
  return new MemoryStore(state, options);
}

async function requestOf(store: MemoryStore<DemoState>, destination: unknown, accountKey = KEY_A) {
  const created = await createPayoutRequest(store, { accountKey, destination, nowMs: NOW });
  if (!created.ok) throw new Error(`申請を作れない（${created.reason}）`);
  return created.request;
}

const destinationOf = (store: MemoryStore<DemoState>, key = KEY_A) =>
  store.read((state) => state.accounts.get(key)?.payoutDestination ?? null);

describe('出金先の変更の参照実装（RP-09）', () => {
  it('申請の後は、同じ末尾4桁の別の口座にも、変更先を書き換えられない', async () => {
    // 攻撃者が持っている情報：利用者の承認済みの申請（表示は「9991・101・末尾4567」）と、企業の画面を操れる立場
    // 試す経路：申請で返った写しを書き換える。同じ表示になる別の口座を、後から同じ申請に入れようとする
    // 期待する結果：保存した申請は変わらず、確定する変更先は、申請のときに固定した口座だけ
    // plan 11章：テスト1（RP-09・RP-10）
    const store = storeWith([account(KEY_A)]);
    const request = await requestOf(store, FIRST);
    expect(displayOf(SAME_LAST4)).toEqual(displayOf(FIRST));
    // 返った写しを書き換えても、保存した申請は変わらない。
    (request.destination as { accountNumber: string }).accountNumber = SAME_LAST4.accountNumber;
    const stored = await findUsableRequest(store, {
      requestId: request.requestId,
      accountKey: KEY_A,
      nowMs: NOW,
    });
    expect(stored.ok && stored.request.destination).toEqual(FIRST);
    // 確定の関数は、変更先を引数から受け取らない（余計な項目を渡しても使わない）。
    const done = await completePayoutChange(store, {
      requestId: request.requestId,
      accountKey: KEY_A,
      nowMs: NOW,
      ...({ destination: SAME_LAST4 } as object),
    });
    expect(done).toEqual({ ok: true, destination: FIRST });
    expect(await destinationOf(store)).toEqual(FIRST);
  });

  it('内容を変えるには新しい申請が要り、前の申請は使えなくなる。他人の申請と期限切れも使えない', async () => {
    // 攻撃者が持っている情報：前の申請の承認（内容を変える前のもの）、または他人の申請ID
    // 試す経路：内容を変えた後に、前の申請ID で確定する。別の利用者の申請ID、期限の切れた申請ID で確定する
    // 期待する結果：前の申請は superseded、他人の申請は not_found、期限切れは expired。変更先は変わらない
    // plan 11章：テスト1（RP-09・RP-12）、テスト6（RP-08）
    const store = storeWith([account(KEY_A), account(KEY_B)]);
    const first = await requestOf(store, FIRST);
    const second = await requestOf(store, SAME_LAST4);
    expect(second.requestId).not.toBe(first.requestId);
    expect(
      await completePayoutChange(store, {
        requestId: first.requestId,
        accountKey: KEY_A,
        nowMs: NOW,
      }),
    ).toEqual({
      ok: false,
      reason: 'superseded',
    });
    expect(await destinationOf(store)).toBeNull();
    // 別の利用者は、この申請を使えない（申請ID を知っていても）。
    expect(
      await completePayoutChange(store, {
        requestId: second.requestId,
        accountKey: KEY_B,
        nowMs: NOW,
      }),
    ).toEqual({
      ok: false,
      reason: 'not_found',
    });
    expect(
      await completePayoutChange(store, {
        requestId: second.requestId,
        accountKey: KEY_A,
        nowMs: NOW + PAYOUT_REQUEST_TTL_MS,
      }),
    ).toEqual({ ok: false, reason: 'expired' });
    expect(await destinationOf(store)).toBeNull();
    expect(
      await completePayoutChange(store, {
        requestId: second.requestId,
        accountKey: KEY_A,
        nowMs: NOW,
      }),
    ).toEqual({
      ok: true,
      destination: SAME_LAST4,
    });
  });

  it('同時の実行と再送でも、変更は一度だけ確定する', async () => {
    // 攻撃者が持っている情報：承認済みの申請（確定の要求を、同時に何度も送れる）
    // 試す経路：同じ申請の確定を、同時に20回呼ぶ。その後にもう一度呼ぶ（再送）
    // 期待する結果：成功は1回だけ。ほかは used。変更先は固定した口座で、申請は使い済み
    // plan 11章：テスト1（RP-12）
    const store = storeWith([account(KEY_A)]);
    const request = await requestOf(store, FIRST);
    const input = { requestId: request.requestId, accountKey: KEY_A, nowMs: NOW };
    const results = await Promise.all(
      Array.from({ length: 20 }, () => completePayoutChange(store, input)),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok && r.reason === 'used')).toHaveLength(19);
    expect(await completePayoutChange(store, input)).toEqual({ ok: false, reason: 'used' });
    expect(await destinationOf(store)).toEqual(FIRST);
    const state = await store.read((s) => s.payoutRequests.get(request.requestId)?.state);
    expect(state).toBe('used');
  });

  it('途中で失敗しても、変更と、申請の使い済みの状態は食い違わない', async () => {
    // 攻撃者が持っている情報：なし（障害のときに、変更だけ、または使い済みだけが残らないことを確かめる）
    // 試す経路：確定の直前に失敗させる。その後、失敗を止めて、同じ申請でもう一度確定する
    // 期待する結果：失敗のときは、変更先は元のまま、申請は pending のまま。やり直すと、どちらもそろって確定する
    // plan 11章：テスト1（RP-09）
    let failing = true;
    const store = storeWith([account(KEY_A)], {
      beforeCommit: () => {
        if (failing) throw new Error('確定の失敗（注入）');
      },
    });
    failing = false;
    const request = await requestOf(store, FIRST);
    failing = true;
    const input = { requestId: request.requestId, accountKey: KEY_A, nowMs: NOW };
    await expect(completePayoutChange(store, input)).rejects.toThrow('確定の失敗');
    failing = false;
    expect(await destinationOf(store)).toBeNull();
    expect(await store.read((s) => s.payoutRequests.get(request.requestId)?.state)).toBe('pending');
    // 処理の途中の例外でも、同じ（写しの上の変更は残らない）。
    await expect(
      store.transaction((state) => {
        const a = state.accounts.get(KEY_A);
        if (a !== undefined) a.payoutDestination = SAME_LAST4;
        throw new Error('途中の失敗');
      }),
    ).rejects.toThrow('途中の失敗');
    expect(await destinationOf(store)).toBeNull();
    expect(await completePayoutChange(store, input)).toEqual({ ok: true, destination: FIRST });
    expect(await store.read((s) => s.payoutRequests.get(request.requestId)?.state)).toBe('used');
  });

  it('形の違う口座は申請にできず、回復の後8日の間は、申請も確定も保留する', async () => {
    // 攻撃者が持っている情報：回復で乗っ取った割符のアカウント（回復の直後に出金先を変えようとする）
    // 試す経路：回復の翌日に申請する。回復の前に作った申請を、回復の後に確定する。桁の違う口座で申請する
    // 期待する結果：recovery_hold。8日を過ぎれば申請できる。形の違う口座は invalid
    // plan 11章：テスト3（RP-53・RP-54）
    const recoveredAt = Math.floor(NOW / 1000) - 86_400;
    const held = storeWith([account(KEY_A, recoveredAt)]);
    expect(
      await createPayoutRequest(held, { accountKey: KEY_A, destination: FIRST, nowMs: NOW }),
    ).toEqual({
      ok: false,
      reason: 'recovery_hold',
    });
    const later = await createPayoutRequest(held, {
      accountKey: KEY_A,
      destination: FIRST,
      nowMs: NOW + 8 * 86_400_000,
    });
    expect(later.ok).toBe(true);
    const store = storeWith([account(KEY_A)]);
    const request = await requestOf(store, FIRST);
    await store.transaction((state) => {
      const a = state.accounts.get(KEY_A);
      if (a !== undefined) a.recoveredAt = Math.floor(NOW / 1000);
    });
    expect(
      await completePayoutChange(store, {
        requestId: request.requestId,
        accountKey: KEY_A,
        nowMs: NOW,
      }),
    ).toEqual({
      ok: false,
      reason: 'recovery_hold',
    });
    for (const bad of [
      { ...FIRST, accountNumber: '123' },
      { ...FIRST, bankCode: 'abcd' },
      null,
      'x',
    ]) {
      expect(
        await createPayoutRequest(store, { accountKey: KEY_A, destination: bad, nowMs: NOW }),
      ).toEqual({
        ok: false,
        reason: 'invalid',
      });
    }
  });
});
