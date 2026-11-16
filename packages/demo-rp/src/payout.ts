// 出金先の変更の、企業の側の参照実装（spec 02 の RP-09・RP-10・RP-12、ADR 0030 の O-115）。
//
// 企業の3つの責務：
// 1. 申請ID を作るときに、変更の内容の全体（口座番号の全桁）を、申請ID に結び付けて固定する。固定した後は書き換えない
//    （書き換える関数を作らない）。
// 2. 内容を変えるときは、新しい申請ID を作り、もう一度承認を受ける。前の申請は、もう使えなくする。
// 3. 変更の実行と、申請を使い済みにする更新を、1つのトランザクションで確定させる。
//
// 割符の承認が示すのは、申請ID と、表示の項目（金融機関コード、支店コード、口座番号の末尾4桁）までである。
// 変更に使う口座は、要求の本文からではなく、申請ID で引いた、固定済みの内容だけから取る。

import { newRandomId, type PayoutDestinationContent } from '@pii-token-vault/rp-kit';
import type { DemoState, PayoutDestination, PayoutRequest } from './state.ts';
import type { MemoryStore } from './store.ts';

/** 申請の有効期間（承認の JWT の5分と、利用者の操作の時間）。 */
export const PAYOUT_REQUEST_TTL_MS = 10 * 60_000;
/** 回復の後、高リスクの操作を保留する日数（RP-53。割符の7日に、日にまるめた分の1日を足す）。 */
export const RECOVERY_HOLD_DAYS = 8;

export type PayoutFailure =
  | 'invalid'
  | 'not_found'
  | 'used'
  | 'superseded'
  | 'expired'
  | 'recovery_hold';

export function parseDestination(input: unknown): PayoutDestination | undefined {
  if (typeof input !== 'object' || input === null) return undefined;
  const { bankCode, branchCode, accountNumber } = input as Record<string, unknown>;
  if (
    typeof bankCode !== 'string' ||
    !/^\d{4}$/.test(bankCode) ||
    typeof branchCode !== 'string' ||
    !/^\d{3}$/.test(branchCode) ||
    typeof accountNumber !== 'string' ||
    !/^\d{7}$/.test(accountNumber)
  ) {
    return undefined;
  }
  return { bankCode, branchCode, accountNumber };
}

/** 割符に送って、利用者に見せる内容（全桁は送らない）。 */
export function displayOf(destination: PayoutDestination): PayoutDestinationContent {
  return {
    bankCode: destination.bankCode,
    branchCode: destination.branchCode,
    accountLast4: destination.accountNumber.slice(-4),
  };
}

export function inRecoveryHold(recoveredAt: number | null, nowMs: number): boolean {
  return recoveredAt !== null && nowMs < (recoveredAt + RECOVERY_HOLD_DAYS * 86_400) * 1000;
}

/**
 * 責務1と2：申請を作り、内容の全体を固定する。同じ利用者の、まだ使っていない前の申請は、もう使えなくする
 * （内容を変えるには、新しい申請と、新しい承認が要る）。
 */
export function createPayoutRequest(
  store: MemoryStore<DemoState>,
  input: { readonly accountKey: string; readonly destination: unknown; readonly nowMs: number },
): Promise<{ ok: true; request: PayoutRequest } | { ok: false; reason: PayoutFailure }> {
  const destination = parseDestination(input.destination);
  return store.transaction((state) => {
    const account = state.accounts.get(input.accountKey);
    if (account === undefined) return { ok: false, reason: 'not_found' } as const;
    if (destination === undefined) return { ok: false, reason: 'invalid' } as const;
    if (inRecoveryHold(account.recoveredAt, input.nowMs)) {
      return { ok: false, reason: 'recovery_hold' } as const;
    }
    for (const earlier of state.payoutRequests.values()) {
      if (earlier.accountKey === input.accountKey && earlier.state === 'pending') {
        earlier.state = 'superseded';
      }
    }
    const request: PayoutRequest = {
      requestId: newRandomId(),
      accountKey: input.accountKey,
      destination: { ...destination },
      createdAt: input.nowMs,
      expiresAt: input.nowMs + PAYOUT_REQUEST_TTL_MS,
      state: 'pending',
      usedAt: null,
    };
    state.payoutRequests.set(request.requestId, request);
    return { ok: true, request } as const;
  });
}

/** 自分の、まだ使える申請を引く（別の利用者の申請は not_found。RP-08）。 */
export function findUsableRequest(
  store: MemoryStore<DemoState>,
  input: { readonly requestId: string; readonly accountKey: string; readonly nowMs: number },
): Promise<{ ok: true; request: PayoutRequest } | { ok: false; reason: PayoutFailure }> {
  return store.read((state) => usable(state, input));
}

function usable(
  state: DemoState,
  input: { readonly requestId: string; readonly accountKey: string; readonly nowMs: number },
): { ok: true; request: PayoutRequest } | { ok: false; reason: PayoutFailure } {
  const request = state.payoutRequests.get(input.requestId);
  if (request === undefined || request.accountKey !== input.accountKey) {
    return { ok: false, reason: 'not_found' };
  }
  if (request.state !== 'pending') return { ok: false, reason: request.state };
  if (request.expiresAt <= input.nowMs) return { ok: false, reason: 'expired' };
  return { ok: true, request };
}

/**
 * 責務3：変更の実行と、申請を使い済みにする更新を、1つのトランザクションで確定させる。
 * 呼ぶのは、割符の承認の JWT を、この申請ID と displayOf(固定した内容) で確かめた後だけ（RP-10）。
 * 変更先は、引数からは受け取らない。申請に固定した内容だけを使う。
 */
export function completePayoutChange(
  store: MemoryStore<DemoState>,
  input: { readonly requestId: string; readonly accountKey: string; readonly nowMs: number },
): Promise<{ ok: true; destination: PayoutDestination } | { ok: false; reason: PayoutFailure }> {
  return store.transaction((state) => {
    const found = usable(state, input);
    if (!found.ok) return found;
    const account = state.accounts.get(input.accountKey);
    if (account === undefined) return { ok: false, reason: 'not_found' } as const;
    if (inRecoveryHold(account.recoveredAt, input.nowMs)) {
      return { ok: false, reason: 'recovery_hold' } as const;
    }
    account.payoutDestination = { ...found.request.destination };
    found.request.state = 'used';
    found.request.usedAt = input.nowMs;
    return { ok: true, destination: account.payoutDestination } as const;
  });
}
