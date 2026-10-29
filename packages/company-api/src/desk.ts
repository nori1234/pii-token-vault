// 窓口の作成の正本（ADR 0019、ADR 0026 の O-63〜O-66、O-69）。テナントの範囲（withTenant）でだけ読み書きする。
//
// - 正本は company_api.desk_changes。照会の承認は、ここに何も残さない（O-63）。
// - 申請ID の原値は置かない。照合用の mac(desk_lookup, …) だけを置く。変更ID と取消要求ID は、内部のレコード ID から
//   mac(desk_id, …) でその都度導き、照合は mac(desk_lookup, …) の索引で行う（O-64、不変条件4）。
// - 状態の変更は、行を1つの文で書き換えるか、行のロック（FOR UPDATE）の中で判定する。取消の受理と、受付の終了は、
//   同じ行の状態で原子的に決まる（O-66）。時刻は割符の時計（deps.now）だけで決める。
// - 終端の行は、終端から7日を過ぎたら、そのテナントの窓口の処理で行を書き換えるときに消す（O-69）。
//   終端でない行は消さない。
// - 取消を受理したら、同じトランザクションで取消の SET を送信待ちに入れる（初回は0〜60秒の乱数だけ遅らせる。O-67）。

import {
  constantTimeEqual,
  lengthPrefixed,
  randomBytesOf,
  randomUuid,
  type TenantId,
  toBase64Url,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { type Db, DbError, sql, type Tx } from '@pii-token-vault/warifu-core/db';
import {
  DESK_EXTERNAL_ID_PATTERN,
  DESK_REQUEST_ID_PATTERN,
  DESK_TIMES,
  type DeskChangeState,
  type DeskStatusItem,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import {
  DESK_CANCEL_ACCEPTED,
  DESK_CANCEL_APPLIED,
  DESK_CHANGE_RECORDED,
  DESK_CLOSED,
  DESK_NOT_CREATED,
  DESK_NOTICE_RECORDED,
} from './audit-events.ts';
import type { CompanyTenant } from './config.ts';

const ID_LABEL = 'warifu/desk/id/v1';
const LOOKUP_LABEL = 'warifu/desk/lookup/v1';
const DAY_MS = 24 * 3600 * 1000;
/** 取消の SET を初めて送るまでの、意図した遅延の上限（ミリ秒。ADR 0026 の O-67）。 */
export const CANCEL_SET_MAX_DELAY_MS = 60_000;
const UNIQUE_VIOLATION = '23505';

export interface DeskDeps {
  readonly db: Db;
  readonly keys: CompanyApiKeyClient;
  readonly now: () => Date;
}

/** 企業に見せる受付の状態（仕様案 v0.7 の 2.4.2）。 */
export type DeskPublicState =
  | 'window_open'
  | 'cancellation_pending'
  | 'closed_without_cancellation'
  | 'cancelled';

interface Row {
  change_ref: string;
  user_id: string;
  request_mac: string;
  state: DeskChangeState;
  notice_at: Date | null;
  cancel_closes_at: Date | null;
  cancel_ref: string | null;
}

// ---- ID ----

async function deriveId(
  keys: CompanyApiKeyClient,
  tenantId: TenantId,
  kind: 'change' | 'cancel',
  ref: string,
): Promise<string> {
  return toBase64Url(await keys.mac('desk_id', lengthPrefixed([ID_LABEL, tenantId, kind, ref])));
}

async function lookupMac(
  keys: CompanyApiKeyClient,
  tenantId: TenantId,
  kind: 'request' | 'change',
  value: string,
): Promise<string> {
  return toBase64Url(
    await keys.mac('desk_lookup', lengthPrefixed([LOOKUP_LABEL, tenantId, kind, value])),
  );
}

/** 変更ID（外に出す値）を、内部のレコード ID から導く。 */
export function changeIdOf(deps: Pick<DeskDeps, 'keys'>, tenantId: TenantId, changeRef: string) {
  return deriveId(deps.keys, tenantId, 'change', changeRef);
}

/** 取消要求ID（外に出す値）を、内部のレコード ID から導く。 */
export function cancellationIdOf(
  deps: Pick<DeskDeps, 'keys'>,
  tenantId: TenantId,
  cancelRef: string,
) {
  return deriveId(deps.keys, tenantId, 'cancel', cancelRef);
}

// ---- 共通 ----

function terminalTimes(now: Date) {
  return {
    terminalAt: now,
    purgeAfter: new Date(now.getTime() + DESK_TIMES.keepAfterTerminalDays * DAY_MS),
  };
}

/** 終端から7日を過ぎた、このテナントの行を消す（withTenant の中で呼ぶ）。 */
async function purge(tx: Tx, now: Date): Promise<void> {
  await tx.execute(sql`DELETE FROM company_api.desk_changes WHERE purge_after <= ${now}`);
}

/** 取消期限を過ぎた作成済みの行を、取消なしで受付を終えた（closed）にする。 */
async function closeExpired(tx: Tx, deps: DeskDeps, refs: readonly string[]): Promise<void> {
  const now = deps.now();
  const { terminalAt, purgeAfter } = terminalTimes(now);
  const closed = await tx.query<{ change_ref: string }>(
    sql`UPDATE company_api.desk_changes
           SET state = 'closed', terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
         WHERE change_ref = ANY(${[...refs]}::uuid[]) AND state = 'created' AND cancel_closes_at <= ${now}
     RETURNING change_ref`,
  );
  for (const _ of closed) await appendAudit(tx, deps.keys, DESK_CLOSED, {}, { now: deps.now });
}

async function lockByChangeMac(tx: Tx, changeMac: string): Promise<Row | undefined> {
  const [row] = await tx.query<Row>(
    sql`SELECT change_ref, user_id, request_mac, state, notice_at, cancel_closes_at, cancel_ref
          FROM company_api.desk_changes WHERE change_mac = ${changeMac} FOR UPDATE`,
  );
  return row;
}

async function lockByRequestMac(tx: Tx, requestMac: string): Promise<Row | undefined> {
  const [row] = await tx.query<Row>(
    sql`SELECT change_ref, user_id, request_mac, state, notice_at, cancel_closes_at, cancel_ref
          FROM company_api.desk_changes WHERE request_mac = ${requestMac} FOR UPDATE`,
  );
  return row;
}

function publicStateOf(row: Row, now: Date): DeskPublicState | undefined {
  switch (row.state) {
    case 'awaiting_notice':
      return 'window_open';
    case 'created':
      return row.cancel_closes_at !== null && row.cancel_closes_at > now
        ? 'window_open'
        : 'closed_without_cancellation';
    case 'cancel_requested':
      return 'cancellation_pending';
    case 'cancelled':
      return 'cancelled';
    case 'closed':
      return 'closed_without_cancellation';
    case 'not_created':
      return undefined;
  }
}

/** 0〜60秒の乱数（ミリ秒）。送るたびに独立に決める（不変条件5、テスト12）。 */
function initialDelayMs(): number {
  const bytes = randomBytesOf(4);
  const value =
    ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0);
  return (value >>> 0) % (CANCEL_SET_MAX_DELAY_MS + 1);
}

// ---- idp の内部 API から ----

export type RecordApprovalResult =
  | { readonly ok: true; readonly changeId: string }
  | { readonly ok: false; readonly reason: 'conflict' | 'not_found' };

/**
 * 承認した作成を記録して、変更ID を返す（/v1/desk_approve）。同じ内部のレコード ID の再送は、同じ変更ID を返す。
 * 同じ申請ID を別の承認で使おうとすると conflict。緊急停止したテナントと、取消の SET の受け口を登録していない
 * テナントでは断る（取消を届けられないため）。
 */
export async function recordApproval(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly changeRef: string; readonly requestId: string },
): Promise<RecordApprovalResult> {
  if (tenant.suspended || tenant.webhookUrl === undefined)
    return { ok: false, reason: 'not_found' };
  if (!DESK_REQUEST_ID_PATTERN.test(input.requestId)) return { ok: false, reason: 'conflict' };
  const tenantId = tenant.tenantId;
  const requestMac = await lookupMac(deps.keys, tenantId, 'request', input.requestId);
  const changeId = await changeIdOf(deps, tenantId, input.changeRef);
  const changeMac = await lookupMac(deps.keys, tenantId, 'change', changeId);
  try {
    return await deps.db.withTenant(tenantId, async (tx) => {
      const now = deps.now();
      await purge(tx, now);
      const [existing] = await tx.query<{ user_id: string; request_mac: string }>(
        sql`SELECT user_id, request_mac FROM company_api.desk_changes WHERE change_ref = ${input.changeRef}`,
      );
      if (existing !== undefined) {
        return existing.user_id === input.userId && existing.request_mac === requestMac
          ? ({ ok: true, changeId } as const)
          : ({ ok: false, reason: 'conflict' } as const);
      }
      await tx.execute(
        sql`INSERT INTO company_api.desk_changes
              (change_ref, tenant_id, user_id, request_mac, change_mac, action, state, approved_at)
            VALUES (${input.changeRef}, ${tenantId}, ${input.userId}, ${requestMac}, ${changeMac},
                    'desk.case.create', 'awaiting_notice', ${now})`,
      );
      await appendAudit(tx, deps.keys, DESK_CHANGE_RECORDED, {}, { now: deps.now });
      return { ok: true, changeId } as const;
    });
  } catch (error) {
    // 同じ申請ID の行がすでにある（一意制約）。
    if (error instanceof DbError && error.code === UNIQUE_VIOLATION) {
      return { ok: false, reason: 'conflict' };
    }
    throw error;
  }
}

/** 利用者の項目の状態と取消期限（/v1/desk_status）。正本にないもの、別の利用者のものは unknown。 */
export async function statusOf(
  deps: DeskDeps,
  tenantId: TenantId,
  userId: WarifuUserId,
  changeRefs: readonly string[],
): Promise<Map<string, DeskStatusItem>> {
  const out = new Map<string, DeskStatusItem>();
  if (changeRefs.length === 0) return out;
  await deps.db.withTenant(tenantId, async (tx) => {
    await purge(tx, deps.now());
    await closeExpired(tx, deps, changeRefs);
    const rows = await tx.query<Row>(
      sql`SELECT change_ref, user_id, request_mac, state, notice_at, cancel_closes_at, cancel_ref
            FROM company_api.desk_changes WHERE change_ref = ANY(${[...changeRefs]}::uuid[])`,
    );
    for (const row of rows) {
      if (row.user_id !== userId) continue;
      out.set(row.change_ref, {
        changeRef: row.change_ref,
        state: row.state,
        cancelDeadline: row.cancel_closes_at === null ? null : row.cancel_closes_at.toISOString(),
      });
    }
  });
  return out;
}

export type AcceptCancelResult =
  | { readonly ok: true; readonly state: DeskChangeState }
  | { readonly ok: false; readonly reason: 'closed' | 'not_found' };

/**
 * 取消を受理する（/v1/desk_cancel）。作成の知らせの前と、期限内の作成済みで受理し、取消の SET を送信待ちに入れる。
 * すでに受理していれば、同じ結果を返す。期限を過ぎたもの、受付を終えたもの、未作成のものは closed。
 */
export async function acceptCancel(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly changeRef: string },
): Promise<AcceptCancelResult> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    await closeExpired(tx, deps, [input.changeRef]);
    const cancelRef = randomUuid();
    const [accepted] = await tx.query<{ change_ref: string }>(
      sql`UPDATE company_api.desk_changes
             SET state = 'cancel_requested', cancel_ref = ${cancelRef}, cancel_accepted_at = ${now}
           WHERE change_ref = ${input.changeRef} AND user_id = ${input.userId}
             AND (state = 'awaiting_notice' OR (state = 'created' AND cancel_closes_at > ${now}))
       RETURNING change_ref`,
    );
    if (accepted !== undefined) {
      await tx.execute(
        sql`INSERT INTO company_api.set_outbox (event_id, tenant_id, event_type, state, change_ref, deliver_after)
            VALUES (${randomUuid()}, ${tenant.tenantId}, 'desk_cancellation', ${null}, ${input.changeRef},
                    ${new Date(now.getTime() + initialDelayMs())})`,
      );
      await appendAudit(tx, deps.keys, DESK_CANCEL_ACCEPTED, {}, { now: deps.now });
      return { ok: true, state: 'cancel_requested' } as const;
    }
    const [row] = await tx.query<Row>(
      sql`SELECT change_ref, user_id, request_mac, state, notice_at, cancel_closes_at, cancel_ref
            FROM company_api.desk_changes WHERE change_ref = ${input.changeRef}`,
    );
    if (row === undefined || row.user_id !== input.userId) {
      return { ok: false, reason: 'not_found' } as const;
    }
    // すでに受理した取消（作成されず取消完了を含む）は、同じ結果を返す。
    if (row.cancel_ref !== null) return { ok: true, state: row.state } as const;
    return { ok: false, reason: 'closed' } as const;
  });
}

// ---- 企業向けのルートから ----

export type DeskRouteResult<T = undefined> =
  | { readonly status: 200; readonly body: T }
  | { readonly status: 204 }
  | { readonly status: 404 | 409 };

/** 作成の知らせ（POST /v1/desk/change-notices）。知らせを記録した時刻から24時間を取消期限にする。 */
export async function recordNotice(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly requestId: string; readonly changeId: string },
): Promise<DeskRouteResult<{ state: DeskPublicState; cancel_closes_at: string | null }>> {
  if (
    !DESK_REQUEST_ID_PATTERN.test(input.requestId) ||
    !DESK_EXTERNAL_ID_PATTERN.test(input.changeId)
  ) {
    return { status: 404 };
  }
  const tenantId = tenant.tenantId;
  const changeMac = await lookupMac(deps.keys, tenantId, 'change', input.changeId);
  const requestMac = await lookupMac(deps.keys, tenantId, 'request', input.requestId);
  return deps.db.withTenant(tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByChangeMac(tx, changeMac);
    if (row === undefined) return { status: 404 } as const;
    // 既知の変更に、別の申請を結び付けようとした（差し替え）。
    if (!constantTimeEqual(Buffer.from(row.request_mac), Buffer.from(requestMac))) {
      return { status: 409 } as const;
    }
    if (row.state === 'not_created') return { status: 409 } as const;
    let deadline = row.cancel_closes_at;
    if (
      row.notice_at === null &&
      (row.state === 'awaiting_notice' || row.state === 'cancel_requested')
    ) {
      deadline = new Date(now.getTime() + DESK_TIMES.cancelWindowSeconds * 1000);
      await tx.execute(
        sql`UPDATE company_api.desk_changes
               SET state = ${row.state === 'awaiting_notice' ? 'created' : 'cancel_requested'},
                   notice_at = ${now}, cancel_closes_at = ${deadline}
             WHERE change_ref = ${row.change_ref}`,
      );
      await appendAudit(tx, deps.keys, DESK_NOTICE_RECORDED, {}, { now: deps.now });
      row.state = row.state === 'awaiting_notice' ? 'created' : row.state;
      row.notice_at = now;
      row.cancel_closes_at = deadline;
    }
    const state = publicStateOf(row, now);
    if (state === undefined) return { status: 409 } as const;
    return {
      status: 200,
      body: { state, cancel_closes_at: deadline === null ? null : deadline.toISOString() },
    } as const;
  });
}

/** 承認を受けたのに作らなかったことの報告（POST /v1/desk/execution-results）。 */
export async function recordNotCreated(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly requestId: string },
): Promise<DeskRouteResult> {
  if (!DESK_REQUEST_ID_PATTERN.test(input.requestId)) return { status: 404 };
  const requestMac = await lookupMac(deps.keys, tenant.tenantId, 'request', input.requestId);
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByRequestMac(tx, requestMac);
    if (row === undefined) return { status: 404 } as const;
    if (row.state === 'not_created') return { status: 204 } as const;
    const beforeNotice =
      row.notice_at === null &&
      (row.state === 'awaiting_notice' || row.state === 'cancel_requested');
    if (!beforeNotice) return { status: 409 } as const;
    const { terminalAt, purgeAfter } = terminalTimes(now);
    await tx.execute(
      sql`UPDATE company_api.desk_changes
             SET state = 'not_created', terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
           WHERE change_ref = ${row.change_ref}`,
    );
    await appendAudit(tx, deps.keys, DESK_NOT_CREATED, {}, { now: deps.now });
    return { status: 204 } as const;
  });
}

/** 取消を適用したことの報告（POST /v1/desk/cancellation-results）。 */
export async function recordCancellationResult(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly changeId: string; readonly cancellationId: string },
): Promise<DeskRouteResult> {
  if (
    !DESK_EXTERNAL_ID_PATTERN.test(input.changeId) ||
    !DESK_EXTERNAL_ID_PATTERN.test(input.cancellationId)
  ) {
    return { status: 404 };
  }
  const tenantId = tenant.tenantId;
  const changeMac = await lookupMac(deps.keys, tenantId, 'change', input.changeId);
  return deps.db.withTenant(tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByChangeMac(tx, changeMac);
    if (row === undefined) return { status: 404 } as const;
    if (row.cancel_ref === null) return { status: 409 } as const;
    const expected = await cancellationIdOf(deps, tenantId, row.cancel_ref);
    if (!constantTimeEqual(Buffer.from(expected), Buffer.from(input.cancellationId))) {
      return { status: 409 } as const;
    }
    if (row.state === 'cancelled' || row.state === 'not_created') return { status: 204 } as const;
    if (row.state !== 'cancel_requested') return { status: 409 } as const;
    const { terminalAt, purgeAfter } = terminalTimes(now);
    await tx.execute(
      sql`UPDATE company_api.desk_changes
             SET state = 'cancelled', terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
           WHERE change_ref = ${row.change_ref}`,
    );
    await appendAudit(tx, deps.keys, DESK_CANCEL_APPLIED, {}, { now: deps.now });
    return { status: 204 } as const;
  });
}

/**
 * 取消の受付の状態（POST /v1/desk/cancellation-status）。取消期限を過ぎた作成済みは、その場で受付を終える。
 * 取消の受理と同じ行のロックの中で決めるので、期限の直前に受理した取消があれば、必ず cancellation_pending になる。
 */
export async function cancellationStatus(
  deps: DeskDeps,
  tenant: CompanyTenant,
  input: { readonly changeId: string },
): Promise<DeskRouteResult<{ state: DeskPublicState }>> {
  if (!DESK_EXTERNAL_ID_PATTERN.test(input.changeId)) return { status: 404 };
  const changeMac = await lookupMac(deps.keys, tenant.tenantId, 'change', input.changeId);
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByChangeMac(tx, changeMac);
    if (row === undefined) return { status: 404 } as const;
    if (row.state === 'created' && row.cancel_closes_at !== null && row.cancel_closes_at <= now) {
      await closeExpired(tx, deps, [row.change_ref]);
      return { status: 200, body: { state: 'closed_without_cancellation' } } as const;
    }
    const state = publicStateOf(row, now);
    if (state === undefined) return { status: 409 } as const;
    return { status: 200, body: { state } } as const;
  });
}

/** 取消の SET に入れる変更ID と取消要求ID（送るときに正本から導く）。行がないか、取消がなければ undefined。 */
export async function cancellationEventOf(
  deps: DeskDeps,
  tenantId: TenantId,
  changeRef: string,
): Promise<{ readonly changeId: string; readonly cancellationId: string } | undefined> {
  const row = await deps.db.withTenant(tenantId, async (tx) => {
    const [found] = await tx.query<{ cancel_ref: string | null }>(
      sql`SELECT cancel_ref FROM company_api.desk_changes WHERE change_ref = ${changeRef}`,
    );
    return found;
  });
  if (row === undefined || row.cancel_ref === null) return undefined;
  return {
    changeId: await changeIdOf(deps, tenantId, changeRef),
    cancellationId: await cancellationIdOf(deps, tenantId, row.cancel_ref),
  };
}
