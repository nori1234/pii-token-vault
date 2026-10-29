// 窓口の操作別承認（idp。ADR 0019、ADR 0026 の O-60〜O-62、O-68、O-69）。
//
// 流れ：
// 1. 企業のサーバーが、PAR の受け口に authorization_details（型 warifu_desk）を1件だけ送る（申請の登録。O-60）。
// 2. 利用者のブラウザが request_uri で認可の入口に来ると、本来のオリジンのインタラクションが、承認用のオリジンの
//    /desk に引き継ぐ（DeskHandoff。プロセスのメモリに5分。O-61）。
// 3. 利用者は、承認用のオリジンで、相手からの電話かを尋ねる問いに答え、内容に結び付いた UV 付きのパスキーで承認する。
//    アサーションの利用者の sub が、申請の subject と一致し、その企業に接続済みのときだけ承認する。
// 4. 作成（desk.case.create）なら、idp.desk_items と company-api の正本に記録してから（O-63）、
//    操作ごとの承認の JWT（鍵 op_approval。O-62）を作る。
// 5. 本来のオリジンでインタラクションを完了し、トークンの応答の authorization_details に JWT を入れて渡す。
//
// 申請ID、変更ID、JWT は、メモリ（引き継ぎ、Grant、認可コード）と内部 API の本文にだけ置く。DB とログには書かない
// （不変条件4）。画面に出す文言は、割符が決めた固定のラベルと文だけ（DESIGN.md 原則1・2、3章）。

import {
  lengthPrefixed,
  randomBytesOf,
  randomUuid,
  type TenantId,
  toBase64Url,
  utf8,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { sql, type Tx } from '@pii-token-vault/warifu-core/db';
import {
  DESK_ACTIONS,
  DESK_CASE_CATEGORIES,
  DESK_CASE_LANGUAGES,
  DESK_DETAIL_TYPE,
  DESK_REQUEST_ID_PATTERN,
  DESK_TIMES,
  type DeskAction,
  type DeskCaseCategory,
  type DeskCaseLanguage,
  isDeskWriteAction,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import { DESK_APPROVED, DESK_CANCEL_REQUESTED, DESK_DECLINED } from './audit-events.ts';
import type { DeviceKind } from './inbox.ts';
import type { RepoDeps } from './repo.ts';
import type { MacMemoryStore } from './storage.ts';

export const DESK_HANDOFF_KIND = 'DeskHandoff';
/** 引き継ぎで、パスキーの確かめに失敗してよい回数。超えたら、その申請は使えない（ADR 0026 の O-61）。 */
export const DESK_MAX_FAILURES = 3;
/** 操作ごとの承認の JWT の typ（ID トークンと取り違えないため。ADR 0026 の O-62）。 */
export const OP_APPROVAL_TYP = 'warifu-op-approval+jwt';
/** 正本に行がない approving の項目を消すまでの時間（承認の手順の途中のものを消さない）。 */
export const APPROVING_GRACE_MS = 2 * 60_000;
/** 受信箱に出す窓口の項目の上限（新しい順）。 */
export const DESK_ITEMS_LIMIT = 50;

const CHALLENGE_LABEL = 'warifu/desk/v1';
const CANCEL_CHALLENGE_LABEL = 'warifu/desk-cancel/v1';
const SUB_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const DAY_MS = 24 * 3600 * 1000;

// ---- 固定の文言（DESIGN.md 3章、ADR 0026 の O-61） ----

/** 操作型ごとの固定ラベル（DESIGN.md 3章）。 */
export const DESK_ACTION_LABELS: Readonly<Record<DeskAction, string>> = Object.freeze({
  'desk.case.status.read': '問い合わせ1件の状態を窓口に伝える',
  'desk.order.status.read': '注文1件の状態を窓口に伝える',
  'desk.case.create': '一般問い合わせを作成する',
});

/** 用途と権限の範囲（割符の固定文）。 */
export const DESK_SCOPE_TEXTS: Readonly<Record<DeskAction, string>> = Object.freeze({
  'desk.case.status.read':
    '窓口の担当者に、あなたが企業の画面で選んだ問い合わせ1件の状態（受付済み、対応中、完了など）だけを伝えます。問い合わせの内容や履歴は伝えません。',
  'desk.order.status.read':
    '窓口の担当者に、あなたが企業の画面で選んだ注文1件の状態（準備中、出荷済み、完了など）だけを伝えます。商品名、金額、届け先は伝えません。',
  'desk.case.create':
    '窓口の担当者が、あなたが選んだ種別と言語で、一般問い合わせを1件作成します。返金、届け先の変更、解約などの手続きはできません。',
});

export const DESK_VALIDITY_TEXT = '承認してから5分の間、この1回の操作にだけ使えます。';
export const DESK_CHANGE_TEXT =
  '承認の後に窓口で行われた変更は、この端末に通知され、通知から24時間まで取り消せます。';

export const DESK_CATEGORY_LABELS: Readonly<Record<DeskCaseCategory, string>> = Object.freeze({
  general: '一般的なお問い合わせ',
  order: '注文について',
  account: 'アカウントについて',
  other: 'その他',
});
export const DESK_LANGUAGE_LABELS: Readonly<Record<DeskCaseLanguage, string>> = Object.freeze({
  ja: '日本語',
  en: '英語',
});

// ---- 申請（authorization_details の1件） ----

export interface DeskChoices {
  readonly category: DeskCaseCategory;
  readonly language: DeskCaseLanguage;
}

export interface DeskDetail {
  readonly action: DeskAction;
  /** 申請ID（不変条件4。DB とログに書かない）。 */
  readonly identifier: string;
  readonly subject: string;
  /** 作成のときだけ。 */
  readonly choices: DeskChoices | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function keysOf(value: Record<string, unknown>): string {
  return Object.keys(value).sort().join(',');
}

/** authorization_details の1件を検査する。型に合わなければ undefined（理由を区別しない）。 */
export function parseDeskDetail(
  value: unknown,
  allowed: readonly DeskAction[],
): DeskDetail | undefined {
  if (!isRecord(value) || value.type !== DESK_DETAIL_TYPE) return undefined;
  const actions = value.actions;
  const action = Array.isArray(actions) && actions.length === 1 ? actions[0] : undefined;
  if (
    typeof action !== 'string' ||
    !(DESK_ACTIONS as readonly string[]).includes(action) ||
    !(allowed as readonly string[]).includes(action)
  ) {
    return undefined;
  }
  const deskAction = action as DeskAction;
  const write = isDeskWriteAction(deskAction);
  const expected = write
    ? 'actions,choices,identifier,subject,type'
    : 'actions,identifier,subject,type';
  if (keysOf(value) !== expected) return undefined;
  const { identifier, subject } = value;
  if (typeof identifier !== 'string' || !DESK_REQUEST_ID_PATTERN.test(identifier)) return undefined;
  if (typeof subject !== 'string' || !SUB_PATTERN.test(subject)) return undefined;
  if (!write) return { action: deskAction, identifier, subject, choices: null };
  const choices = value.choices;
  if (!isRecord(choices) || keysOf(choices) !== 'category,language') return undefined;
  const { category, language } = choices;
  if (
    typeof category !== 'string' ||
    !(DESK_CASE_CATEGORIES as readonly string[]).includes(category) ||
    typeof language !== 'string' ||
    !(DESK_CASE_LANGUAGES as readonly string[]).includes(language)
  ) {
    return undefined;
  }
  return {
    action: deskAction,
    identifier,
    subject,
    choices: { category: category as DeskCaseCategory, language: language as DeskCaseLanguage },
  };
}

/** oidc-provider の params.authorization_details（JSON の文字列）から。配列で1件だけ。 */
export function deskDetailFromParam(
  param: unknown,
  allowed: readonly DeskAction[],
): DeskDetail | undefined {
  if (typeof param !== 'string' || param.length > 4096) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(param);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) return undefined;
  return parseDeskDetail(parsed[0], allowed);
}

/** RAR の1件の形（企業が送った形と同じ。キーの順を決める）。 */
export function deskDetailJson(detail: DeskDetail): Record<string, unknown> {
  return {
    type: DESK_DETAIL_TYPE,
    actions: [detail.action],
    identifier: detail.identifier,
    subject: detail.subject,
    ...(detail.choices === null
      ? {}
      : { choices: { category: detail.choices.category, language: detail.choices.language } }),
  };
}

/** 2つの申請が同じか。 */
export function sameDeskDetail(a: DeskDetail, b: DeskDetail): boolean {
  return JSON.stringify(deskDetailJson(a)) === JSON.stringify(deskDetailJson(b));
}

// ---- 引き継ぎ（承認用のオリジンへ） ----

export type DeskDeclineReason = 'denied' | 'unrecognized' | 'incoming_call';
export const DESK_DECLINE_REASONS: readonly DeskDeclineReason[] = Object.freeze([
  'denied',
  'unrecognized',
  'incoming_call',
]);

export interface DeskHandoff {
  readonly uid: string;
  readonly tenantId: TenantId;
  readonly clientId: string;
  readonly detail: DeskDetail;
  readonly device: DeviceKind;
  /** ミリ秒。 */
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly state: 'pending' | 'approved' | 'declined';
  readonly failures: number;
  readonly approval?: {
    readonly userId: WarifuUserId;
    readonly approvedAt: number;
    /** 操作ごとの承認の JWT（不変条件4のトークン。メモリだけ）。 */
    readonly jwt: string;
  };
  readonly declineReason?: DeskDeclineReason;
}

function ttlOf(handoff: DeskHandoff, nowMs: number): number {
  return Math.max(1, Math.ceil((handoff.expiresAt - nowMs) / 1000));
}

export async function saveHandoff(
  store: MacMemoryStore,
  handoff: DeskHandoff,
  nowMs: number,
): Promise<void> {
  await store.set(DESK_HANDOFF_KIND, handoff.uid, handoff, ttlOf(handoff, nowMs));
}

export async function loadHandoff(
  store: MacMemoryStore,
  uid: string,
  nowMs: number,
): Promise<DeskHandoff | undefined> {
  const handoff = await store.get<DeskHandoff>(DESK_HANDOFF_KIND, uid);
  if (handoff === undefined || handoff.uid !== uid || handoff.expiresAt <= nowMs) return undefined;
  return handoff;
}

/** 承認を受け付けられる引き継ぎか（期限内、決まっていない、失敗が上限の前）。 */
export function isOpen(handoff: DeskHandoff | undefined, nowMs: number): handoff is DeskHandoff {
  return (
    handoff !== undefined &&
    handoff.state === 'pending' &&
    handoff.expiresAt > nowMs &&
    handoff.failures < DESK_MAX_FAILURES
  );
}

/** 窓口の承認のチャレンジの材料。引き継ぎの中身と、決定（承認）と、uid と、使い捨ての乱数を、長さ付きでつなぐ。 */
export function deskChallengeMessage(handoff: DeskHandoff, nonce: string): Uint8Array {
  const { detail } = handoff;
  return lengthPrefixed([
    CHALLENGE_LABEL,
    handoff.uid,
    'approved',
    nonce,
    handoff.tenantId,
    handoff.clientId,
    detail.action,
    detail.identifier,
    detail.subject,
    detail.choices?.category ?? '',
    detail.choices?.language ?? '',
    String(handoff.createdAt),
    String(handoff.expiresAt),
    handoff.device,
  ]);
}

// ---- 操作ごとの承認（O-62） ----

export class OpApprovalKeyError extends Error {
  override name = 'OpApprovalKeyError';
}

/** 操作ごとの承認の JWT を作る。署名は鍵サービスの op_approval（ES256。r‖s の64バイト）。 */
export async function signOpApproval(
  keys: IdpKeyClient,
  input: {
    readonly issuer: string;
    readonly clientId: string;
    readonly sub: string;
    readonly detail: DeskDetail;
    readonly changeId: string | null;
    readonly acr: string;
    /** 秒。 */
    readonly authTime: number;
  },
): Promise<string> {
  const [current] = await keys.publicKeys('op_approval');
  if (current === undefined) throw new OpApprovalKeyError();
  const header = { alg: 'ES256', typ: OP_APPROVAL_TYP, kid: current.kid };
  const payload = {
    iss: input.issuer,
    aud: input.clientId,
    sub: input.sub,
    purpose: 'desk',
    action: input.detail.action,
    request_id: input.detail.identifier,
    ...(input.changeId === null ? {} : { change_id: input.changeId }),
    acr: input.acr,
    auth_time: input.authTime,
    iat: input.authTime,
    exp: input.authTime + DESK_TIMES.approvalTtlSeconds,
    jti: toBase64Url(randomBytesOf(16)),
  };
  const signingInput = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
  const { kid, signature } = await keys.sign('op_approval', utf8(signingInput));
  if (kid !== current.kid) throw new OpApprovalKeyError();
  return `${signingInput}.${toBase64Url(signature)}`;
}

// ---- 監査 ----

const AUDIT_ACTIONS: Readonly<
  Record<DeskAction, 'case_status_read' | 'order_status_read' | 'case_create'>
> = Object.freeze({
  'desk.case.status.read': 'case_status_read',
  'desk.order.status.read': 'order_status_read',
  'desk.case.create': 'case_create',
});

/** 承認を、利用者の範囲の監査ログに残す（操作の種類とテナントだけ）。 */
export async function auditApproved(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
  action: DeskAction,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      DESK_APPROVED,
      { tenant_id: tenantId, action: AUDIT_ACTIONS[action] },
      { now: repo.now },
    ),
  );
}

/** 承認しなかったことを、テナントの範囲の監査ログに残す（利用者はまだ分からない）。 */
export async function auditDeclined(
  repo: RepoDeps,
  tenantId: TenantId,
  reason: DeskDeclineReason,
): Promise<void> {
  await repo.db.withTenant(tenantId, (tx) =>
    appendAudit(tx, repo.keys, DESK_DECLINED, { tenant_id: tenantId, reason }, { now: repo.now }),
  );
}

// ---- 受信箱の窓口の項目（idp.desk_items。O-63、O-68、O-69） ----

interface DeskItemRow {
  item_id: string;
  tenant_id: string;
  change_ref: string;
  action: 'desk.case.create';
  state: 'approving' | 'approved' | 'closed';
  created_at: Date;
  purge_after: Date | null;
}

export interface DeskItem {
  readonly itemId: string;
  readonly tenantId: TenantId;
  readonly changeRef: string;
  readonly action: 'desk.case.create';
  readonly state: 'approving' | 'approved' | 'closed';
  readonly createdAt: Date;
}

function toDeskItem(row: DeskItemRow): DeskItem {
  return {
    itemId: row.item_id,
    tenantId: row.tenant_id as TenantId,
    changeRef: row.change_ref,
    action: row.action,
    state: row.state,
    createdAt: row.created_at,
  };
}

async function purgeDeskItems(tx: Tx, now: Date): Promise<void> {
  await tx.execute(sql`DELETE FROM idp.desk_items WHERE purge_after <= ${now}`);
}

/** 承認の手順の初めに、approving の項目を置く。内部のレコード ID（change_ref）は乱数。 */
export async function insertApprovingItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<DeskItem> {
  return repo.db.withWarifuUser(userId, async (tx) => {
    const now = repo.now();
    await purgeDeskItems(tx, now);
    const row: DeskItemRow = {
      item_id: randomUuid(),
      tenant_id: tenantId,
      change_ref: randomUuid(),
      action: 'desk.case.create',
      state: 'approving',
      created_at: now,
      purge_after: null,
    };
    await tx.execute(
      sql`INSERT INTO idp.desk_items (item_id, user_id, tenant_id, change_ref, action, state, created_at)
          VALUES (${row.item_id}, ${userId}, ${tenantId}, ${row.change_ref}, ${row.action}, 'approving', ${now})`,
    );
    return toDeskItem(row);
  });
}

/** 正本に記録できたら approved にする。 */
export async function markItemApproved(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: string,
): Promise<boolean> {
  return repo.db.withWarifuUser(userId, async (tx) => {
    const updated = await tx.execute(
      sql`UPDATE idp.desk_items SET state = 'approved' WHERE item_id = ${itemId} AND state = 'approving'`,
    );
    return updated === 1;
  });
}

/** 正本に記録できなかった（同じ申請がすでに使われた、テナントが止まっている）項目を消す。 */
export async function deleteItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: string,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    tx.execute(sql`DELETE FROM idp.desk_items WHERE item_id = ${itemId}`),
  );
}

/** 利用者の窓口の項目（新しい順）。消す予定を過ぎたものは、先に消す。 */
export async function listDeskItems(repo: RepoDeps, userId: WarifuUserId): Promise<DeskItem[]> {
  return repo.db.withWarifuUser(userId, async (tx) => {
    await purgeDeskItems(tx, repo.now());
    const rows = await tx.query<DeskItemRow>(
      sql`SELECT item_id, tenant_id, change_ref, action, state, created_at, purge_after FROM idp.desk_items
           ORDER BY created_at DESC, item_id LIMIT ${DESK_ITEMS_LIMIT}`,
    );
    return rows.map(toDeskItem);
  });
}

/** 自分の項目を1つ引く。ほかの利用者のもの、ないものは undefined（区別しない）。 */
export async function findDeskItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: unknown,
): Promise<DeskItem | undefined> {
  if (typeof itemId !== 'string' || !/^[0-9a-f-]{36}$/.test(itemId)) return undefined;
  return repo.db.withWarifuUser(userId, async (tx) => {
    const [row] = await tx.query<DeskItemRow>(
      sql`SELECT item_id, tenant_id, change_ref, action, state, created_at, purge_after FROM idp.desk_items
           WHERE item_id = ${itemId}`,
    );
    return row === undefined ? undefined : toDeskItem(row);
  });
}

/**
 * 正本の状態を受けて、項目を片付ける。終端なら closed にして7日後に消す予定を付ける。正本にない approving の項目は、
 * 手順の途中のものを消さないよう、作ってから2分を過ぎたものだけ消す。
 */
export async function settleDeskItems(
  repo: RepoDeps,
  userId: WarifuUserId,
  input: { readonly terminal: readonly string[]; readonly missing: readonly string[] },
): Promise<void> {
  if (input.terminal.length === 0 && input.missing.length === 0) return;
  await repo.db.withWarifuUser(userId, async (tx) => {
    const now = repo.now();
    if (input.terminal.length > 0) {
      await tx.execute(
        sql`UPDATE idp.desk_items
               SET state = 'closed', purge_after = ${new Date(now.getTime() + DESK_TIMES.keepAfterTerminalDays * DAY_MS)}
             WHERE item_id = ANY(${[...input.terminal]}::uuid[]) AND state <> 'closed'`,
      );
    }
    if (input.missing.length > 0) {
      await tx.execute(
        sql`DELETE FROM idp.desk_items
             WHERE item_id = ANY(${[...input.missing]}::uuid[]) AND state = 'approving'
               AND created_at <= ${new Date(now.getTime() - APPROVING_GRACE_MS)}`,
      );
    }
  });
}

/** 取消を頼んだことを、利用者の範囲の監査ログに残す。 */
export async function auditCancelRequested(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    appendAudit(tx, repo.keys, DESK_CANCEL_REQUESTED, { tenant_id: tenantId }, { now: repo.now }),
  );
}

/** 取消のチャレンジの材料（ADR 0023 と同じ考え方。項目、取消、利用者、承認用のセッション、乱数）。 */
export function deskCancelChallengeMessage(input: {
  readonly item: DeskItem;
  readonly userId: WarifuUserId;
  readonly sessionRef: string;
  readonly nonce: string;
}): Uint8Array {
  return lengthPrefixed([
    CANCEL_CHALLENGE_LABEL,
    input.item.itemId,
    input.userId,
    'cancel',
    input.sessionRef,
    input.nonce,
    input.item.tenantId,
    input.item.changeRef,
    input.item.createdAt.toISOString(),
  ]);
}
