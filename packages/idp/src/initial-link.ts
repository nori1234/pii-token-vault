// 既存会員の初回紐付け（idp。ADR 0020、ADR 0028 の O-86・O-90・O-103）。
//
// 流れ（窓口の操作別承認と同じ形。ADR 0026）：
// 1. 企業のサーバーが、PAR の受け口に authorization_details（型 warifu_initial_link）を1件だけ送る。
//    action は initial_link.approve（最初の承認）か initial_link.finalize（待機の後の最終の承認）。
// 2. 本来のオリジンのインタラクションが、承認用のオリジンの /initial-link に引き継ぐ（InitialLinkHandoff。プロセスの
//    メモリに5分）。
// 3. 利用者は、承認用のオリジンで、UV 付きのパスキーで承認する。アサーションの利用者の sub が申請の subject と一致し、
//    その企業に接続済みで、回復の後の制限の中でないときだけ進める。
// 4. 最初の承認：idp.initial_link_items に approving の項目を置いてから（受信箱の項目の記録が先。O-103）、company-api に
//    承認を記録させる。企業には、トークンの応答で状態（pending_notice）だけを返す。JWT は出さない。
// 5. 最終の承認：自分の項目（approved）を引き、company-api に、待機の満了、2つ目の証跡、移行専用ID の一致を確かめさせ、
//    通ったときだけ、一度しか使えない紐付けの承認の JWT（鍵 initial_link）を作って、トークンの応答で渡す。
//
// 移行専用ID と JWT は、メモリ（引き継ぎ、Grant、認可コード）と内部 API の本文にだけ置く。DB とログには書かない
// （不変条件4）。画面に出す文言は、割符が決めた固定の文だけ（DESIGN.md 2章・3章）。

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
  INITIAL_LINK_ACTIONS,
  INITIAL_LINK_APPROVAL_TYP,
  INITIAL_LINK_DETAIL_TYPE,
  INITIAL_LINK_ID_PATTERN,
  INITIAL_LINK_IDP_TIMES,
  type InitialLinkAction,
  type InitialLinkState,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import {
  INITIAL_LINK_APPROVED,
  INITIAL_LINK_CANCEL_REQUESTED,
  INITIAL_LINK_DECLINED,
} from './audit-events.ts';
import type { DeviceKind } from './inbox.ts';
import type { RepoDeps } from './repo.ts';
import type { MacMemoryStore } from './storage.ts';

export const INITIAL_LINK_HANDOFF_KIND = 'InitialLinkHandoff';
/** 引き継ぎで、パスキーの確かめに失敗してよい回数（窓口と同じ。ADR 0026 の O-61）。 */
export const INITIAL_LINK_MAX_FAILURES = 3;
/** 正本に行がない approving の項目を消すまでの時間（O-103）。 */
export const INITIAL_LINK_APPROVING_GRACE_MS = 2 * 60_000;
/** 受信箱に出す初回紐付けの項目の上限（新しい順）。 */
export const INITIAL_LINK_ITEMS_LIMIT = 20;

const CHALLENGE_LABEL = 'warifu/initial-link/v1';
const CANCEL_CHALLENGE_LABEL = 'warifu/initial-link-cancel/v1';
const SUB_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const DAY_MS = 24 * 3600 * 1000;

// ---- 固定の文言（DESIGN.md 2章「初回紐付けの承認」「初回紐付けの最終確認」。警告文 I は public/app.js） ----

export const INITIAL_LINK_TEXTS = Object.freeze({
  operation: '旧会員の紐付け',
  purpose: 'この企業で確認された旧会員を、この割符のアカウントに結び付けます。',
  permanent: 'P0 では、結び付けた後に付け替えることはできません。',
  waiting:
    '承認すると、待機の時間が始まります。待機の間は、受信箱から取り消せます。待機が終わった後に、企業の画面からもう一度確かめるまで、紐付けは確定しません。',
  notice: '企業に、元の会員への知らせを依頼します。',
  final: '待機が終わりました。承認すると、旧会員がこの割符のアカウントに結び付きます。',
});

// ---- 申請（authorization_details の1件） ----

export interface InitialLinkDetail {
  readonly action: InitialLinkAction;
  /** 移行専用ID（不変条件4。DB とログに書かない）。 */
  readonly identifier: string;
  readonly subject: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** authorization_details の1件を検査する。型に合わなければ undefined（理由を区別しない）。 */
export function parseInitialLinkDetail(value: unknown): InitialLinkDetail | undefined {
  if (!isRecord(value) || value.type !== INITIAL_LINK_DETAIL_TYPE) return undefined;
  if (Object.keys(value).sort().join(',') !== 'actions,identifier,subject,type') return undefined;
  const { actions, identifier, subject } = value;
  const action = Array.isArray(actions) && actions.length === 1 ? actions[0] : undefined;
  if (typeof action !== 'string' || !(INITIAL_LINK_ACTIONS as readonly string[]).includes(action)) {
    return undefined;
  }
  if (typeof identifier !== 'string' || !INITIAL_LINK_ID_PATTERN.test(identifier)) return undefined;
  if (typeof subject !== 'string' || !SUB_PATTERN.test(subject)) return undefined;
  return { action: action as InitialLinkAction, identifier, subject };
}

/** RAR の1件の形（企業が送った形と同じ。キーの順を決める）。 */
export function initialLinkDetailJson(detail: InitialLinkDetail): Record<string, unknown> {
  return {
    type: INITIAL_LINK_DETAIL_TYPE,
    actions: [detail.action],
    identifier: detail.identifier,
    subject: detail.subject,
  };
}

export function sameInitialLinkDetail(a: InitialLinkDetail, b: InitialLinkDetail): boolean {
  return JSON.stringify(initialLinkDetailJson(a)) === JSON.stringify(initialLinkDetailJson(b));
}

// ---- 引き継ぎ（承認用のオリジンへ） ----

export type InitialLinkDeclineReason = 'denied' | 'unrecognized' | 'cancel';
export const INITIAL_LINK_DECLINE_REASONS: readonly InitialLinkDeclineReason[] = Object.freeze([
  'denied',
  'unrecognized',
  'cancel',
]);

export interface InitialLinkHandoff {
  readonly uid: string;
  readonly tenantId: TenantId;
  readonly clientId: string;
  readonly detail: InitialLinkDetail;
  readonly device: DeviceKind;
  /** ミリ秒。 */
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly state: 'pending' | 'approved' | 'declined';
  readonly failures: number;
  readonly approval?: {
    readonly userId: WarifuUserId;
    readonly approvedAt: number;
    /** 最初の承認の後の正本の状態（企業にはこれだけを返す）。 */
    readonly state?: InitialLinkState;
    /** 最終の承認の後の、紐付けの承認の JWT（不変条件4のトークン。メモリだけ）。 */
    readonly jwt?: string;
  };
  readonly declineReason?: InitialLinkDeclineReason;
}

function ttlOf(handoff: InitialLinkHandoff, nowMs: number): number {
  return Math.max(1, Math.ceil((handoff.expiresAt - nowMs) / 1000));
}

export async function saveInitialLinkHandoff(
  store: MacMemoryStore,
  handoff: InitialLinkHandoff,
  nowMs: number,
): Promise<void> {
  await store.set(INITIAL_LINK_HANDOFF_KIND, handoff.uid, handoff, ttlOf(handoff, nowMs));
}

export async function loadInitialLinkHandoff(
  store: MacMemoryStore,
  uid: string,
  nowMs: number,
): Promise<InitialLinkHandoff | undefined> {
  const handoff = await store.get<InitialLinkHandoff>(INITIAL_LINK_HANDOFF_KIND, uid);
  if (handoff === undefined || handoff.uid !== uid || handoff.expiresAt <= nowMs) return undefined;
  return handoff;
}

/** 承認を受け付けられる引き継ぎか（期限内、決まっていない、失敗が上限の前）。 */
export function isOpenInitialLink(
  handoff: InitialLinkHandoff | undefined,
  nowMs: number,
): handoff is InitialLinkHandoff {
  return (
    handoff !== undefined &&
    handoff.state === 'pending' &&
    handoff.expiresAt > nowMs &&
    handoff.failures < INITIAL_LINK_MAX_FAILURES
  );
}

/** 承認のチャレンジの材料。引き継ぎの中身と、決定（承認）と、uid と、使い捨ての乱数を、長さ付きでつなぐ。 */
export function initialLinkChallengeMessage(
  handoff: InitialLinkHandoff,
  nonce: string,
): Uint8Array {
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
    String(handoff.createdAt),
    String(handoff.expiresAt),
    handoff.device,
  ]);
}

// ---- 紐付けの承認の JWT（O-86 の手順7） ----

export class InitialLinkKeyError extends Error {
  override name = 'InitialLinkKeyError';
}

/** 紐付けの承認の JWT を作る。署名は鍵サービスの initial_link（ES256。r‖s の64バイト）。 */
export async function signInitialLinkApproval(
  keys: IdpKeyClient,
  input: {
    readonly issuer: string;
    readonly clientId: string;
    readonly sub: string;
    readonly initialLinkId: string;
    readonly acr: string;
    /** 秒。 */
    readonly authTime: number;
  },
): Promise<string> {
  const [current] = await keys.publicKeys('initial_link');
  if (current === undefined) throw new InitialLinkKeyError();
  const header = { alg: 'ES256', typ: INITIAL_LINK_APPROVAL_TYP, kid: current.kid };
  const payload = {
    iss: input.issuer,
    aud: input.clientId,
    sub: input.sub,
    purpose: 'initial_link',
    initial_link_id: input.initialLinkId,
    acr: input.acr,
    auth_time: input.authTime,
    iat: input.authTime,
    exp: input.authTime + INITIAL_LINK_IDP_TIMES.approvalTtlSeconds,
    jti: toBase64Url(randomBytesOf(16)),
  };
  const signingInput = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
  const { kid, signature } = await keys.sign('initial_link', utf8(signingInput));
  if (kid !== current.kid) throw new InitialLinkKeyError();
  return `${signingInput}.${toBase64Url(signature)}`;
}

// ---- 監査（O-102。移行専用ID、JWT は入れない） ----

export async function auditInitialLinkApproved(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
  stage: 'initial' | 'final',
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      INITIAL_LINK_APPROVED,
      { tenant_id: tenantId, stage },
      { now: repo.now },
    ),
  );
}

export async function auditInitialLinkDeclined(
  repo: RepoDeps,
  tenantId: TenantId,
  reason: InitialLinkDeclineReason,
): Promise<void> {
  await repo.db.withTenant(tenantId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      INITIAL_LINK_DECLINED,
      { tenant_id: tenantId, reason },
      { now: repo.now },
    ),
  );
}

export async function auditInitialLinkCancelRequested(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      INITIAL_LINK_CANCEL_REQUESTED,
      { tenant_id: tenantId },
      { now: repo.now },
    ),
  );
}

// ---- 受信箱の初回紐付けの項目（idp.initial_link_items。O-90、O-103） ----

interface ItemRow {
  item_id: string;
  tenant_id: string;
  link_ref: string;
  state: 'approving' | 'approved' | 'closed';
  created_at: Date;
}

export interface InitialLinkItem {
  readonly itemId: string;
  readonly tenantId: TenantId;
  /** company-api の正本の item_ref（idp が作った乱数の UUID）。 */
  readonly linkRef: string;
  readonly state: 'approving' | 'approved' | 'closed';
  readonly createdAt: Date;
}

function toItem(row: ItemRow): InitialLinkItem {
  return {
    itemId: row.item_id,
    tenantId: row.tenant_id as TenantId,
    linkRef: row.link_ref,
    state: row.state,
    createdAt: row.created_at,
  };
}

async function purgeItems(tx: Tx, now: Date): Promise<void> {
  await tx.execute(sql`DELETE FROM idp.initial_link_items WHERE purge_after <= ${now}`);
}

/** 最初の承認の初めに、approving の項目を置く（受信箱の項目の記録が先。O-103 の手順1）。 */
export async function insertApprovingInitialLinkItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<InitialLinkItem> {
  return repo.db.withWarifuUser(userId, async (tx) => {
    const now = repo.now();
    await purgeItems(tx, now);
    const row: ItemRow = {
      item_id: randomUuid(),
      tenant_id: tenantId,
      link_ref: randomUuid(),
      state: 'approving',
      created_at: now,
    };
    await tx.execute(
      sql`INSERT INTO idp.initial_link_items (item_id, user_id, tenant_id, link_ref, state, created_at)
          VALUES (${row.item_id}, ${userId}, ${tenantId}, ${row.link_ref}, 'approving', ${now})`,
    );
    return toItem(row);
  });
}

export async function markInitialLinkItemApproved(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: string,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    tx.execute(
      sql`UPDATE idp.initial_link_items SET state = 'approved'
           WHERE item_id = ${itemId} AND state = 'approving'`,
    ),
  );
}

export async function deleteInitialLinkItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: string,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    tx.execute(sql`DELETE FROM idp.initial_link_items WHERE item_id = ${itemId}`),
  );
}

/** 利用者の項目（新しい順）。消す予定を過ぎたものは、先に消す。tenantId を渡せば、そのテナントの分だけ。 */
export async function listInitialLinkItems(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId?: TenantId,
): Promise<InitialLinkItem[]> {
  return repo.db.withWarifuUser(userId, async (tx) => {
    await purgeItems(tx, repo.now());
    const rows =
      tenantId === undefined
        ? await tx.query<ItemRow>(
            sql`SELECT item_id, tenant_id, link_ref, state, created_at FROM idp.initial_link_items
                 ORDER BY created_at DESC, item_id LIMIT ${INITIAL_LINK_ITEMS_LIMIT}`,
          )
        : await tx.query<ItemRow>(
            sql`SELECT item_id, tenant_id, link_ref, state, created_at FROM idp.initial_link_items
                 WHERE tenant_id = ${tenantId}
                 ORDER BY created_at DESC, item_id LIMIT ${INITIAL_LINK_ITEMS_LIMIT}`,
          );
    return rows.map(toItem);
  });
}

/** 自分の項目を1つ引く。ほかの利用者のもの、ないものは undefined（区別しない）。 */
export async function findInitialLinkItem(
  repo: RepoDeps,
  userId: WarifuUserId,
  itemId: unknown,
): Promise<InitialLinkItem | undefined> {
  if (typeof itemId !== 'string' || !/^[0-9a-f-]{36}$/.test(itemId)) return undefined;
  return repo.db.withWarifuUser(userId, async (tx) => {
    const [row] = await tx.query<ItemRow>(
      sql`SELECT item_id, tenant_id, link_ref, state, created_at FROM idp.initial_link_items
           WHERE item_id = ${itemId}`,
    );
    return row === undefined ? undefined : toItem(row);
  });
}

/**
 * 正本の状態を受けて、項目を片付ける（窓口の settleDeskItems と同じ規則。ADR 0026 の O-63）。終端なら closed にして
 * 7日後に消す予定を付ける。正本にない approving の項目は、2分を過ぎたものだけ消す。正本にある approving の項目は approved にする。
 */
export async function settleInitialLinkItems(
  repo: RepoDeps,
  userId: WarifuUserId,
  input: {
    readonly terminal: readonly string[];
    readonly missing: readonly string[];
    readonly recorded: readonly string[];
  },
): Promise<void> {
  if (input.terminal.length === 0 && input.missing.length === 0 && input.recorded.length === 0) {
    return;
  }
  await repo.db.withWarifuUser(userId, async (tx) => {
    const now = repo.now();
    if (input.recorded.length > 0) {
      await tx.execute(
        sql`UPDATE idp.initial_link_items SET state = 'approved'
             WHERE item_id = ANY(${[...input.recorded]}::uuid[]) AND state = 'approving'`,
      );
    }
    if (input.terminal.length > 0) {
      await tx.execute(
        sql`UPDATE idp.initial_link_items
               SET state = 'closed',
                   purge_after = ${new Date(now.getTime() + INITIAL_LINK_IDP_TIMES.keepAfterTerminalDays * DAY_MS)}
             WHERE item_id = ANY(${[...input.terminal]}::uuid[]) AND state <> 'closed'`,
      );
    }
    if (input.missing.length > 0) {
      await tx.execute(
        sql`DELETE FROM idp.initial_link_items
             WHERE item_id = ANY(${[...input.missing]}::uuid[]) AND state = 'approving'
               AND created_at <= ${new Date(now.getTime() - INITIAL_LINK_APPROVING_GRACE_MS)}`,
      );
    }
  });
}

/** 取消のチャレンジの材料（項目、取消、利用者、承認用のセッション、乱数）。 */
export function initialLinkCancelChallengeMessage(input: {
  readonly item: InitialLinkItem;
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
    input.item.linkRef,
    input.item.createdAt.toISOString(),
  ]);
}

const TERMINAL: ReadonlySet<string> = new Set(['linked', 'cancelled', 'expired', 'not_linked']);

export function isTerminalInitialLinkState(state: InitialLinkState): boolean {
  return TERMINAL.has(state);
}
