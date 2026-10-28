// 端末の受信箱（plan 4章「通知」、DESIGN.md 2章「受信箱」、ADR 0023）。
//
// - 受信箱（idp.inbox）を正とする。PWA はポーリングで受け取る。Web Push は P1。
// - 項目は2種類。承認待ち（approval）は、承認か拒否を受け付ける。知らせ（notice）は、読むだけ。
// - 中身は、割符のコードの型が検査した項目だけ（型の外の自由文、連絡先、トークンは入れない。不変条件4）。
//   企業の要求から来る値（受け取り場所の名称など）も、型が決めた項目として検査してから置く（DESIGN.md 1章）。
//   画面に出す文言（見出し、項目のラベル）は型が決め、企業名は登録簿から引く。
// - すべて withWarifuUser の中で読み書きする。項目の ID を知っていても、ほかの利用者の項目には届かない（RLS。テスト6）。
// - 承認と拒否は、DB の1つの文で状態を変える（同じ要求に両方が通らないようにする。ADR 0006）。
// - 保存期間を過ぎた行は、その利用者の受信箱を読むときと書くときに消す（利用者をまたいで消す経路は作らない。ADR 0023）。

import {
  lengthPrefixed,
  randomUuid,
  type TenantId,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { sql, type Tx } from '@pii-token-vault/warifu-core/db';
import { APPROVAL_DECIDED, APPROVAL_REQUESTED } from './audit-events.ts';
import type { RepoDeps } from './repo.ts';

/** 承認待ちの有効期間の範囲（秒）。値は型が決める（M7 の CIBA など）。 */
export const APPROVAL_TTL_MIN_SECONDS = 60;
export const APPROVAL_TTL_MAX_SECONDS = 15 * 60;
/** 決まった後、または期限が切れた後の承認待ちを残す日数。 */
export const APPROVAL_KEEP_DAYS = 30;
/** 知らせを残す日数。 */
export const NOTICE_KEEP_DAYS = 90;
/** 1人の利用者が同時に持てる承認待ち（期限内）の数。企業に受信箱を埋めさせない。 */
export const MAX_PENDING_APPROVALS = 20;
/** 一覧で返す件数の上限（新しい順）。 */
export const INBOX_LIST_LIMIT = 100;

const DAY_MS = 24 * 60 * 60 * 1000;
const TYPE_PATTERN = /^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,3}$/;
const ITEM_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CONTENT_KEY_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
const MAX_CONTENT_KEYS = 16;
const MAX_CONTENT_STRING = 200;
const CHALLENGE_LABEL = 'warifu/approval/v1';

/** 型が決めた中身。キーは小文字の英数字、値は短い文字列、整数、真偽値だけ（入れ子にしない）。 */
export type InboxContent = Readonly<Record<string, string | number | boolean>>;

/** 画面に出す1行（ラベルは型が決めた語、値は中身から作った文字列）。 */
export interface DisplayLine {
  readonly label: string;
  readonly value: string;
}

// ---- 知らせ ----

/** 知らせの型（M6）。plan 4章の「全端末に知らせる」もの。回復、窓口での変更、協力者は M7・M8 で足す。 */
export const NOTICE_TYPES = Object.freeze({
  'passkey.added': {
    title: 'パスキーが追加されました',
    lines: (content: InboxContent): readonly DisplayLine[] => [
      {
        label: '種類',
        value: content.synced === true ? '同期パスキー' : '端末固定のパスキー',
      },
    ],
  },
  'passkey.removed': { title: 'パスキーが削除されました', lines: () => [] },
  'email.registered': { title: 'メールアドレスが登録されました', lines: () => [] },
  'email.changed': { title: 'メールアドレスが変更されました', lines: () => [] },
} satisfies Record<
  string,
  { title: string; lines: (content: InboxContent) => readonly DisplayLine[] }
>);

export type NoticeType = keyof typeof NOTICE_TYPES;

// ---- 承認待ち ----

/** 端末での承認（step-up。警告文 A-2）か、窓口での承認（警告文 A-1）か（DESIGN.md 2章）。 */
export type ApprovalChannel = 'device' | 'desk';
export type ApprovalDecision = 'approved' | 'denied';

/**
 * 承認待ちの型。割符のコードで定義する（企業の設定からは作らない）。M6 では製品の型はまだなく、M7 で CIBA と
 * 操作に結び付けた承認の型を足す。createIdp の approvalTypes で渡す。
 */
export interface ApprovalType {
  readonly type: string;
  readonly channel: ApprovalChannel;
  /** 操作の種類（割符が決めた語。例：「配送先の変更」）。承認画面の見出しの次に出す。 */
  readonly operation: string;
  /** 中身を検査して、置く形にする。型に合わなければ undefined（承認画面を出さずに拒否する。DESIGN.md 1章）。 */
  parse(details: unknown): InboxContent | undefined;
  /** 画面に出す項目。parse の結果だけから作る。 */
  lines(content: InboxContent): readonly DisplayLine[];
  /** 承認か拒否が DB で確定した後に呼ぶ（M7 で、CIBA の結果を返すのに使う）。失敗しても確定は戻さない。 */
  settle?(input: {
    readonly itemId: string;
    readonly userId: WarifuUserId;
    readonly tenantId: TenantId;
    readonly decision: ApprovalDecision;
    readonly content: InboxContent;
  }): Promise<void>;
}

export class ApprovalTypes {
  readonly #byType = new Map<string, ApprovalType>();

  constructor(types: readonly ApprovalType[]) {
    for (const t of types) {
      if (!TYPE_PATTERN.test(t.type) || this.#byType.has(t.type) || t.type in NOTICE_TYPES) {
        throw new RangeError('承認待ちの型の名前が違うか、重なっている');
      }
      if (t.channel !== 'device' && t.channel !== 'desk') throw new RangeError('承認の種類が違う');
      if (typeof t.operation !== 'string' || t.operation.length === 0 || t.operation.length > 40) {
        throw new RangeError('操作の種類の語が違う');
      }
      this.#byType.set(t.type, Object.freeze(t));
    }
  }

  get(type: string): ApprovalType | undefined {
    return this.#byType.get(type);
  }
}

/** 中身が、決めた形（平らなオブジェクト、短い値）か。型の parse の後にも、もう一度確かめる。 */
export function isInboxContent(value: unknown): value is InboxContent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  if (entries.length > MAX_CONTENT_KEYS) return false;
  for (const [key, v] of entries) {
    if (!CONTENT_KEY_PATTERN.test(key)) return false;
    if (typeof v === 'boolean') continue;
    if (typeof v === 'number' && Number.isSafeInteger(v)) continue;
    if (
      typeof v === 'string' &&
      v.length <= MAX_CONTENT_STRING &&
      !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(v)
    ) {
      continue;
    }
    return false;
  }
  return true;
}

/** キーの順を決めた JSON（チャレンジの材料。jsonb はキーの順を保たないので、読み出した後に作る）。 */
export function canonicalContent(content: InboxContent): string {
  const keys = Object.keys(content).sort();
  return JSON.stringify(keys.map((key) => [key, content[key]]));
}

export function isItemId(value: unknown): value is string {
  return typeof value === 'string' && ITEM_ID_PATTERN.test(value);
}

// ---- 行 ----

interface InboxRow {
  item_id: string;
  kind: 'approval' | 'notice';
  type: string;
  tenant_id: string | null;
  content: unknown;
  state: 'pending' | 'approved' | 'denied' | 'unread' | 'read';
  created_at: Date;
  expires_at: Date | null;
  decided_at: Date | null;
  read_at: Date | null;
}

export interface InboxItem {
  readonly itemId: string;
  readonly kind: 'approval' | 'notice';
  readonly type: string;
  readonly tenantId: TenantId | null;
  readonly content: InboxContent;
  readonly state: InboxRow['state'];
  readonly createdAt: Date;
  readonly expiresAt: Date | null;
  readonly decidedAt: Date | null;
  readonly readAt: Date | null;
}

/** 承認待ち（期限内で、まだ決まっていないもの）。 */
export interface PendingApproval extends InboxItem {
  readonly kind: 'approval';
  readonly tenantId: TenantId;
  readonly expiresAt: Date;
}

function toItem(row: InboxRow): InboxItem | undefined {
  if (!isInboxContent(row.content)) return undefined;
  return {
    itemId: row.item_id,
    kind: row.kind,
    type: row.type,
    tenantId: row.tenant_id as TenantId | null,
    content: row.content,
    state: row.state,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    decidedAt: row.decided_at,
    readAt: row.read_at,
  };
}

/** 保存期間を過ぎた、この利用者の行を消す（withWarifuUser の中で呼ぶ）。 */
export async function purgeInbox(tx: Tx, now: Date): Promise<number> {
  return tx.execute(sql`DELETE FROM idp.inbox WHERE purge_after <= ${now}`);
}

/** 知らせを入れる。知らせのもとになった変更と同じトランザクションで呼ぶ（変更だけが残ることがないように）。 */
export async function insertNotice(
  tx: Tx,
  input: {
    readonly userId: WarifuUserId;
    readonly type: NoticeType;
    readonly content?: InboxContent;
    readonly now: Date;
  },
): Promise<void> {
  const content = input.content ?? {};
  if (!isInboxContent(content)) throw new RangeError('知らせの中身の形が違う');
  await purgeInbox(tx, input.now);
  await tx.execute(
    sql`INSERT INTO idp.inbox (item_id, user_id, kind, type, tenant_id, content, state, created_at, purge_after)
        VALUES (${randomUuid()}, ${input.userId}, 'notice', ${input.type}, ${null}, ${JSON.stringify(content)}::jsonb,
                'unread', ${input.now}, ${new Date(input.now.getTime() + NOTICE_KEEP_DAYS * DAY_MS)})`,
  );
}

export type RequestApprovalResult =
  | { readonly ok: true; readonly itemId: string; readonly expiresAt: Date }
  | { readonly ok: false; readonly reason: 'invalid' | 'too_many' };

/**
 * 承認待ちを作る（M7 の CIBA などが呼ぶ。HTTP のルートはない）。型に合わない中身は、置かずに断る。
 * 利用者が存在しなければ、外部キーで失敗する。
 */
export async function requestApproval(
  deps: RepoDeps & { readonly approvalTypes: ApprovalTypes },
  input: {
    readonly userId: WarifuUserId;
    readonly tenantId: TenantId;
    readonly type: string;
    readonly details: unknown;
    readonly ttlSeconds: number;
  },
): Promise<RequestApprovalResult> {
  const def = deps.approvalTypes.get(input.type);
  if (def === undefined) return { ok: false, reason: 'invalid' };
  if (
    !Number.isInteger(input.ttlSeconds) ||
    input.ttlSeconds < APPROVAL_TTL_MIN_SECONDS ||
    input.ttlSeconds > APPROVAL_TTL_MAX_SECONDS
  ) {
    return { ok: false, reason: 'invalid' };
  }
  const content = def.parse(input.details);
  if (content === undefined || !isInboxContent(content)) return { ok: false, reason: 'invalid' };
  return deps.db.withWarifuUser(input.userId, async (tx) => {
    const now = deps.now();
    await purgeInbox(tx, now);
    const pending = await tx.one<{ count: string }>(
      sql`SELECT pg_catalog.count(*) AS count FROM idp.inbox
           WHERE kind = 'approval' AND state = 'pending' AND expires_at > ${now}`,
    );
    if (Number(pending.count) >= MAX_PENDING_APPROVALS) {
      return { ok: false, reason: 'too_many' } as const;
    }
    const itemId = randomUuid();
    const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000);
    await tx.execute(
      sql`INSERT INTO idp.inbox (item_id, user_id, kind, type, tenant_id, content, state, created_at, expires_at,
                                 purge_after)
          VALUES (${itemId}, ${input.userId}, 'approval', ${def.type}, ${input.tenantId},
                  ${JSON.stringify(content)}::jsonb, 'pending', ${now}, ${expiresAt},
                  ${new Date(expiresAt.getTime() + APPROVAL_KEEP_DAYS * DAY_MS)})`,
    );
    await appendAudit(
      tx,
      deps.keys,
      APPROVAL_REQUESTED,
      { channel: def.channel, tenant_id: input.tenantId },
      { now: deps.now },
    );
    return { ok: true, itemId, expiresAt } as const;
  });
}

/** 受信箱の一覧（新しい順）。保存期間を過ぎた行は、先に消す。 */
export async function listInbox(deps: RepoDeps, userId: WarifuUserId): Promise<InboxItem[]> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    await purgeInbox(tx, deps.now());
    const rows = await tx.query<InboxRow>(
      sql`SELECT item_id, kind, type, tenant_id, content, state, created_at, expires_at, decided_at, read_at FROM idp.inbox ORDER BY created_at DESC, item_id LIMIT ${INBOX_LIST_LIMIT}`,
    );
    return rows.map(toItem).filter((item): item is InboxItem => item !== undefined);
  });
}

/** 知らせを読んだことにする。自分の未読の知らせでなければ false（ほかの利用者の ID と、ない ID を区別しない）。 */
export async function markNoticeRead(
  deps: RepoDeps,
  userId: WarifuUserId,
  itemId: string,
): Promise<boolean> {
  if (!isItemId(itemId)) return false;
  return deps.db.withWarifuUser(userId, async (tx) => {
    const updated = await tx.execute(
      sql`UPDATE idp.inbox SET state = 'read', read_at = ${deps.now()}
           WHERE item_id = ${itemId} AND kind = 'notice' AND state = 'unread'`,
    );
    return updated === 1;
  });
}

/** 期限内で、まだ決まっていない承認待ちを1つ引く。自分のものでなければ undefined。 */
export async function findPendingApproval(
  deps: RepoDeps,
  userId: WarifuUserId,
  itemId: unknown,
): Promise<PendingApproval | undefined> {
  if (!isItemId(itemId)) return undefined;
  return deps.db.withWarifuUser(userId, async (tx) => {
    const [row] = await tx.query<InboxRow>(
      sql`SELECT item_id, kind, type, tenant_id, content, state, created_at, expires_at, decided_at, read_at FROM idp.inbox
           WHERE item_id = ${itemId} AND kind = 'approval' AND state = 'pending' AND expires_at > ${deps.now()}`,
    );
    const item = row === undefined ? undefined : toItem(row);
    return item as PendingApproval | undefined;
  });
}

/** 期限内で、まだ決まっていない承認待ちの一覧（新しい順）。 */
export async function listPendingApprovals(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<PendingApproval[]> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const rows = await tx.query<InboxRow>(
      sql`SELECT item_id, kind, type, tenant_id, content, state, created_at, expires_at, decided_at, read_at FROM idp.inbox
           WHERE kind = 'approval' AND state = 'pending' AND expires_at > ${deps.now()}
           ORDER BY created_at DESC, item_id LIMIT ${MAX_PENDING_APPROVALS}`,
    );
    return rows
      .map(toItem)
      .filter((item): item is PendingApproval => item !== undefined && item.tenantId !== null);
  });
}

/**
 * 承認か拒否を確定する。状態の変更は1つの文で行い、期限内でまだ決まっていないときだけ通す
 * （同じ要求への承認と拒否が両方通ることはない。ADR 0006）。監査ログは同じトランザクションに残す。
 * 確定できなければ undefined（決まった後、期限切れ、ほかの利用者のもの、ないものを区別しない）。
 */
export async function decideApproval(
  deps: RepoDeps & { readonly approvalTypes: ApprovalTypes },
  input: {
    readonly userId: WarifuUserId;
    readonly itemId: string;
    readonly decision: ApprovalDecision;
  },
): Promise<PendingApproval | undefined> {
  if (!isItemId(input.itemId)) return undefined;
  return deps.db.withWarifuUser(input.userId, async (tx) => {
    const now = deps.now();
    const [row] = await tx.query<InboxRow>(
      sql`UPDATE idp.inbox SET state = ${input.decision}, decided_at = ${now}
           WHERE item_id = ${input.itemId} AND kind = 'approval' AND state = 'pending' AND expires_at > ${now}
       RETURNING item_id, kind, type, tenant_id, content, state, created_at, expires_at, decided_at, read_at`,
    );
    const item = row === undefined ? undefined : toItem(row);
    if (item === undefined || item.tenantId === null) return undefined;
    const def = deps.approvalTypes.get(item.type);
    await appendAudit(
      tx,
      deps.keys,
      APPROVAL_DECIDED,
      {
        decision: input.decision,
        channel: def?.channel ?? 'device',
        tenant_id: item.tenantId,
      },
      { now: deps.now },
    );
    return item as PendingApproval;
  });
}

/**
 * 承認と拒否のチャレンジの材料（ADR 0023）。要求の内容（型、企業、中身、時刻）と、決定（承認か拒否か）、
 * 利用者、承認のセッション、使い捨ての乱数を、長さ付きでつなぐ。鍵サービスの mac(approval_challenge) にかけた値を
 * WebAuthn の challenge にするので、署名は、この内容のこの決定にだけ結び付く。
 */
export function approvalChallengeMessage(input: {
  readonly item: PendingApproval;
  readonly userId: WarifuUserId;
  readonly decision: ApprovalDecision;
  readonly sessionRef: string;
  readonly nonce: string;
}): Uint8Array {
  const { item } = input;
  return lengthPrefixed([
    CHALLENGE_LABEL,
    item.itemId,
    input.userId,
    input.decision,
    input.sessionRef,
    input.nonce,
    item.type,
    item.tenantId,
    canonicalContent(item.content),
    item.createdAt.toISOString(),
    item.expiresAt.toISOString(),
  ]);
}
