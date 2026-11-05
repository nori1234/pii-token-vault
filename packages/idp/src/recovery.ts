// 回復（plan 4章、ADR 0003、ADR 0027）。肯定リスト (b) の「回復コード、協力者の承認、待機の満了の3つがそろったとき」
// だけで回復を成立させる（不変条件1(b)）。メール、電話、氏名などは、どこでも入力にしない（PRN-85）。
//
// - 回復コードは、利用者 ID と80ビットの秘密。保存するのは mac(recovery_code, …) だけ（不変条件4、O-73）。
//   利用者 ID は、DB の境界（withWarifuUser）を決めるためだけに使い、それだけでは何も許可しない（不変条件1(c)）。
// - 協力関係は、内部 ID の組だけ（PRN-91）。表示名は協力者の端末の中だけ。
// - 招待と、協力者の承認の結び付けは、プロセスのメモリ（MacMemoryStore）に置く（10分、1回だけ。O-74、O-76）。
// - DB は、持ち主か協力者の、どちらか1人の範囲（withWarifuUser）でだけ読み書きする（不変条件8）。
// - 協力者への知らせは、持ち主の変更と同じトランザクションで送信待ち（idp.helper_notice_outbox）に置き、確定の後に
//   flushHelperNotices で協力者の受信箱へ移す。移せなくても、持ち主の変更は取り消さず、後で送り直す（O-79）。

import {
  constantTimeEqual,
  isUuid,
  lengthPrefixed,
  randomBytesOf,
  randomUuid,
  uuidBytes,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import { sql, type Tx } from '@pii-token-vault/warifu-core/db';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import {
  RECOVERY_CANCELLED,
  RECOVERY_CODE_ISSUED,
  RECOVERY_COMPLETED,
  RECOVERY_EXPIRED,
  RECOVERY_HELPER_APPROVED,
  RECOVERY_HELPER_REMOVED,
  RECOVERY_HELPER_SET,
  RECOVERY_STARTED,
} from './audit-events.ts';
import { type DeviceKind, insertNotice, type NoticeType } from './inbox.ts';
import { insertCredential, type NewCredential, type RepoDeps } from './repo.ts';
import type { MacMemoryStore } from './storage.ts';
import { uuidFromBytes } from './webauthn.ts';

const DAY_MS = 24 * 3600 * 1000;

/** 回復の時間（ADR 0027。値の考え方は ADR 0012 の決定7）。 */
export const RECOVERY_TIMES = Object.freeze({
  /** 待機の既定（O-77）。 */
  defaultWaitSeconds: 72 * 3600,
  /** 本番（https のオリジン）での待機の下限。起動時に強制する。 */
  minProductionWaitSeconds: 24 * 3600,
  /** 協力者の承認を待つ期限。 */
  helperDeadlineSeconds: 24 * 3600,
  /** 取消の後に、回復を始められない期間（PRN-89）。 */
  lockoutDays: 14,
  /** 回復の後の制限（PRN-90）。 */
  restrictionDays: 7,
  /** 協力者が、直近にこの日数の中で回復かパスキーの追加をしていたら、承認を受け付けない（PRN-87）。 */
  helperFreshDays: 14,
  /** 招待と結び付けのコードの有効期間（ADR 0012 の決定5）。 */
  codeTtlSeconds: 600,
  /** 回復の記録を、終端から消すまで（O-83）。 */
  keepAfterEndDays: 90,
});

// ---- Crockford の base32（読み間違えにくい文字だけ。O→0、I と L→1 に読み替える） ----

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const MAX_INPUT = 128;

export function crockfordEncode(bytes: Uint8Array): string {
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

/** 長さが byteLength の値に戻す。形が違う、余りのビットが0でないときは undefined。 */
export function crockfordDecode(input: unknown, byteLength: number): Uint8Array | undefined {
  if (typeof input !== 'string' || input.length > MAX_INPUT) return undefined;
  const text = input.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (text.length !== Math.ceil((byteLength * 8) / 5)) return undefined;
  const out = new Uint8Array(byteLength);
  let value = 0;
  let bits = 0;
  let index = 0;
  for (const char of text) {
    const digit = CROCKFORD.indexOf(char);
    if (digit < 0) return undefined;
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      out[index] = (value >>> (bits - 8)) & 255;
      index += 1;
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  if (index !== byteLength || value !== 0) return undefined;
  return out;
}

function grouped(text: string, size: number): string {
  const groups: string[] = [];
  for (let i = 0; i < text.length; i += size) groups.push(text.slice(i, i + size));
  return groups.join('-');
}

// ---- 回復コード（O-73） ----

const SECRET_BYTES = 10;
const CODE_BYTES = 16 + SECRET_BYTES;
const CODE_LABEL = 'warifu/recovery-code/v1';

export function formatRecoveryCode(userId: WarifuUserId, secret: Uint8Array): string {
  const bytes = new Uint8Array(CODE_BYTES);
  bytes.set(uuidBytes(userId), 0);
  bytes.set(secret, 16);
  return grouped(crockfordEncode(bytes), 6);
}

export function parseRecoveryCode(
  input: unknown,
): { readonly userId: WarifuUserId; readonly secret: Uint8Array } | undefined {
  const bytes = crockfordDecode(input, CODE_BYTES);
  if (bytes === undefined) return undefined;
  const userId = uuidFromBytes(bytes.subarray(0, 16));
  if (!isUuid(userId)) return undefined;
  return { userId: userId as WarifuUserId, secret: bytes.slice(16) };
}

async function codeMacOf(
  keys: IdpKeyClient,
  userId: WarifuUserId,
  secret: Uint8Array,
): Promise<Uint8Array> {
  return keys.mac('recovery_code', lengthPrefixed([CODE_LABEL, userId, secret]));
}

// ---- 招待と結び付けのコード（O-74、O-76）。120ビット、24文字 ----

const SHORT_BYTES = 15;

export function newShortCode(): string {
  return grouped(crockfordEncode(randomBytesOf(SHORT_BYTES)), 6);
}

/** 入力を、保存先の鍵にする正規の形（区切りなし）にする。形が違えば undefined。 */
export function shortCodeKey(input: unknown): string | undefined {
  const bytes = crockfordDecode(input, SHORT_BYTES);
  return bytes === undefined ? undefined : crockfordEncode(bytes);
}

export const INVITE_KIND = 'RecoveryInvite';
export const BINDING_KIND = 'RecoveryBinding';

/** 協力者の招待（メモリ）。受け入れた協力者と、協力関係の ID は、受け入れの時に決める。 */
export interface RecoveryInvite {
  readonly ownerUserId: WarifuUserId;
  readonly expiresAt: number;
  readonly state: 'open' | 'accepted';
  readonly helperUserId?: WarifuUserId;
  readonly relationshipId?: string;
}

/** 協力者の承認の結び付け（メモリ）。新しい端末に出したコードと、回復の記録と、回復待ちのパスキーの組。 */
export interface RecoveryBinding {
  readonly userId: WarifuUserId;
  readonly attemptId: string;
  /** 回復待ちのパスキーの ID（base64url）。 */
  readonly credentialId: string;
  readonly helperUserId: WarifuUserId;
  readonly expiresAt: number;
}

/** 招待を作る。持ち主の開いている招待は1つだけ（前のものは消す）。 */
export async function createInvite(
  store: MacMemoryStore,
  ownerUserId: WarifuUserId,
  nowMs: number,
): Promise<{ code: string; expiresAt: number }> {
  store.deleteWhere(
    INVITE_KIND,
    (value) => (value as RecoveryInvite | undefined)?.ownerUserId === ownerUserId,
  );
  const code = newShortCode();
  const invite: RecoveryInvite = {
    ownerUserId,
    expiresAt: nowMs + RECOVERY_TIMES.codeTtlSeconds * 1000,
    state: 'open',
  };
  await store.set(INVITE_KIND, shortCodeKey(code) as string, invite, RECOVERY_TIMES.codeTtlSeconds);
  return { code, expiresAt: invite.expiresAt };
}

export async function loadInvite(
  store: MacMemoryStore,
  code: unknown,
  nowMs: number,
): Promise<{ key: string; invite: RecoveryInvite } | undefined> {
  const key = shortCodeKey(code);
  if (key === undefined) return undefined;
  const invite = await store.get<RecoveryInvite>(INVITE_KIND, key);
  if (invite === undefined || invite.expiresAt <= nowMs) return undefined;
  return { key, invite };
}

/** 結び付けを作る。回復の記録ごとに1つだけ（前のものは消す）。 */
export async function createBinding(
  store: MacMemoryStore,
  input: Omit<RecoveryBinding, 'expiresAt'>,
  nowMs: number,
): Promise<{ code: string; expiresAt: number }> {
  store.deleteWhere(
    BINDING_KIND,
    (value) => (value as RecoveryBinding | undefined)?.attemptId === input.attemptId,
  );
  const code = newShortCode();
  const binding: RecoveryBinding = {
    ...input,
    expiresAt: nowMs + RECOVERY_TIMES.codeTtlSeconds * 1000,
  };
  await store.set(
    BINDING_KIND,
    shortCodeKey(code) as string,
    binding,
    RECOVERY_TIMES.codeTtlSeconds,
  );
  return { code, expiresAt: binding.expiresAt };
}

export async function loadBinding(
  store: MacMemoryStore,
  code: unknown,
  nowMs: number,
): Promise<{ key: string; binding: RecoveryBinding } | undefined> {
  const key = shortCodeKey(code);
  if (key === undefined) return undefined;
  const binding = await store.get<RecoveryBinding>(BINDING_KIND, key);
  if (binding === undefined || binding.expiresAt <= nowMs) return undefined;
  return { key, binding };
}

// ---- 知らせ ----

/** 協力者への知らせを、持ち主の範囲の送信待ちに置く（持ち主の変更と同じトランザクションで呼ぶ）。 */
async function queueHelperNotice(
  tx: Tx,
  input: {
    readonly ownerUserId: WarifuUserId;
    readonly helperUserId: string;
    readonly relationshipId: string;
    readonly type: NoticeType;
    readonly now: Date;
  },
): Promise<void> {
  await tx.execute(
    sql`INSERT INTO idp.helper_notice_outbox
          (notice_id, owner_user_id, helper_user_id, relationship_id, type, created_at)
        VALUES (${randomUuid()}, ${input.ownerUserId}, ${input.helperUserId}, ${input.relationshipId},
                ${input.type}, ${input.now})`,
  );
}

/**
 * 持ち主の送信待ちにある協力者への知らせを、協力者の受信箱へ移す。協力者の受信箱には、送信待ちの ID を項目の ID に
 * して置くので、途中で失敗して送り直しても、同じ知らせは1つだけになる。移した数を返す。失敗したら例外にする
 * （呼び出し元は、持ち主の変更を取り消さず、後で送り直す）。
 */
export async function flushHelperNotices(
  deps: RepoDeps,
  ownerUserId: WarifuUserId,
): Promise<number> {
  const pending = await deps.db.withWarifuUser(ownerUserId, (tx) =>
    tx.query<{
      notice_id: string;
      helper_user_id: string;
      relationship_id: string;
      type: NoticeType;
    }>(
      sql`SELECT notice_id, helper_user_id, relationship_id, type FROM idp.helper_notice_outbox
           ORDER BY created_at, notice_id LIMIT 20`,
    ),
  );
  for (const row of pending) {
    const helperUserId = row.helper_user_id as WarifuUserId;
    await deps.db.withWarifuUser(helperUserId, (tx) =>
      insertNotice(tx, {
        userId: helperUserId,
        type: row.type,
        content: { relationship: row.relationship_id },
        now: deps.now(),
        itemId: row.notice_id,
      }),
    );
    await deps.db.withWarifuUser(ownerUserId, (tx) =>
      tx.execute(sql`DELETE FROM idp.helper_notice_outbox WHERE notice_id = ${row.notice_id}`),
    );
  }
  return pending.length;
}

interface HelperRow {
  relationship_id: string;
  helper_user_id: string;
  created_at: Date;
}

async function helperOfOwner(tx: Tx, ownerUserId: WarifuUserId): Promise<HelperRow | undefined> {
  const [row] = await tx.query<HelperRow>(
    sql`SELECT relationship_id, helper_user_id, created_at FROM idp.helpers
         WHERE owner_user_id = ${ownerUserId}`,
  );
  return row;
}

// ---- 回復コードの作成と作り直し ----

/**
 * 回復コードを作る（作り直すと前のコードは使えなくなる）。平文は返り値だけにあり、どこにも残さない。
 * 持ち主の受信箱に知らせ、作り直しなら協力者にも知らせる（ADR 0012 の決定3）。
 */
export async function issueRecoveryCode(
  deps: RepoDeps,
  keys: IdpKeyClient,
  userId: WarifuUserId,
): Promise<{ readonly code: string; readonly reissued: boolean }> {
  const secret = randomBytesOf(SECRET_BYTES);
  const mac = await codeMacOf(keys, userId, secret);
  const reissued = await deps.db.withWarifuUser(userId, async (tx) => {
    const now = deps.now();
    const [existing] = await tx.query(
      sql`SELECT user_id FROM idp.recovery_codes WHERE user_id = ${userId} FOR UPDATE`,
    );
    if (existing === undefined) {
      await tx.execute(
        sql`INSERT INTO idp.recovery_codes (user_id, code_mac, created_at)
            VALUES (${userId}, ${mac}, ${now})`,
      );
    } else {
      await tx.execute(
        sql`UPDATE idp.recovery_codes SET code_mac = ${mac}, created_at = ${now}
             WHERE user_id = ${userId}`,
      );
    }
    const reissued = existing !== undefined;
    await insertNotice(tx, {
      userId,
      type: reissued ? 'recovery.code_reissued' : 'recovery.code_issued',
      now,
    });
    const helper = await helperOfOwner(tx, userId);
    if (reissued && helper !== undefined) {
      await queueHelperNotice(tx, {
        ownerUserId: userId,
        helperUserId: helper.helper_user_id,
        relationshipId: helper.relationship_id,
        type: 'helper.code_reissued',
        now,
      });
    }
    await appendAudit(tx, deps.keys, RECOVERY_CODE_ISSUED, { reissued }, { now: deps.now });
    return reissued;
  });
  return { code: formatRecoveryCode(userId, secret), reissued };
}

// ---- 状態 ----

export interface RecoveryAttemptView {
  readonly attemptId: string;
  readonly state: 'awaiting_helper' | 'waiting';
  readonly device: DeviceKind;
  readonly startedAt: Date;
  readonly helperDeadline: Date;
  readonly readyAt: Date | null;
}

interface AttemptRow {
  attempt_id: string;
  helper_user_id: string;
  state: 'awaiting_helper' | 'waiting' | 'completed' | 'cancelled' | 'expired';
  request_device: DeviceKind;
  started_at: Date;
  helper_deadline: Date;
  ready_at: Date | null;
}

/**
 * 終わった回復の記録を片付ける（withWarifuUser の中で呼ぶ）。協力者の承認の期限を過ぎたものは期限切れにして
 * 回復待ちのパスキーを消し、終端から90日を過ぎた記録を消す（O-77、O-83）。
 */
async function settleAttempts(tx: Tx, deps: RepoDeps, userId: WarifuUserId): Promise<void> {
  const now = deps.now();
  const expired = await tx.query<{ attempt_id: string }>(
    sql`UPDATE idp.recovery_attempts
           SET state = 'expired', ended_at = ${now},
               purge_after = ${new Date(now.getTime() + RECOVERY_TIMES.keepAfterEndDays * DAY_MS)}
         WHERE state = 'awaiting_helper' AND helper_deadline <= ${now}
     RETURNING attempt_id`,
  );
  for (const row of expired) {
    await tx.execute(
      sql`DELETE FROM idp.credentials WHERE state = 'pending' AND recovery_attempt_id = ${row.attempt_id}`,
    );
    await insertNotice(tx, { userId, type: 'recovery.expired', now });
    await appendAudit(tx, deps.keys, RECOVERY_EXPIRED, {}, { now: deps.now });
  }
  await tx.execute(sql`DELETE FROM idp.recovery_attempts WHERE purge_after <= ${now}`);
}

async function activeAttempt(tx: Tx): Promise<AttemptRow | undefined> {
  const [row] = await tx.query<AttemptRow>(
    sql`SELECT attempt_id, helper_user_id, state, request_device, started_at, helper_deadline, ready_at
          FROM idp.recovery_attempts WHERE state IN ('awaiting_helper', 'waiting')`,
  );
  return row;
}

function viewOf(row: AttemptRow): RecoveryAttemptView {
  return {
    attemptId: row.attempt_id,
    state: row.state as 'awaiting_helper' | 'waiting',
    device: row.request_device,
    startedAt: row.started_at,
    helperDeadline: row.helper_deadline,
    readyAt: row.ready_at,
  };
}

export interface RecoverySettings {
  readonly codeCreatedAt: Date | null;
  readonly helper: { readonly relationshipId: string; readonly createdAt: Date } | null;
  /** 回復の後の制限の終わり（制限の中でなければ null）。 */
  readonly restrictedUntil: Date | null;
  readonly attempt: RecoveryAttemptView | null;
}

export async function recoverySettings(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<RecoverySettings> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    await settleAttempts(tx, deps, userId);
    const [code] = await tx.query<{ created_at: Date }>(
      sql`SELECT created_at FROM idp.recovery_codes WHERE user_id = ${userId}`,
    );
    const helper = await helperOfOwner(tx, userId);
    const attempt = await activeAttempt(tx);
    return {
      codeCreatedAt: code?.created_at ?? null,
      helper:
        helper === undefined
          ? null
          : { relationshipId: helper.relationship_id, createdAt: helper.created_at },
      restrictedUntil: await restrictedUntilIn(tx, deps.now()),
      attempt: attempt === undefined ? null : viewOf(attempt),
    };
  });
}

/** いまの利用者の、回復の後の制限の終わり（withWarifuUser の中で呼ぶ）。制限の中でなければ null。 */
async function restrictedUntilIn(tx: Tx, now: Date): Promise<Date | null> {
  const [user] = await tx.query<{ recovered_at: Date | null }>(
    sql`SELECT recovered_at FROM idp.users`,
  );
  if (user?.recovered_at === null || user?.recovered_at === undefined) return null;
  const until = new Date(user.recovered_at.getTime() + RECOVERY_TIMES.restrictionDays * DAY_MS);
  return until > now ? until : null;
}

/** 回復の後の制限の終わり（制限の中でなければ null）。PWA の画面に出す。 */
export async function recoveryRestrictedUntil(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<Date | null> {
  return deps.db.withWarifuUser(userId, (tx) => restrictedUntilIn(tx, deps.now()));
}

/** 回復の後の制限の中か（PRN-90）。協力者の変更、パスキーの削除、メールの登録と変更、高リスクの承認の前に呼ぶ。 */
export async function isRecoveryRestricted(deps: RepoDeps, userId: WarifuUserId): Promise<boolean> {
  return deps.db.withWarifuUser(
    userId,
    async (tx) => (await restrictedUntilIn(tx, deps.now())) !== null,
  );
}

// ---- 協力者（O-74） ----

/** 協力者を登録する（入れ替えなら前の協力関係を消す）。両者（と前の協力者）の受信箱に知らせる。 */
export async function setHelper(
  deps: RepoDeps,
  input: {
    readonly ownerUserId: WarifuUserId;
    readonly helperUserId: WarifuUserId;
    readonly relationshipId: string;
  },
): Promise<boolean> {
  if (input.ownerUserId === input.helperUserId) return false;
  const previous = await deps.db.withWarifuUser(input.ownerUserId, async (tx) => {
    const now = deps.now();
    if ((await restrictedUntilIn(tx, now)) !== null) return 'restricted' as const;
    const old = await helperOfOwner(tx, input.ownerUserId);
    if (old !== undefined) {
      await tx.execute(sql`DELETE FROM idp.helpers WHERE relationship_id = ${old.relationship_id}`);
    }
    await tx.execute(
      sql`INSERT INTO idp.helpers (relationship_id, owner_user_id, helper_user_id, created_at)
          VALUES (${input.relationshipId}, ${input.ownerUserId}, ${input.helperUserId}, ${now})`,
    );
    await insertNotice(tx, { userId: input.ownerUserId, type: 'helper.set', now });
    await queueHelperNotice(tx, {
      ownerUserId: input.ownerUserId,
      helperUserId: input.helperUserId,
      relationshipId: input.relationshipId,
      type: 'helper.added',
      now,
    });
    if (old !== undefined && old.helper_user_id !== input.helperUserId) {
      await queueHelperNotice(tx, {
        ownerUserId: input.ownerUserId,
        helperUserId: old.helper_user_id,
        relationshipId: old.relationship_id,
        type: 'helper.ended',
        now,
      });
    }
    await appendAudit(
      tx,
      deps.keys,
      RECOVERY_HELPER_SET,
      { replaced: old !== undefined },
      { now: deps.now },
    );
    return 'set' as const;
  });
  return previous === 'set';
}

/** 協力者を外す。外せたら true（制限の中、協力者がいないときは false）。 */
export async function removeHelper(deps: RepoDeps, ownerUserId: WarifuUserId): Promise<boolean> {
  const removed = await deps.db.withWarifuUser(ownerUserId, async (tx) => {
    const now = deps.now();
    if ((await restrictedUntilIn(tx, now)) !== null) return undefined;
    const old = await helperOfOwner(tx, ownerUserId);
    if (old === undefined) return undefined;
    await tx.execute(sql`DELETE FROM idp.helpers WHERE relationship_id = ${old.relationship_id}`);
    await insertNotice(tx, { userId: ownerUserId, type: 'helper.removed', now });
    await queueHelperNotice(tx, {
      ownerUserId,
      helperUserId: old.helper_user_id,
      relationshipId: old.relationship_id,
      type: 'helper.ended',
      now,
    });
    await appendAudit(tx, deps.keys, RECOVERY_HELPER_REMOVED, {}, { now: deps.now });
    return true;
  });
  return removed === true;
}

/**
 * 協力者の範囲で、その持ち主との協力関係の ID を引く。協力者でなければ undefined。
 * 協力者が、直近14日以内に回復したか、パスキーを足していれば（最初のパスキーは除く）、eligible は false（PRN-87）。
 */
export async function helperRelationship(
  deps: RepoDeps,
  helperUserId: WarifuUserId,
  ownerUserId: WarifuUserId,
): Promise<{ readonly relationshipId: string; readonly eligible: boolean } | undefined> {
  return deps.db.withWarifuUser(helperUserId, async (tx) => {
    const [row] = await tx.query<{ relationship_id: string }>(
      sql`SELECT relationship_id FROM idp.helpers
           WHERE helper_user_id = ${helperUserId} AND owner_user_id = ${ownerUserId}`,
    );
    if (row === undefined) return undefined;
    const since = new Date(deps.now().getTime() - RECOVERY_TIMES.helperFreshDays * DAY_MS);
    const [user] = await tx.query<{ recovered_at: Date | null }>(
      sql`SELECT recovered_at FROM idp.users`,
    );
    // 最初のパスキーは、アカウントと同じトランザクションで作るので、作成の時刻が同じ（除く）。比べるのは DB の中で
    // 行う（JS の Date はミリ秒までなので、マイクロ秒の差を見落とさない）。
    const [added] = await tx.query(
      sql`SELECT c.credential_id FROM idp.credentials AS c, idp.users AS u
           WHERE c.state = 'active' AND c.created_at > ${since} AND c.created_at > u.created_at
           LIMIT 1`,
    );
    const recentlyRecovered = user?.recovered_at != null && user.recovered_at > since;
    return {
      relationshipId: row.relationship_id,
      eligible: !recentlyRecovered && added === undefined,
    };
  });
}

/** 協力者として、協力している相手の協力関係（協力者の範囲）。端末が表示名を引くためだけに使う。 */
export async function listHelping(
  deps: RepoDeps,
  helperUserId: WarifuUserId,
): Promise<{ readonly relationshipId: string; readonly createdAt: Date }[]> {
  return deps.db.withWarifuUser(helperUserId, async (tx) => {
    const rows = await tx.query<{ relationship_id: string; created_at: Date }>(
      sql`SELECT relationship_id, created_at FROM idp.helpers
           WHERE helper_user_id = ${helperUserId} ORDER BY created_at, relationship_id`,
    );
    return rows.map((row) => ({ relationshipId: row.relationship_id, createdAt: row.created_at }));
  });
}

// ---- 回復の開始（O-75） ----

export type StartCheck =
  | {
      readonly ok: true;
      readonly userId: WarifuUserId;
      readonly codeCreatedAt: string;
    }
  | { readonly ok: false };

const DUMMY_MAC = new Uint8Array(32);

/**
 * 回復コードを確かめ、回復を始められるかを判定する。コードの形が違う、利用者がいない、秘密が違う、協力者がいない、
 * 進行中の回復がある、取消の後の14日の中、のどれでも、同じ { ok: false } にする。所要時間をそろえるため、
 * 形が違っても乱数の利用者の範囲で同じ問い合わせと MAC の計算をする（不変条件10、テスト10）。
 */
export async function checkRecoveryStart(
  deps: RepoDeps,
  keys: IdpKeyClient,
  input: unknown,
): Promise<StartCheck> {
  const parsed = parseRecoveryCode(input);
  const userId = parsed?.userId ?? (randomUuid() as WarifuUserId);
  const secret = parsed?.secret ?? randomBytesOf(SECRET_BYTES);
  const mac = await codeMacOf(keys, userId, secret);
  return deps.db.withWarifuUser(userId, async (tx) => {
    await settleAttempts(tx, deps, userId);
    const [code] = await tx.query<{ code_mac: Uint8Array; created_at: Date }>(
      sql`SELECT code_mac, created_at FROM idp.recovery_codes WHERE user_id = ${userId}`,
    );
    const [user] = await tx.query<{ recovery_locked_until: Date | null }>(
      sql`SELECT recovery_locked_until FROM idp.users`,
    );
    const helper = await helperOfOwner(tx, userId);
    const active = await activeAttempt(tx);
    const matched = constantTimeEqual(
      code === undefined ? DUMMY_MAC : new Uint8Array(code.code_mac),
      mac,
    );
    const locked = user?.recovery_locked_until != null && user.recovery_locked_until > deps.now();
    if (
      parsed === undefined ||
      code === undefined ||
      !matched ||
      locked ||
      helper === undefined ||
      active !== undefined
    ) {
      return { ok: false } as const;
    }
    return { ok: true, userId, codeCreatedAt: code.created_at.toISOString() } as const;
  });
}

/**
 * 回復を始める。新しい端末で作った回復待ちのパスキーと、回復の記録を、1つのトランザクションで置く。
 * 判定（checkRecoveryStart）の後にコードが作り直された、協力者がいなくなった、ほかの回復が始まったときは undefined。
 */
export async function startRecovery(
  deps: RepoDeps,
  input: {
    readonly userId: WarifuUserId;
    readonly codeCreatedAt: string;
    readonly credential: NewCredential;
    readonly device: DeviceKind;
  },
): Promise<
  | {
      readonly attemptId: string;
      readonly helperUserId: WarifuUserId;
      readonly relationshipId: string;
    }
  | undefined
> {
  const attemptId = randomUuid();
  let started:
    | { attemptId: string; helperUserId: WarifuUserId; relationshipId: string }
    | undefined;
  try {
    started = await deps.db.withWarifuUser(input.userId, async (tx) => {
      const now = deps.now();
      await settleAttempts(tx, deps, input.userId);
      const [code] = await tx.query<{ created_at: Date }>(
        sql`SELECT created_at FROM idp.recovery_codes WHERE user_id = ${input.userId} FOR UPDATE`,
      );
      const [user] = await tx.query<{ recovery_locked_until: Date | null }>(
        sql`SELECT recovery_locked_until FROM idp.users`,
      );
      const helper = await helperOfOwner(tx, input.userId);
      if (
        code === undefined ||
        code.created_at.toISOString() !== input.codeCreatedAt ||
        (user?.recovery_locked_until != null && user.recovery_locked_until > now) ||
        helper === undefined ||
        (await activeAttempt(tx)) !== undefined
      ) {
        return undefined;
      }
      await tx.execute(
        sql`INSERT INTO idp.recovery_attempts
              (attempt_id, user_id, helper_user_id, state, request_device, started_at, helper_deadline)
            VALUES (${attemptId}, ${input.userId}, ${helper.helper_user_id}, 'awaiting_helper', ${input.device},
                    ${now}, ${new Date(now.getTime() + RECOVERY_TIMES.helperDeadlineSeconds * 1000)})`,
      );
      await insertCredential(tx, input.userId, input.credential, attemptId);
      await insertNotice(tx, {
        userId: input.userId,
        type: 'recovery.started',
        content: { device: input.device },
        now,
      });
      await queueHelperNotice(tx, {
        ownerUserId: input.userId,
        helperUserId: helper.helper_user_id,
        relationshipId: helper.relationship_id,
        type: 'helper.recovery_started',
        now,
      });
      await appendAudit(tx, deps.keys, RECOVERY_STARTED, {}, { now: deps.now });
      return {
        attemptId,
        helperUserId: helper.helper_user_id as WarifuUserId,
        relationshipId: helper.relationship_id,
      };
    });
  } catch {
    // 同時に始めた回復（一意の索引）、同じパスキーの二重の登録など。
    return undefined;
  }
  return started;
}

// ---- 新しい端末の状態（O-75、O-79） ----

export interface PendingRecovery {
  readonly attemptId: string;
  readonly state: 'awaiting_helper' | 'waiting';
  readonly helperUserId: WarifuUserId;
  readonly helperDeadline: Date;
  readonly readyAt: Date | null;
}

/** 回復待ちのパスキーから、その回復の記録を引く（期限切れなどで終わっていれば undefined）。 */
export async function pendingRecoveryOf(
  deps: RepoDeps,
  userId: WarifuUserId,
  credentialId: Uint8Array,
): Promise<PendingRecovery | undefined> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    await settleAttempts(tx, deps, userId);
    const [row] = await tx.query<AttemptRow>(
      sql`SELECT a.attempt_id, a.helper_user_id, a.state, a.request_device, a.started_at, a.helper_deadline,
                 a.ready_at
            FROM idp.credentials AS c
            JOIN idp.recovery_attempts AS a ON a.attempt_id = c.recovery_attempt_id
           WHERE c.credential_id = ${credentialId} AND c.state = 'pending'
             AND a.state IN ('awaiting_helper', 'waiting')`,
    );
    if (row === undefined) return undefined;
    return {
      attemptId: row.attempt_id,
      state: row.state as 'awaiting_helper' | 'waiting',
      helperUserId: row.helper_user_id as WarifuUserId,
      helperDeadline: row.helper_deadline,
      readyAt: row.ready_at,
    };
  });
}

// ---- 協力者の承認（O-76） ----

/** 待機に入れる。承認した人が、始めた時点の協力者で、記録が協力者の承認待ちのときだけ。待機の終わりを返す。 */
export async function approveRecovery(
  deps: RepoDeps,
  input: {
    readonly userId: WarifuUserId;
    readonly attemptId: string;
    readonly helperUserId: WarifuUserId;
    readonly waitSeconds: number;
  },
): Promise<Date | undefined> {
  return deps.db.withWarifuUser(input.userId, async (tx) => {
    const now = deps.now();
    await settleAttempts(tx, deps, input.userId);
    const readyAt = new Date(now.getTime() + input.waitSeconds * 1000);
    const updated = await tx.execute(
      sql`UPDATE idp.recovery_attempts
             SET state = 'waiting', approved_at = ${now}, ready_at = ${readyAt}
           WHERE attempt_id = ${input.attemptId} AND state = 'awaiting_helper'
             AND helper_user_id = ${input.helperUserId} AND helper_deadline > ${now}`,
    );
    if (updated !== 1) return undefined;
    await insertNotice(tx, { userId: input.userId, type: 'recovery.approved', now });
    await appendAudit(tx, deps.keys, RECOVERY_HELPER_APPROVED, {}, { now: deps.now });
    return readyAt;
  });
}

// ---- 取消（O-78） ----

/** 回復を取り消す。回復コードを失効させ、回復待ちのパスキーを消し、14日間は回復を始められないようにする。 */
export async function cancelRecovery(
  deps: RepoDeps,
  input: { readonly userId: WarifuUserId; readonly attemptId: string },
): Promise<boolean> {
  const cancelled = await deps.db.withWarifuUser(input.userId, async (tx) => {
    const now = deps.now();
    await settleAttempts(tx, deps, input.userId);
    const [row] = await tx.query<{ helper_user_id: string }>(
      sql`UPDATE idp.recovery_attempts
             SET state = 'cancelled', ended_at = ${now},
                 purge_after = ${new Date(now.getTime() + RECOVERY_TIMES.keepAfterEndDays * DAY_MS)}
           WHERE attempt_id = ${input.attemptId} AND state IN ('awaiting_helper', 'waiting')
       RETURNING helper_user_id`,
    );
    if (row === undefined) return undefined;
    await tx.execute(
      sql`DELETE FROM idp.credentials WHERE state = 'pending' AND recovery_attempt_id = ${input.attemptId}`,
    );
    await tx.execute(sql`DELETE FROM idp.recovery_codes WHERE user_id = ${input.userId}`);
    await tx.execute(
      sql`UPDATE idp.users
             SET recovery_locked_until = ${new Date(now.getTime() + RECOVERY_TIMES.lockoutDays * DAY_MS)}`,
    );
    await insertNotice(tx, { userId: input.userId, type: 'recovery.cancelled', now });
    const helper = await helperOfOwner(tx, input.userId);
    if (helper !== undefined) {
      await queueHelperNotice(tx, {
        ownerUserId: input.userId,
        helperUserId: helper.helper_user_id,
        relationshipId: helper.relationship_id,
        type: 'helper.recovery_cancelled',
        now,
      });
    }
    await appendAudit(tx, deps.keys, RECOVERY_CANCELLED, {}, { now: deps.now });
    return true;
  });
  return cancelled === true;
}

/** 進行中の回復の記録（持ち主の範囲）。 */
export async function activeRecovery(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<RecoveryAttemptView | undefined> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    await settleAttempts(tx, deps, userId);
    const row = await activeAttempt(tx);
    return row === undefined ? undefined : viewOf(row);
  });
}

// ---- 成立（O-79） ----

/**
 * 回復を成立させる。待機を終えた記録と、その回復待ちのパスキーのときだけ。ほかの有効なパスキーを一時停止し、
 * recovered_at を置き、回復コードを作り直す（新しいコードの平文は返り値だけ）。協力者への知らせは送信待ちに置く
 * だけで、ここでは送らない。企業への知らせは、準備（呼び出し側が成立の前に行う）を、成立の後に確定する必要が
 * あることを記録する（companyNoticePending。確定は confirmCompanyNotices で、届くまで送り直す。O-79、O-81）。
 */
export async function completeRecovery(
  deps: RepoDeps,
  keys: IdpKeyClient,
  input: {
    readonly userId: WarifuUserId;
    readonly attemptId: string;
    readonly credentialId: Uint8Array;
    /** 成立の時刻（企業への知らせの recovered_at と同じ日にするため、呼び出し側が決める）。 */
    readonly at: Date;
    /** 企業への知らせを準備した（接続している企業がある）か。 */
    readonly companyNoticePending: boolean;
  },
): Promise<{ readonly code: string; readonly recoveredAt: Date } | undefined> {
  const secret = randomBytesOf(SECRET_BYTES);
  const mac = await codeMacOf(keys, input.userId, secret);
  const done = await deps.db.withWarifuUser(input.userId, async (tx) => {
    const now = input.at;
    const updated = await tx.execute(
      sql`UPDATE idp.recovery_attempts
             SET state = 'completed', ended_at = ${now},
                 purge_after = ${new Date(now.getTime() + RECOVERY_TIMES.keepAfterEndDays * DAY_MS)},
                 company_notice_pending = ${input.companyNoticePending}
           WHERE attempt_id = ${input.attemptId} AND state = 'waiting' AND ready_at <= ${now}`,
    );
    if (updated !== 1) return undefined;
    await tx.execute(sql`UPDATE idp.credentials SET state = 'suspended' WHERE state = 'active'`);
    const activated = await tx.execute(
      sql`UPDATE idp.credentials SET state = 'active', recovery_attempt_id = ${null}
           WHERE credential_id = ${input.credentialId} AND state = 'pending'
             AND recovery_attempt_id = ${input.attemptId}`,
    );
    if (activated !== 1) throw new Error('回復待ちのパスキーがない');
    await tx.execute(sql`UPDATE idp.users SET recovered_at = ${now}`);
    await tx.execute(sql`DELETE FROM idp.recovery_codes WHERE user_id = ${input.userId}`);
    await tx.execute(
      sql`INSERT INTO idp.recovery_codes (user_id, code_mac, created_at)
          VALUES (${input.userId}, ${mac}, ${now})`,
    );
    await insertNotice(tx, { userId: input.userId, type: 'recovery.completed', now });
    await insertNotice(tx, { userId: input.userId, type: 'recovery.code_reissued', now });
    const helper = await helperOfOwner(tx, input.userId);
    if (helper !== undefined) {
      for (const type of ['helper.recovery_completed', 'helper.code_reissued'] as const) {
        await queueHelperNotice(tx, {
          ownerUserId: input.userId,
          helperUserId: helper.helper_user_id,
          relationshipId: helper.relationship_id,
          type,
          now,
        });
      }
    }
    await appendAudit(tx, deps.keys, RECOVERY_COMPLETED, {}, { now: deps.now });
    await appendAudit(tx, deps.keys, RECOVERY_CODE_ISSUED, { reissued: true }, { now: deps.now });
    return { recoveredAt: now };
  });
  if (done === undefined) return undefined;
  return { code: formatRecoveryCode(input.userId, secret), recoveredAt: done.recoveredAt };
}

/** 成立した回復のうち、企業への知らせの確定がまだのもの（持ち主の範囲）。回復の記録の ID を返す。 */
export async function pendingCompanyNotices(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<string[]> {
  const rows = await deps.db.withWarifuUser(userId, (tx) =>
    tx.query<{ attempt_id: string }>(
      sql`SELECT attempt_id FROM idp.recovery_attempts
           WHERE state = 'completed' AND company_notice_pending ORDER BY ended_at, attempt_id`,
    ),
  );
  return rows.map((row) => row.attempt_id);
}

/** 企業への知らせを確定できたことを記録する。 */
export async function markCompanyNoticeConfirmed(
  deps: RepoDeps,
  userId: WarifuUserId,
  attemptId: string,
): Promise<void> {
  await deps.db.withWarifuUser(userId, (tx) =>
    tx.execute(
      sql`UPDATE idp.recovery_attempts SET company_notice_pending = false
           WHERE attempt_id = ${attemptId} AND state = 'completed'`,
    ),
  );
}

/** recovered_at を、企業に渡す日の値（UTC の0時の秒）にする（O-81。企業をまたいだ突き合わせを弱める）。 */
export function recoveredDayOf(recoveredAt: Date): number {
  return Math.floor(recoveredAt.getTime() / DAY_MS) * (DAY_MS / 1000);
}

/** ID トークンに入れる recovered_at（日にまるめた値）。回復していなければ undefined。 */
export async function recoveredDay(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<number | undefined> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const [user] = await tx.query<{ recovered_at: Date | null }>(
      sql`SELECT recovered_at FROM idp.users`,
    );
    return user?.recovered_at == null ? undefined : recoveredDayOf(user.recovered_at);
  });
}
