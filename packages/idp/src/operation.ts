// 高リスクの操作の step-up（idp。ADR 0030 の O-112〜O-117）。P0 の操作は出金先の変更だけ。
//
// 流れ（窓口の操作別承認と同じ形。ADR 0026）：
// 1. 企業のサーバーが、PAR の受け口に authorization_details（型 warifu_operation）を1件だけ送る。中身は、企業の
//    申請ID と、利用者に見せる内容（金融機関コード、支店コード、口座番号の末尾4桁）だけ。
// 2. 本来のオリジンのインタラクションが、承認用のオリジンの /operation に引き継ぐ（プロセスのメモリに5分）。
// 3. 利用者は、内容に結び付いた UV 付きのパスキーで承認する。sub の一致、接続済み、回復の後の制限の外のときだけ。
// 4. 承認の JWT（鍵 operation_approval）を作り、トークンの応答で企業に渡す。
//
// 金融機関と支店の名前は、割符の対応表（DEMO_BANKS。P0 は架空）から引く。企業から名前を受け取らない（O-117）。
// 申請ID と内容は、メモリ（引き継ぎ、Grant、認可コード）にだけ置き、DB とログには書かない（不変条件4）。

import {
  lengthPrefixed,
  randomBytesOf,
  type TenantId,
  toBase64Url,
  utf8,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { appendAudit } from '@pii-token-vault/warifu-core/audit';
import {
  OPERATION_ACTIONS,
  OPERATION_APPROVAL_TYP,
  OPERATION_DETAIL_TYPE,
  OPERATION_REQUEST_ID_PATTERN,
  type OperationAction,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import { OPERATION_APPROVED, OPERATION_DECLINED } from './audit-events.ts';
import type { DeviceKind } from './inbox.ts';
import type { RepoDeps } from './repo.ts';
import type { MacMemoryStore } from './storage.ts';

export const OPERATION_HANDOFF_KIND = 'OperationHandoff';
export const OPERATION_MAX_FAILURES = 3;
/** 引き継ぎと、承認の JWT の有効期間（秒。窓口と同じ）。 */
export const OPERATION_TIMES = Object.freeze({ requestTtlSeconds: 300, approvalTtlSeconds: 300 });

const CHALLENGE_LABEL = 'warifu/operation/v1';
const SUB_PATTERN = /^[A-Za-z0-9_-]{43}$/;

// ---- 金融機関と支店の対応表（O-117。P0 は架空） ----

/**
 * デモ用の架空の金融機関と支店。名前は架空。コードは、実在のものと重なることがありうるので、画面には必ず
 * 「デモ用の架空の金融機関・支店です」と出す（実在の口座を扱えるように見せない。O-113）。
 * 本番の対応表のデータの利用条件と更新の手順は、P1 で決める（plan 10章）。
 */
export const DEMO_BANKS: Readonly<
  Record<string, { readonly name: string; readonly branches: Readonly<Record<string, string>> }>
> = Object.freeze({
  '9991': {
    name: 'わりふデモ銀行',
    branches: Object.freeze({ '001': '本店', '101': '中央支店', '201': 'みなと支店' }),
  },
  '9992': {
    name: 'デモ信用金庫',
    branches: Object.freeze({ '001': '本店', '301': '駅前支店' }),
  },
});

/** 画面に出す固定の注記（O-113）。 */
export const DEMO_BANKS_NOTE = 'デモ用の架空の金融機関・支店です。';

// ---- 固定の文言（DESIGN.md 2章「端末での承認（step-up）」） ----

export const OPERATION_LABELS: Readonly<Record<OperationAction, string>> = Object.freeze({
  'payout_destination.change': '出金先の変更',
});

export const OPERATION_VALIDITY_TEXT = '承認してから5分の間、この1回の変更にだけ使えます。';

// ---- 申請（authorization_details の1件） ----

export interface PayoutContent {
  readonly bank_code: string;
  readonly branch_code: string;
  readonly account_last4: string;
}

export interface OperationDetail {
  readonly action: OperationAction;
  /** 企業の申請ID（不変条件4。DB とログに書かない）。 */
  readonly identifier: string;
  readonly subject: string;
  readonly content: PayoutContent;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function keysOf(value: Record<string, unknown>): string {
  return Object.keys(value).sort().join(',');
}

/** 1件を検査する。型、操作、項目の形、対応表にあるコードの組か。合わなければ undefined（理由を区別しない）。 */
export function parseOperationDetail(
  value: unknown,
  allowed: readonly OperationAction[],
): OperationDetail | undefined {
  if (!isRecord(value) || value.type !== OPERATION_DETAIL_TYPE) return undefined;
  if (keysOf(value) !== 'actions,content,identifier,subject,type') return undefined;
  const { actions, identifier, subject, content } = value;
  const action = Array.isArray(actions) && actions.length === 1 ? actions[0] : undefined;
  if (
    typeof action !== 'string' ||
    !(OPERATION_ACTIONS as readonly string[]).includes(action) ||
    !(allowed as readonly string[]).includes(action)
  ) {
    return undefined;
  }
  if (typeof identifier !== 'string' || !OPERATION_REQUEST_ID_PATTERN.test(identifier)) {
    return undefined;
  }
  if (typeof subject !== 'string' || !SUB_PATTERN.test(subject)) return undefined;
  if (!isRecord(content) || keysOf(content) !== 'account_last4,bank_code,branch_code') {
    return undefined;
  }
  const { bank_code: bank, branch_code: branch, account_last4: last4 } = content;
  if (
    typeof bank !== 'string' ||
    !/^\d{4}$/.test(bank) ||
    typeof branch !== 'string' ||
    !/^\d{3}$/.test(branch) ||
    typeof last4 !== 'string' ||
    !/^\d{4}$/.test(last4)
  ) {
    return undefined;
  }
  // 対応表にないコードの組は断る（名前を出せないものを承認させない。O-112）。
  if (
    !Object.hasOwn(DEMO_BANKS, bank) ||
    !Object.hasOwn(DEMO_BANKS[bank]?.branches ?? {}, branch)
  ) {
    return undefined;
  }
  return {
    action: action as OperationAction,
    identifier,
    subject,
    content: { bank_code: bank, branch_code: branch, account_last4: last4 },
  };
}

export function operationDetailJson(detail: OperationDetail): Record<string, unknown> {
  return {
    type: OPERATION_DETAIL_TYPE,
    actions: [detail.action],
    identifier: detail.identifier,
    subject: detail.subject,
    content: {
      bank_code: detail.content.bank_code,
      branch_code: detail.content.branch_code,
      account_last4: detail.content.account_last4,
    },
  };
}

export function sameOperationDetail(a: OperationDetail, b: OperationDetail): boolean {
  return JSON.stringify(operationDetailJson(a)) === JSON.stringify(operationDetailJson(b));
}

/** 画面に出す内容の行（割符の固定の書式。名前は対応表から）。 */
export function contentLines(detail: OperationDetail): { label: string; value: string }[] {
  const bank = DEMO_BANKS[detail.content.bank_code];
  const branch = bank?.branches[detail.content.branch_code];
  return [
    { label: '金融機関', value: `${bank?.name ?? ''}（${detail.content.bank_code}）` },
    { label: '支店', value: `${branch ?? ''}（${detail.content.branch_code}）` },
    { label: '口座番号の末尾', value: detail.content.account_last4 },
  ];
}

// ---- 引き継ぎ ----

export type OperationDeclineReason = 'denied' | 'unrecognized';
export const OPERATION_DECLINE_REASONS: readonly OperationDeclineReason[] = Object.freeze([
  'denied',
  'unrecognized',
]);

export interface OperationHandoff {
  readonly uid: string;
  readonly tenantId: TenantId;
  readonly clientId: string;
  readonly detail: OperationDetail;
  readonly device: DeviceKind;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly state: 'pending' | 'approved' | 'declined';
  readonly failures: number;
  readonly approval?: {
    readonly userId: WarifuUserId;
    readonly approvedAt: number;
    readonly jwt: string;
  };
  readonly declineReason?: OperationDeclineReason;
}

export async function saveOperationHandoff(
  store: MacMemoryStore,
  handoff: OperationHandoff,
  nowMs: number,
): Promise<void> {
  const ttl = Math.max(1, Math.ceil((handoff.expiresAt - nowMs) / 1000));
  await store.set(OPERATION_HANDOFF_KIND, handoff.uid, handoff, ttl);
}

export async function loadOperationHandoff(
  store: MacMemoryStore,
  uid: string,
  nowMs: number,
): Promise<OperationHandoff | undefined> {
  const handoff = await store.get<OperationHandoff>(OPERATION_HANDOFF_KIND, uid);
  if (handoff === undefined || handoff.uid !== uid || handoff.expiresAt <= nowMs) return undefined;
  return handoff;
}

export function isOpenOperation(
  handoff: OperationHandoff | undefined,
  nowMs: number,
): handoff is OperationHandoff {
  return (
    handoff !== undefined &&
    handoff.state === 'pending' &&
    handoff.expiresAt > nowMs &&
    handoff.failures < OPERATION_MAX_FAILURES
  );
}

/** 承認のチャレンジの材料。内容の各項目まで、長さ付きでつなぐ（画面と違う内容に同じアサーションを使わせない。O-113）。 */
export function operationChallengeMessage(handoff: OperationHandoff, nonce: string): Uint8Array {
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
    detail.content.bank_code,
    detail.content.branch_code,
    detail.content.account_last4,
    String(handoff.createdAt),
    String(handoff.expiresAt),
    handoff.device,
  ]);
}

// ---- 承認の JWT（O-114） ----

export class OperationKeyError extends Error {
  override name = 'OperationKeyError';
}

export async function signOperationApproval(
  keys: IdpKeyClient,
  input: {
    readonly issuer: string;
    readonly clientId: string;
    readonly sub: string;
    readonly detail: OperationDetail;
    readonly acr: string;
    /** 秒。 */
    readonly authTime: number;
  },
): Promise<string> {
  const [current] = await keys.publicKeys('operation_approval');
  if (current === undefined) throw new OperationKeyError();
  const header = { alg: 'ES256', typ: OPERATION_APPROVAL_TYP, kid: current.kid };
  const payload = {
    iss: input.issuer,
    aud: input.clientId,
    sub: input.sub,
    purpose: 'operation',
    action: input.detail.action,
    request_id: input.detail.identifier,
    content: operationDetailJson(input.detail).content,
    acr: input.acr,
    auth_time: input.authTime,
    iat: input.authTime,
    exp: input.authTime + OPERATION_TIMES.approvalTtlSeconds,
    jti: toBase64Url(randomBytesOf(16)),
  };
  const signingInput = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(utf8(JSON.stringify(payload)))}`;
  const { kid, signature } = await keys.sign('operation_approval', utf8(signingInput));
  if (kid !== current.kid) throw new OperationKeyError();
  return `${signingInput}.${toBase64Url(signature)}`;
}

// ---- 監査（操作の種類とテナントだけ。申請ID と内容は入れない） ----

export async function auditOperationApproved(
  repo: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<void> {
  await repo.db.withWarifuUser(userId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      OPERATION_APPROVED,
      { tenant_id: tenantId, action: 'payout_destination_change' },
      { now: repo.now },
    ),
  );
}

export async function auditOperationDeclined(
  repo: RepoDeps,
  tenantId: TenantId,
  reason: OperationDeclineReason,
): Promise<void> {
  await repo.db.withTenant(tenantId, (tx) =>
    appendAudit(
      tx,
      repo.keys,
      OPERATION_DECLINED,
      { tenant_id: tenantId, reason },
      { now: repo.now },
    ),
  );
}
