// 既存会員の初回紐付けの正本（ADR 0020、ADR 0028 の O-86〜O-92、O-103）。テナントの範囲（withTenant）でだけ読み書きする。
//
// - 正本は company_api.initial_links。企業の申請ID、移行専用ID、会員参照、証跡の原文は置かない。照合用の
//   mac(initial_link_lookup, …) と、作ったときの鍵の版だけを置く（不変条件4、O-87、O-88）。
// - 外に出す移行専用ID（と取消ID）は、内部のレコード ID から mac(initial_link_public_id, …) で、行に置いた版を使って
//   その都度導く。開いている申請の ID を、新しい版で導き直さない（O-87）。企業が出した ID は、鍵サービスが持つすべての
//   版で索引の MAC を作って引く（当たったかどうかで作る回数を変えない）。
// - 状態の変更は、行のロック（FOR UPDATE）の中で判定する。承認・取消・結果の報告の競合は、正本の状態で決まる（O-90）。
//   時刻は割符の時計（deps.now）だけで決める。期限切れは、行を読むときに確かめて進める。
// - 終端の行は、終端から7日を過ぎたら、そのテナントの処理で消す（O-92）。終端でない行は消さない。
// - 待機の知らせの SET（O-103）と取消の SET（O-91）は、同じトランザクションで送信待ちに入れる。中身は送るときに導く。

import {
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
  INITIAL_LINK_ID_PATTERN,
  type InitialLinkState,
  type InitialLinkStatusItem,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import {
  INITIAL_LINK_APPROVED,
  INITIAL_LINK_CANCEL_ACCEPTED,
  INITIAL_LINK_CANCELLED,
  INITIAL_LINK_EXPIRED,
  INITIAL_LINK_LINKED,
  INITIAL_LINK_NOT_LINKED,
  INITIAL_LINK_NOTICE_QUEUED,
  INITIAL_LINK_PREPARED,
  INITIAL_LINK_PROOF_ACCEPTED,
  INITIAL_LINK_WAITING,
} from './audit-events.ts';
import type { ApiClient, CompanyTenant } from './config.ts';
import { initialDelayMs } from './desk.ts';
import { verifyJwt } from './jwt.ts';

const ID_LABEL = 'warifu/initial-link/id/v1';
const LOOKUP_LABEL = 'warifu/initial-link/lookup/v1';
const HOUR_MS = 3600 * 1000;
const DAY_MS = 24 * HOUR_MS;
const UNIQUE_VIOLATION = '23505';
const CLOCK_TOLERANCE_SECONDS = 30;

/** 値は、どれも根拠のない仮置き（ADR 0028 の O-90。仕様案 v0.7 の 0.2）。 */
export const INITIAL_LINK_TIMES = Object.freeze({
  /** 待機（待機の知らせの SET が届いてから）。 */
  waitMs: 24 * HOUR_MS,
  /** pending_notice でいられる時間。 */
  pendingNoticeMs: 24 * HOUR_MS,
  /** 親申請の期限（pending_link になってから。送り直しで延ばさない）。 */
  parentMs: 72 * HOUR_MS,
  /** 本人の承認の前（prepared）でいられる時間。 */
  preparedMs: 72 * HOUR_MS,
  /** 証跡の有効期間の上限（秒）。 */
  proofMaxAgeSeconds: 300,
  /** 終端から消すまで。 */
  keepAfterTerminalDays: 7,
});

/** 証跡の typ（client assertion と区別する。O-88）。 */
export const INITIAL_LINK_PROOF_TYP = 'warifu-initial-link-proof+jwt';
/** 企業の申請ID の形。 */
export const INITIAL_LINK_REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
/** 会員参照（128ビット以上の乱数を base64url にしたもの。O-88）。 */
export const MEMBER_REF_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const JTI_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const PROOF_CLAIMS: readonly string[] = Object.freeze([
  'iss',
  'aud',
  'iat',
  'exp',
  'jti',
  'initial_link_id',
  'member_ref',
  'stage',
  'eligibility',
  'credential_kind',
  'profile_version',
  'auth_epoch',
]);

const TERMINAL: ReadonlySet<InitialLinkState> = new Set([
  'linked',
  'cancelled',
  'expired',
  'not_linked',
]);
const OPEN_FOR_CANCEL: ReadonlySet<InitialLinkState> = new Set([
  'pending_notice',
  'pending_link',
  'awaiting_final',
]);

export interface InitialLinkDeps {
  readonly db: Db;
  readonly keys: CompanyApiKeyClient;
  readonly now: () => Date;
}

interface Row {
  link_ref: string;
  user_id: string | null;
  public_id_version: number;
  member_mac: string;
  participation_revision: number;
  profile_version: number;
  credential_kind: 'passkey' | 'fido2' | null;
  auth_epoch: string | null;
  initial_proof_mac: string | null;
  initial_proof_mac_version: number | null;
  final_proof_mac: string | null;
  final_proof_mac_version: number | null;
  state: InitialLinkState;
  created_at: Date;
  approved_at: Date | null;
  item_ref: string | null;
  wait_until: Date | null;
  parent_expires_at: Date | null;
  cancel_ref: string | null;
}

// ---- ID と索引 ----

/** 移行専用ID（kind = link）か取消ID（kind = cancel）を、内部のレコード ID から、指定した版で導く。 */
export async function publicIdOf(
  keys: CompanyApiKeyClient,
  tenantId: TenantId,
  kind: 'link' | 'cancel',
  ref: string,
  version?: number,
): Promise<{ readonly id: string; readonly version: number }> {
  const result = await keys.macVersioned(
    'initial_link_public_id',
    lengthPrefixed([ID_LABEL, tenantId, kind, ref]),
    version,
  );
  return { id: toBase64Url(result.mac), version: result.version };
}

type LookupKind = 'request' | 'link' | 'member' | 'proof' | 'jti';

function lookupMessage(tenantId: TenantId, kind: LookupKind, value: string): Uint8Array {
  return lengthPrefixed([LOOKUP_LABEL, tenantId, kind, value]);
}

/** 新しく置く索引の MAC（最新の版）。 */
async function lookupLatest(
  keys: CompanyApiKeyClient,
  tenantId: TenantId,
  kind: LookupKind,
  value: string,
): Promise<{ readonly mac: string; readonly version: number }> {
  const result = await keys.macVersioned(
    'initial_link_lookup',
    lookupMessage(tenantId, kind, value),
  );
  return { mac: toBase64Url(result.mac), version: result.version };
}

/** 照合に使う索引の MAC（鍵サービスが持つすべての版）。 */
async function lookupAll(
  keys: CompanyApiKeyClient,
  tenantId: TenantId,
  kind: LookupKind,
  value: string,
): Promise<string[]> {
  const all = await keys.macAllVersions(
    'initial_link_lookup',
    lookupMessage(tenantId, kind, value),
  );
  return all.map((m) => toBase64Url(m.mac));
}

// ---- 共通 ----

function terminalTimes(now: Date) {
  return {
    terminalAt: now,
    purgeAfter: new Date(now.getTime() + INITIAL_LINK_TIMES.keepAfterTerminalDays * DAY_MS),
  };
}

async function purge(tx: Tx, now: Date): Promise<void> {
  await tx.execute(sql`DELETE FROM company_api.initial_links WHERE purge_after <= ${now}`);
  await tx.execute(sql`DELETE FROM company_api.initial_link_proof_jtis WHERE expires_at <= ${now}`);
}

/** 届いていない待機の知らせの SET を消す（申請が終わったとき。O-103）。 */
async function dropWaitingSet(tx: Tx, linkRef: string): Promise<void> {
  await tx.execute(
    sql`DELETE FROM company_api.set_outbox
         WHERE link_ref = ${linkRef} AND event_type = 'initial_link_waiting'`,
  );
}

/** 期限か版を見て、終わっているべき行を expired に、待機が満ちた行を awaiting_final に進める。進めた後の状態を返す。 */
async function advance(
  tx: Tx,
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  row: Row,
): Promise<InitialLinkState> {
  if (TERMINAL.has(row.state)) return row.state;
  const now = deps.now();
  const versionChanged =
    row.participation_revision !== tenant.participationRevision ||
    row.profile_version !== tenant.initialLink?.profileVersion;
  // 取消を受理した行と、紐付けの承認を出した行は、企業の結果の報告で終わる（版の変化で期限切れにしない）。
  const expirable = row.state !== 'cancel_requested' && row.state !== 'approved';
  const expired =
    expirable &&
    (versionChanged ||
      (row.state === 'prepared' &&
        row.created_at.getTime() + INITIAL_LINK_TIMES.preparedMs <= now.getTime()) ||
      (row.state === 'pending_notice' &&
        row.approved_at !== null &&
        row.approved_at.getTime() + INITIAL_LINK_TIMES.pendingNoticeMs <= now.getTime()) ||
      ((row.state === 'pending_link' || row.state === 'awaiting_final') &&
        row.parent_expires_at !== null &&
        row.parent_expires_at <= now));
  if (expired) {
    const { terminalAt, purgeAfter } = terminalTimes(now);
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'expired', state_version = state_version + 1,
                 terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
           WHERE link_ref = ${row.link_ref}`,
    );
    await dropWaitingSet(tx, row.link_ref);
    await appendAudit(tx, deps.keys, INITIAL_LINK_EXPIRED, {}, { now: deps.now });
    row.state = 'expired';
    return 'expired';
  }
  if (row.state === 'pending_link' && row.wait_until !== null && row.wait_until <= now) {
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'awaiting_final', state_version = state_version + 1
           WHERE link_ref = ${row.link_ref}`,
    );
    row.state = 'awaiting_final';
  }
  return row.state;
}

async function lockByLinkMacs(tx: Tx, macs: readonly string[]): Promise<Row | undefined> {
  const [row] = await tx.query<Row>(
    sql`SELECT link_ref, user_id, public_id_version, member_mac, participation_revision, profile_version, credential_kind, auth_epoch, initial_proof_mac, initial_proof_mac_version, final_proof_mac, final_proof_mac_version, state, created_at, approved_at, item_ref, wait_until, parent_expires_at, cancel_ref FROM company_api.initial_links
         WHERE link_mac = ANY(${[...macs]}::text[]) FOR UPDATE`,
  );
  return row;
}

async function lockByItemRef(tx: Tx, itemRef: string): Promise<Row | undefined> {
  const [row] = await tx.query<Row>(
    sql`SELECT link_ref, user_id, public_id_version, member_mac, participation_revision, profile_version, credential_kind, auth_epoch, initial_proof_mac, initial_proof_mac_version, final_proof_mac, final_proof_mac_version, state, created_at, approved_at, item_ref, wait_until, parent_expires_at, cancel_ref FROM company_api.initial_links WHERE item_ref = ${itemRef} FOR UPDATE`,
  );
  return row;
}

function usable(tenant: CompanyTenant): boolean {
  return !tenant.suspended && tenant.initialLink !== undefined && tenant.webhookUrl !== undefined;
}

// ---- 企業向けのルートから ----

export type RouteResult<T = undefined> =
  | { readonly status: 200; readonly body: T }
  | { readonly status: 204 }
  | { readonly status: 400 | 404 | 409 };

/**
 * 仮申請（POST /v1/initial-link/prepare）。同じ申請ID の再送には、同じ移行専用ID を返す（会員参照が違えば 409）。
 * 待機も知らせも、まだ始めない（O-86 の手順2）。
 */
export async function prepare(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: { readonly requestId: unknown; readonly memberRef: unknown },
): Promise<RouteResult<{ readonly initial_link_id: string; readonly state: InitialLinkState }>> {
  const { requestId, memberRef } = input;
  if (
    typeof requestId !== 'string' ||
    !INITIAL_LINK_REQUEST_ID_PATTERN.test(requestId) ||
    typeof memberRef !== 'string' ||
    !MEMBER_REF_PATTERN.test(memberRef)
  ) {
    return { status: 400 };
  }
  if (!usable(tenant)) return { status: 409 };
  const profileVersion = tenant.initialLink?.profileVersion ?? 0;
  const tenantId = tenant.tenantId;
  const requestMacs = await lookupAll(deps.keys, tenantId, 'request', requestId);
  const memberMacs = await lookupAll(deps.keys, tenantId, 'member', memberRef);

  const existing = async () =>
    deps.db.withTenant(tenantId, async (tx) => {
      await purge(tx, deps.now());
      const [row] = await tx.query<Row>(
        sql`SELECT link_ref, user_id, public_id_version, member_mac, participation_revision, profile_version, credential_kind, auth_epoch, initial_proof_mac, initial_proof_mac_version, final_proof_mac, final_proof_mac_version, state, created_at, approved_at, item_ref, wait_until, parent_expires_at, cancel_ref FROM company_api.initial_links
             WHERE request_mac = ANY(${requestMacs}::text[]) FOR UPDATE`,
      );
      if (row === undefined) return undefined;
      if (!memberMacs.includes(row.member_mac)) return { conflict: true } as const;
      const state = await advance(tx, deps, tenant, row);
      return { row, state } as const;
    });
  const answer = async (found: { row: Row; state: InitialLinkState }) => ({
    status: 200 as const,
    body: {
      initial_link_id: (
        await publicIdOf(
          deps.keys,
          tenantId,
          'link',
          found.row.link_ref,
          found.row.public_id_version,
        )
      ).id,
      state: found.state,
    },
  });

  const before = await existing();
  if (before !== undefined) return 'conflict' in before ? { status: 409 } : answer(before);

  const linkRef = randomUuid();
  const publicId = await publicIdOf(deps.keys, tenantId, 'link', linkRef);
  const linkMac = await lookupLatest(deps.keys, tenantId, 'link', publicId.id);
  const requestMac = await lookupLatest(deps.keys, tenantId, 'request', requestId);
  const memberMac = await lookupLatest(deps.keys, tenantId, 'member', memberRef);
  try {
    await deps.db.withTenant(tenantId, async (tx) => {
      await tx.execute(
        sql`INSERT INTO company_api.initial_links
              (link_ref, tenant_id, public_id_version, request_mac, request_mac_version, link_mac,
               link_mac_version, member_mac, member_mac_version, participation_revision, profile_version,
               state, created_at)
            VALUES (${linkRef}, ${tenantId}, ${publicId.version}, ${requestMac.mac}, ${requestMac.version},
                    ${linkMac.mac}, ${linkMac.version}, ${memberMac.mac}, ${memberMac.version},
                    ${tenant.participationRevision}, ${profileVersion}, 'prepared', ${deps.now()})`,
      );
      await appendAudit(tx, deps.keys, INITIAL_LINK_PREPARED, {}, { now: deps.now });
    });
  } catch (error) {
    // 同じ申請ID の同時の再送（一意制約）。先に入った行で答える。
    if (error instanceof DbError && error.code === UNIQUE_VIOLATION) {
      const after = await existing();
      if (after === undefined || 'conflict' in after) return { status: 409 };
      return answer(after);
    }
    throw error;
  }
  return { status: 200, body: { initial_link_id: publicId.id, state: 'prepared' } };
}

interface ProofClaims {
  readonly initialLinkId: string;
  readonly memberRef: string;
  readonly stage: 'initial' | 'final' | 'cancel';
  readonly credentialKind: 'passkey' | 'fido2';
  readonly authEpoch: number;
  readonly jti: string;
  readonly exp: number;
}

/** 証跡の audience（company-api の初回紐付けのルート。O-88）。 */
export function proofAudience(issuer: string): string {
  return `${issuer}/v1/initial-link`;
}

/**
 * 企業の証跡を確かめる（O-88）。クライアントの登録済みの鍵で ES256、typ は証跡のもの、クレームは許可リストだけ、
 * 有効期間は5分まで、jti は使い済みでないこと。jti は5分の間、使い済みとして覚える（MAC だけを置く）。
 */
async function verifyProof(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  client: ApiClient,
  issuer: string,
  jws: unknown,
): Promise<ProofClaims | undefined> {
  if (typeof jws !== 'string') return undefined;
  const audience = proofAudience(issuer);
  const payload = await verifyJwt(jws, client.jwks.keys, {
    issuer: client.clientId,
    audience,
    typ: INITIAL_LINK_PROOF_TYP,
    maxTokenAge: INITIAL_LINK_TIMES.proofMaxAgeSeconds,
    clockTolerance: CLOCK_TOLERANCE_SECONDS,
    currentDate: deps.now(),
    requiredClaims: [...PROOF_CLAIMS],
  });
  if (payload === undefined) return undefined;
  const keys = Object.keys(payload);
  if (keys.length !== PROOF_CLAIMS.length || !keys.every((k) => PROOF_CLAIMS.includes(k))) {
    return undefined;
  }
  const {
    aud,
    iat,
    exp,
    jti,
    initial_link_id,
    member_ref,
    stage,
    eligibility,
    credential_kind,
    profile_version,
    auth_epoch,
  } = payload as Record<string, unknown>;
  if (
    aud !== audience ||
    typeof iat !== 'number' ||
    typeof exp !== 'number' ||
    exp <= iat ||
    exp - iat > INITIAL_LINK_TIMES.proofMaxAgeSeconds ||
    typeof jti !== 'string' ||
    !JTI_PATTERN.test(jti) ||
    typeof initial_link_id !== 'string' ||
    !INITIAL_LINK_ID_PATTERN.test(initial_link_id) ||
    typeof member_ref !== 'string' ||
    !MEMBER_REF_PATTERN.test(member_ref) ||
    (stage !== 'initial' && stage !== 'final' && stage !== 'cancel') ||
    eligibility !== 'eligible' ||
    (credential_kind !== 'passkey' && credential_kind !== 'fido2') ||
    profile_version !== tenant.initialLink?.profileVersion ||
    typeof auth_epoch !== 'number' ||
    !Number.isSafeInteger(auth_epoch) ||
    auth_epoch < 0
  ) {
    return undefined;
  }
  // jti の再送を断る（鍵サービスが持つすべての版で引き、最新の版で覚える）。
  const jtiMacs = await lookupAll(deps.keys, tenant.tenantId, 'jti', jti);
  const latest = await lookupLatest(deps.keys, tenant.tenantId, 'jti', jti);
  const fresh = await deps.db.withTenant(tenant.tenantId, async (tx) => {
    await tx.execute(
      sql`DELETE FROM company_api.initial_link_proof_jtis WHERE expires_at <= ${deps.now()}`,
    );
    const [used] = await tx.query<{ jti_mac: string }>(
      sql`SELECT jti_mac FROM company_api.initial_link_proof_jtis WHERE jti_mac = ANY(${jtiMacs}::text[])`,
    );
    if (used !== undefined) return false;
    const inserted = await tx.execute(
      sql`INSERT INTO company_api.initial_link_proof_jtis (tenant_id, jti_mac, jti_mac_version, expires_at)
          VALUES (${tenant.tenantId}, ${latest.mac}, ${latest.version},
                  ${new Date((exp + CLOCK_TOLERANCE_SECONDS) * 1000)})
          ON CONFLICT DO NOTHING`,
    );
    return inserted === 1;
  });
  if (!fresh) return undefined;
  return {
    initialLinkId: initial_link_id,
    memberRef: member_ref,
    stage,
    credentialKind: credential_kind,
    authEpoch: auth_epoch,
    jti,
    exp,
  };
}

/**
 * 証跡を受ける（POST /v1/initial-link/proofs）。初回の証跡は prepared の申請に、最終の証跡は待機が満ちた申請に。
 * 会員参照が prepare と違えば 409。最終の証跡の認証世代が初回と違えば、申請を expired にして 409（O-88）。
 */
export async function acceptProof(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  client: ApiClient,
  issuer: string,
  input: { readonly proof: unknown },
): Promise<RouteResult> {
  if (!usable(tenant)) return { status: 409 };
  const claims = await verifyProof(deps, tenant, client, issuer, input.proof);
  if (claims === undefined || claims.stage === 'cancel') return { status: 400 };
  const tenantId = tenant.tenantId;
  const linkMacs = await lookupAll(deps.keys, tenantId, 'link', claims.initialLinkId);
  const memberMacs = await lookupAll(deps.keys, tenantId, 'member', claims.memberRef);
  const proofMac = await lookupLatest(deps.keys, tenantId, 'proof', String(input.proof));
  return deps.db.withTenant(tenantId, async (tx): Promise<RouteResult> => {
    await purge(tx, deps.now());
    const row = await lockByLinkMacs(tx, linkMacs);
    if (row === undefined) return { status: 404 };
    if (!memberMacs.includes(row.member_mac)) return { status: 409 };
    const state = await advance(tx, deps, tenant, row);
    if (claims.stage === 'initial') {
      if (state !== 'prepared' || row.initial_proof_mac !== null) return { status: 409 };
      await tx.execute(
        sql`UPDATE company_api.initial_links
               SET credential_kind = ${claims.credentialKind}, auth_epoch = ${claims.authEpoch},
                   initial_proof_mac = ${proofMac.mac}, initial_proof_mac_version = ${proofMac.version},
                   state_version = state_version + 1
             WHERE link_ref = ${row.link_ref}`,
      );
      await appendAudit(
        tx,
        deps.keys,
        INITIAL_LINK_PROOF_ACCEPTED,
        { stage: 'initial' },
        { now: deps.now },
      );
      return { status: 204 };
    }
    if (state !== 'awaiting_final' || row.final_proof_mac !== null) return { status: 409 };
    if (
      row.credential_kind !== claims.credentialKind ||
      Number(row.auth_epoch) !== claims.authEpoch
    ) {
      // 待機中に、旧会員の側で認証器や権限が変わった。時間がたっても疑いは消えない（O-88）。
      const { terminalAt, purgeAfter } = terminalTimes(deps.now());
      await tx.execute(
        sql`UPDATE company_api.initial_links
               SET state = 'expired', state_version = state_version + 1,
                   terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
             WHERE link_ref = ${row.link_ref}`,
      );
      await appendAudit(tx, deps.keys, INITIAL_LINK_EXPIRED, {}, { now: deps.now });
      return { status: 409 };
    }
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET final_proof_mac = ${proofMac.mac}, final_proof_mac_version = ${proofMac.version},
                 state_version = state_version + 1
           WHERE link_ref = ${row.link_ref}`,
    );
    await appendAudit(
      tx,
      deps.keys,
      INITIAL_LINK_PROOF_ACCEPTED,
      { stage: 'final' },
      { now: deps.now },
    );
    return { status: 204 };
  });
}

/**
 * 企業の側の取消（POST /v1/initial-link/cancel-requests）。旧会員の側の新しい証跡（stage は cancel）を添える。
 * prepared と、利用者の取消と同じ状態で受理し、申請を終える（O-90）。紐付けの承認を出した後は 409。
 */
export async function acceptCompanyCancel(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  client: ApiClient,
  issuer: string,
  input: { readonly proof: unknown },
): Promise<RouteResult<{ readonly state: InitialLinkState }>> {
  const claims = await verifyProof(deps, tenant, client, issuer, input.proof);
  if (claims === undefined || claims.stage !== 'cancel') return { status: 400 };
  const tenantId = tenant.tenantId;
  const linkMacs = await lookupAll(deps.keys, tenantId, 'link', claims.initialLinkId);
  const memberMacs = await lookupAll(deps.keys, tenantId, 'member', claims.memberRef);
  return deps.db.withTenant(tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByLinkMacs(tx, linkMacs);
    if (row === undefined) return { status: 404 } as const;
    if (!memberMacs.includes(row.member_mac)) return { status: 409 } as const;
    const state = await advance(tx, deps, tenant, row);
    if (state === 'cancelled') return { status: 200, body: { state } } as const;
    if (state !== 'prepared' && !OPEN_FOR_CANCEL.has(state)) return { status: 409 } as const;
    const { terminalAt, purgeAfter } = terminalTimes(now);
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'cancelled', state_version = state_version + 1, cancel_ref = ${randomUuid()},
                 cancel_accepted_at = ${now}, cancel_source = 'company',
                 terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
           WHERE link_ref = ${row.link_ref}`,
    );
    await dropWaitingSet(tx, row.link_ref);
    await appendAudit(
      tx,
      deps.keys,
      INITIAL_LINK_CANCEL_ACCEPTED,
      { source: 'company' },
      { now: deps.now },
    );
    await appendAudit(tx, deps.keys, INITIAL_LINK_CANCELLED, {}, { now: deps.now });
    return { status: 200, body: { state: 'cancelled' as InitialLinkState } } as const;
  });
}

/**
 * 企業の結果の報告（POST /v1/initial-link/results。O-91）。同じ報告の再送は 204。approved の前の linked と、
 * 取消を受理した後の linked は 409（後者は、企業の側で紐付けが先に決まったことを意味する。防御の停止と調査）。
 */
export async function recordResult(
  deps: InitialLinkDeps & { readonly onLinkedAfterCancel?: () => void },
  tenant: CompanyTenant,
  input: { readonly initialLinkId: unknown; readonly result: unknown },
): Promise<RouteResult> {
  const { initialLinkId, result } = input;
  if (
    typeof initialLinkId !== 'string' ||
    !INITIAL_LINK_ID_PATTERN.test(initialLinkId) ||
    (result !== 'linked' && result !== 'not_linked' && result !== 'cancelled')
  ) {
    return { status: 400 };
  }
  const tenantId = tenant.tenantId;
  const linkMacs = await lookupAll(deps.keys, tenantId, 'link', initialLinkId);
  return deps.db.withTenant(tenantId, async (tx): Promise<RouteResult> => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByLinkMacs(tx, linkMacs);
    if (row === undefined) return { status: 404 };
    const state = await advance(tx, deps, tenant, row);
    const { terminalAt, purgeAfter } = terminalTimes(now);
    if (result === 'linked') {
      if (state === 'linked') return { status: 204 };
      if (state === 'cancel_requested' || state === 'cancelled') deps.onLinkedAfterCancel?.();
      if (state !== 'approved' || row.user_id === null) return { status: 409 };
      await tx.execute(
        sql`UPDATE company_api.initial_links
               SET state = 'linked', state_version = state_version + 1,
                   terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
             WHERE link_ref = ${row.link_ref}`,
      );
      await tx.execute(
        sql`INSERT INTO company_api.initial_link_records
              (tenant_id, user_id, credential_kind, profile_version, participation, linked_on,
               initial_proof_mac, initial_proof_mac_version, final_proof_mac, final_proof_mac_version)
            VALUES (${tenantId}, ${row.user_id}, ${row.credential_kind}, ${row.profile_version},
                    ${tenant.participation}, ${now.toISOString().slice(0, 10)}, ${row.initial_proof_mac},
                    ${row.initial_proof_mac_version}, ${row.final_proof_mac}, ${row.final_proof_mac_version})`,
      );
      await appendAudit(tx, deps.keys, INITIAL_LINK_LINKED, {}, { now: deps.now });
      return { status: 204 };
    }
    if (result === 'not_linked') {
      if (state === 'not_linked') return { status: 204 };
      if (state !== 'approved') return { status: 409 };
      await tx.execute(
        sql`UPDATE company_api.initial_links
               SET state = 'not_linked', state_version = state_version + 1,
                   terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
             WHERE link_ref = ${row.link_ref}`,
      );
      await appendAudit(tx, deps.keys, INITIAL_LINK_NOT_LINKED, {}, { now: deps.now });
      return { status: 204 };
    }
    if (state === 'cancelled') return { status: 204 };
    if (state !== 'cancel_requested') return { status: 409 };
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'cancelled', state_version = state_version + 1,
                 terminal_at = ${terminalAt}, purge_after = ${purgeAfter}
           WHERE link_ref = ${row.link_ref}`,
    );
    await appendAudit(tx, deps.keys, INITIAL_LINK_CANCELLED, {}, { now: deps.now });
    return { status: 204 };
  });
}

// ---- idp の内部 API から ----

export type InternalResult<T = unknown> =
  | ({ readonly ok: true } & T)
  | { readonly ok: false; readonly reason: 'not_found' | 'conflict' | 'not_ready' };

/**
 * 本人の承認の前の確かめ（PAR の入口と承認の画面）。初回の証跡を受理した prepared の申請で、この利用者に開いている
 * ほかの申請も、紐付け済みの記録もないときだけ ok（O-86、O-87）。
 */
export async function checkForApproval(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly initialLinkId: string },
): Promise<InternalResult> {
  if (!usable(tenant) || !INITIAL_LINK_ID_PATTERN.test(input.initialLinkId)) {
    return { ok: false, reason: 'not_found' };
  }
  const linkMacs = await lookupAll(deps.keys, tenant.tenantId, 'link', input.initialLinkId);
  return deps.db.withTenant(tenant.tenantId, async (tx): Promise<InternalResult> => {
    await purge(tx, deps.now());
    const row = await lockByLinkMacs(tx, linkMacs);
    if (row === undefined) return { ok: false, reason: 'not_found' };
    const state = await advance(tx, deps, tenant, row);
    if (state !== 'prepared' || row.initial_proof_mac === null) {
      return { ok: false, reason: state === 'prepared' ? 'not_ready' : 'conflict' };
    }
    if (await userBusy(tx, input.userId, row.link_ref)) return { ok: false, reason: 'conflict' };
    return { ok: true };
  });
}

async function userBusy(tx: Tx, userId: WarifuUserId, linkRef: string): Promise<boolean> {
  const [open] = await tx.query<{ link_ref: string }>(
    sql`SELECT link_ref FROM company_api.initial_links
         WHERE user_id = ${userId} AND terminal_at IS NULL AND link_ref <> ${linkRef} LIMIT 1`,
  );
  if (open !== undefined) return true;
  const [record] = await tx.query<{ user_id: string }>(
    sql`SELECT user_id FROM company_api.initial_link_records WHERE user_id = ${userId}`,
  );
  return record !== undefined;
}

/**
 * 本人の承認を記録する（/v1/initial_link_approve。O-103 の手順2）。1つのトランザクションで、承認を記録し、
 * pending_notice にし、待機の知らせの SET を送信待ちに入れる。同じ項目のレコード ID の再送は、同じ結果を返す。
 */
export async function recordApproval(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: {
    readonly userId: WarifuUserId;
    readonly itemRef: string;
    readonly initialLinkId: string;
  },
): Promise<InternalResult<{ readonly linkRef: string; readonly state: InitialLinkState }>> {
  if (!usable(tenant) || !INITIAL_LINK_ID_PATTERN.test(input.initialLinkId)) {
    return { ok: false, reason: 'not_found' };
  }
  const linkMacs = await lookupAll(deps.keys, tenant.tenantId, 'link', input.initialLinkId);
  try {
    return await deps.db.withTenant(tenant.tenantId, async (tx) => {
      const now = deps.now();
      await purge(tx, now);
      const row = await lockByLinkMacs(tx, linkMacs);
      if (row === undefined) return { ok: false, reason: 'not_found' } as const;
      if (row.item_ref !== null) {
        // 再送：同じ項目、同じ利用者なら同じ結果。
        if (row.item_ref !== input.itemRef || row.user_id !== input.userId) {
          return { ok: false, reason: 'conflict' } as const;
        }
        const state = await advance(tx, deps, tenant, row);
        return { ok: true, linkRef: row.link_ref, state } as const;
      }
      const state = await advance(tx, deps, tenant, row);
      if (state !== 'prepared') return { ok: false, reason: 'conflict' } as const;
      if (row.initial_proof_mac === null) return { ok: false, reason: 'not_ready' } as const;
      if (await userBusy(tx, input.userId, row.link_ref)) {
        return { ok: false, reason: 'conflict' } as const;
      }
      await tx.execute(
        sql`UPDATE company_api.initial_links
               SET state = 'pending_notice', state_version = state_version + 1, user_id = ${input.userId},
                   approved_at = ${now}, item_ref = ${input.itemRef}
             WHERE link_ref = ${row.link_ref}`,
      );
      await tx.execute(
        sql`INSERT INTO company_api.set_outbox
              (event_id, tenant_id, event_type, state, link_ref, deliver_after)
            VALUES (${randomUuid()}, ${tenant.tenantId}, 'initial_link_waiting', ${null}, ${row.link_ref},
                    ${new Date(now.getTime() + initialDelayMs())})
            ON CONFLICT DO NOTHING`,
      );
      await appendAudit(tx, deps.keys, INITIAL_LINK_NOTICE_QUEUED, {}, { now: deps.now });
      return {
        ok: true,
        linkRef: row.link_ref,
        state: 'pending_notice' as InitialLinkState,
      } as const;
    });
  } catch (error) {
    // 同じ利用者の別の申請が、同時に開いた（一意制約）。
    if (error instanceof DbError && error.code === UNIQUE_VIOLATION) {
      return { ok: false, reason: 'conflict' };
    }
    throw error;
  }
}

/**
 * 最終の承認（/v1/initial_link_finalize。O-86 の手順7）。待機が満ち、2つ目の証跡を受理し、同じ利用者で、親申請の
 * 期限と版が変わっていないときだけ approved にして、移行専用ID を返す（idp はこれで紐付けの承認の JWT を作る）。
 */
export async function recordFinalApproval(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly itemRef: string },
): Promise<InternalResult<{ readonly initialLinkId: string }>> {
  if (!usable(tenant)) return { ok: false, reason: 'not_found' };
  const found = await deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByItemRef(tx, input.itemRef);
    if (row === undefined || row.user_id !== input.userId) {
      return { ok: false, reason: 'not_found' } as const;
    }
    const state = await advance(tx, deps, tenant, row);
    if (state === 'approved') return { ok: true, row } as const;
    if (state !== 'awaiting_final') {
      return {
        ok: false,
        reason: state === 'pending_link' || state === 'pending_notice' ? 'not_ready' : 'conflict',
      } as const;
    }
    if (row.final_proof_mac === null) return { ok: false, reason: 'not_ready' } as const;
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'approved', state_version = state_version + 1, final_approved_at = ${now}
           WHERE link_ref = ${row.link_ref}`,
    );
    await appendAudit(tx, deps.keys, INITIAL_LINK_APPROVED, {}, { now: deps.now });
    return { ok: true, row } as const;
  });
  if (!found.ok) return found;
  const { id } = await publicIdOf(
    deps.keys,
    tenant.tenantId,
    'link',
    found.row.link_ref,
    found.row.public_id_version,
  );
  return { ok: true, initialLinkId: id };
}

// 受信箱に出す項目の状態（/v1/initial_link_status）。正本にないもの、別の利用者のものは unknown。

export async function statusOf(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly itemRefs: readonly string[] },
): Promise<readonly InitialLinkStatusItem[]> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    await purge(tx, deps.now());
    const out: InitialLinkStatusItem[] = [];
    for (const itemRef of input.itemRefs) {
      const row = await lockByItemRef(tx, itemRef);
      if (row === undefined || row.user_id !== input.userId) {
        out.push({ itemRef, state: 'unknown', waitUntil: null });
        continue;
      }
      const state = await advance(tx, deps, tenant, row);
      out.push({
        itemRef,
        state,
        waitUntil:
          state === 'pending_link' && row.wait_until !== null ? row.wait_until.toISOString() : null,
      });
    }
    return out;
  });
}

/**
 * 利用者の取消（/v1/initial_link_cancel。O-90）。pending_notice、pending_link、awaiting_final で受理し、
 * cancel_requested にして取消の SET を送信待ちに入れる。approved では受理しない（409）。
 */
export async function acceptUserCancel(
  deps: InitialLinkDeps,
  tenant: CompanyTenant,
  input: { readonly userId: WarifuUserId; readonly itemRef: string },
): Promise<InternalResult<{ readonly state: InitialLinkState }>> {
  return deps.db.withTenant(tenant.tenantId, async (tx) => {
    const now = deps.now();
    await purge(tx, now);
    const row = await lockByItemRef(tx, input.itemRef);
    if (row === undefined || row.user_id !== input.userId) {
      return { ok: false, reason: 'not_found' } as const;
    }
    const state = await advance(tx, deps, tenant, row);
    if (state === 'cancel_requested' || state === 'cancelled') return { ok: true, state } as const;
    if (!OPEN_FOR_CANCEL.has(state)) return { ok: false, reason: 'conflict' } as const;
    await tx.execute(
      sql`UPDATE company_api.initial_links
             SET state = 'cancel_requested', state_version = state_version + 1, cancel_ref = ${randomUuid()},
                 cancel_accepted_at = ${now}, cancel_source = 'user'
           WHERE link_ref = ${row.link_ref}`,
    );
    await dropWaitingSet(tx, row.link_ref);
    await tx.execute(
      sql`INSERT INTO company_api.set_outbox
            (event_id, tenant_id, event_type, state, link_ref, deliver_after)
          VALUES (${randomUuid()}, ${tenant.tenantId}, 'initial_link_cancellation', ${null}, ${row.link_ref},
                  ${new Date(now.getTime() + initialDelayMs())})
          ON CONFLICT DO NOTHING`,
    );
    await appendAudit(
      tx,
      deps.keys,
      INITIAL_LINK_CANCEL_ACCEPTED,
      { source: 'user' },
      { now: deps.now },
    );
    return { ok: true, state: 'cancel_requested' as InitialLinkState } as const;
  });
}

// ---- 送信待ちから ----

/** 待機の知らせの SET と取消の SET に入れる ID（送るときに、行に置いた版で導く）。送るものがなければ undefined。 */
export async function initialLinkEventOf(
  deps: Pick<InitialLinkDeps, 'db' | 'keys'>,
  tenantId: TenantId,
  linkRef: string,
  type: 'initial_link_waiting' | 'initial_link_cancellation',
): Promise<{ readonly initialLinkId: string; readonly cancellationId?: string } | undefined> {
  const row = await deps.db.withTenant(tenantId, async (tx) => {
    const [found] = await tx.query<{
      public_id_version: number;
      state: InitialLinkState;
      cancel_ref: string | null;
    }>(
      sql`SELECT public_id_version, state, cancel_ref FROM company_api.initial_links WHERE link_ref = ${linkRef}`,
    );
    return found;
  });
  if (row === undefined) return undefined;
  if (type === 'initial_link_waiting' && row.state !== 'pending_notice') return undefined;
  if (type === 'initial_link_cancellation' && row.cancel_ref === null) return undefined;
  const { id } = await publicIdOf(deps.keys, tenantId, 'link', linkRef, row.public_id_version);
  if (type === 'initial_link_waiting') return { initialLinkId: id };
  const cancellation = await publicIdOf(
    deps.keys,
    tenantId,
    'cancel',
    row.cancel_ref as string,
    row.public_id_version,
  );
  return { initialLinkId: id, cancellationId: cancellation.id };
}

/**
 * 待機の知らせの SET に 202 が返った（O-103）。その時刻を待機の起点として固定し、pending_link にする。
 * 送信待ちの行を消すトランザクションの中で呼ぶ（withTenant の中）。
 */
export async function startWaiting(
  tx: Tx,
  deps: Pick<InitialLinkDeps, 'keys' | 'now'>,
  linkRef: string,
): Promise<boolean> {
  const now = deps.now();
  const waitUntil = new Date(now.getTime() + INITIAL_LINK_TIMES.waitMs);
  const parent = new Date(now.getTime() + INITIAL_LINK_TIMES.parentMs);
  const updated = await tx.execute(
    sql`UPDATE company_api.initial_links
           SET state = 'pending_link', state_version = state_version + 1, wait_started_at = ${now},
               wait_until = ${waitUntil}, parent_expires_at = ${parent}
         WHERE link_ref = ${linkRef} AND state = 'pending_notice'`,
  );
  if (updated === 1) await appendAudit(tx, deps.keys, INITIAL_LINK_WAITING, {}, { now: deps.now });
  return updated === 1;
}

/** テスト用ではない：起動のとき、行が参照する鍵の版が鍵サービスにあるかを確かめる（O-87）。なければ false。 */
export async function referencedVersionsAvailable(
  deps: Pick<InitialLinkDeps, 'db' | 'keys'>,
  tenants: Iterable<CompanyTenant>,
): Promise<boolean> {
  const probe = randomBytesOf(16);
  const publicVersions = new Set(
    (await deps.keys.macAllVersions('initial_link_public_id', probe)).map((m) => m.version),
  );
  const lookupVersions = new Set(
    (await deps.keys.macAllVersions('initial_link_lookup', probe)).map((m) => m.version),
  );
  for (const tenant of tenants) {
    const ok = await deps.db.withTenant(tenant.tenantId, async (tx) => {
      const [row] = await tx.query<{ public_max: number | null; lookup_max: number | null }>(
        sql`SELECT max(public_id_version) AS public_max,
                   max(greatest(request_mac_version, link_mac_version, member_mac_version,
                                coalesce(initial_proof_mac_version, 0), coalesce(final_proof_mac_version, 0)))
                     AS lookup_max
              FROM company_api.initial_links`,
      );
      const publicMax = row?.public_max ?? 0;
      const lookupMax = row?.lookup_max ?? 0;
      const covered = (versions: Set<number>, max: number) =>
        max === 0 || [...Array(max).keys()].every((i) => versions.has(i + 1));
      return covered(publicVersions, publicMax) && covered(lookupVersions, lookupMax);
    });
    if (!ok) return false;
  }
  return true;
}
