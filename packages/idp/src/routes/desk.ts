// 窓口の操作別承認のルート（ADR 0026 の O-61〜O-63、O-68）。
//
// 本来のオリジン：
// - GET /interaction/:uid（interaction.ts）：要求に warifu_desk があれば、startDeskHandoff で引き継ぎを作り、
//   承認用のオリジンの /desk に移らせる（uid は URL のフラグメントで渡し、サーバーには送らない）。
// - GET /interaction/:uid/desk/finish：引き継ぎの結果で、インタラクションを完了する（承認なら、承認した利用者で
//   ログインし、操作ごとの承認の JWT を入れた Grant で同意する。それ以外は access_denied）。
// - GET /op-approval/jwks：操作ごとの承認の JWT の公開鍵。
// 承認用のオリジン：
// - GET /desk、POST /api/desk/view、/api/desk/approve/options、/api/desk/approve/verify、/api/desk/decline：
//   窓口での承認の画面と、承認（内容に結び付いた UV 付きのパスキー）と、承認しない（パスキーなし）。
// - GET /api/desk-items、POST /api/desk-items/cancel/options、/api/desk-items/cancel/verify：窓口の作成の項目と、
//   取消（承認用のセッションと、項目に結び付いた UV 付きのパスキー）。
//
// 応答の本文は固定の形だけ。申請ID、変更ID、JWT は、ログにも応答のエラーにも出さない（不変条件4）。

import {
  randomBytesOf,
  type TenantId,
  toBase64Url,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { DeskClientError } from '@pii-token-vault/warifu-core/desk/client';
import {
  DESK_TIMES,
  type DeskChangeState,
  isDeskWriteAction,
  isTerminalDeskState,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { InteractionResults } from 'oidc-provider';
import {
  auditApproved,
  auditCancelRequested,
  auditDeclined,
  DESK_ACTION_LABELS,
  DESK_CATEGORY_LABELS,
  DESK_CHANGE_TEXT,
  DESK_DECLINE_REASONS,
  DESK_HANDOFF_KIND,
  DESK_LANGUAGE_LABELS,
  DESK_SCOPE_TEXTS,
  DESK_VALIDITY_TEXT,
  type DeskDeclineReason,
  type DeskDetail,
  type DeskHandoff,
  type DeskItem,
  deleteItem,
  deskCancelChallengeMessage,
  deskChallengeMessage,
  deskDetailFromParam,
  deskDetailJson,
  findDeskItem,
  insertApprovingItem,
  isOpen,
  listDeskItems,
  loadHandoff,
  markItemApproved,
  sameDeskDetail,
  saveHandoff,
  settleDeskItems,
  signOpApproval,
} from '../desk.ts';
import { bodyOf, FAILED, RATE_LIMITED } from '../http.ts';
import { DEVICE_KINDS, deviceKindOf } from '../inbox.ts';
import { renderPage } from '../pages.ts';
import { ACR_PASSKEY, clientEntryOf } from '../provider.ts';
import { hasConnection } from '../repo.ts';
import { deriveSub } from '../subject.ts';
import type { RouteContext } from './context.ts';

const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** 承認しないときの理由（画面の案内と監査だけに使う。企業には区別して返さない）。 */
const DECLINE_REASONS: ReadonlySet<string> = new Set(DESK_DECLINE_REASONS);
/** 窓口の承認の画面の固定の警告文（DESIGN.md 3章の A-1）。サーバーは ID だけを渡す。 */
const DESK_WARNING = 'A-1';
/** 窓口での変更の知らせの固定の警告文（DESIGN.md 3章の E）。 */
const NOTICE_WARNING = 'E';

/** 受信箱に出す窓口の項目の状態（画面の文言は app.js の固定の語）。 */
export type DeskItemView =
  | 'approving'
  | 'awaiting_notice'
  | 'created'
  | 'cancel_requested'
  | 'cancelled'
  | 'not_created'
  | 'closed'
  | 'unknown';

/** 受信箱の窓口の項目（企業名は登録簿、操作は固定のラベル）。 */
export interface DeskItemEntry {
  readonly id: string;
  readonly kind: 'desk';
  readonly company: string;
  readonly operation: string;
  readonly state: DeskItemView;
  readonly cancelDeadline: string | null;
  readonly cancellable: boolean;
  readonly createdAt: string;
  readonly warning: typeof NOTICE_WARNING;
}

function viewOf(
  item: DeskItem,
  state: DeskChangeState | 'unknown',
  deadline: string | null,
  nowMs: number,
): DeskItemView {
  if (state === 'unknown') return item.state === 'approving' ? 'approving' : 'unknown';
  if (state === 'created' && deadline !== null && Date.parse(deadline) <= nowMs) return 'closed';
  return state;
}

/**
 * 利用者の窓口の項目を、正本の状態と合わせて返す（受信箱と、承認用のオリジンの一覧で使う）。正本が終端なら、
 * 項目を片付ける（7日後に消す予定を付ける）。company-api につながらなければ、状態は unknown にする。
 */
export async function deskItemEntries(
  ctx: RouteContext,
  userId: WarifuUserId,
): Promise<DeskItemEntry[]> {
  const items = await listDeskItems(ctx.repo, userId);
  if (items.length === 0) return [];
  const states = new Map<string, { state: DeskChangeState | 'unknown'; deadline: string | null }>();
  let reachable = false;
  if (ctx.desk !== undefined) {
    try {
      const result = await ctx.desk.status({
        userId,
        items: items.map((item) => ({ tenantId: item.tenantId, changeRef: item.changeRef })),
      });
      for (const entry of result) {
        states.set(entry.changeRef, { state: entry.state, deadline: entry.cancelDeadline });
      }
      reachable = true;
    } catch (error) {
      if (!(error instanceof DeskClientError)) throw error;
    }
  }
  if (reachable) {
    const terminal: string[] = [];
    const missing: string[] = [];
    const recorded: string[] = [];
    for (const item of items) {
      const state = states.get(item.changeRef)?.state ?? 'unknown';
      if (state === 'unknown') missing.push(item.itemId);
      else if (isTerminalDeskState(state)) terminal.push(item.itemId);
      else if (item.state === 'approving') recorded.push(item.itemId);
    }
    await settleDeskItems(ctx.repo, userId, { terminal, missing, recorded });
  }
  const nowMs = ctx.nowMs();
  const out: DeskItemEntry[] = [];
  for (const item of items) {
    const tenant = ctx.registry.tenants.get(item.tenantId);
    if (tenant === undefined) continue;
    const found = states.get(item.changeRef) ?? { state: 'unknown' as const, deadline: null };
    const view = viewOf(item, found.state, found.deadline, nowMs);
    out.push({
      id: item.itemId,
      kind: 'desk',
      company: tenant.displayName,
      operation: DESK_ACTION_LABELS[item.action],
      state: view,
      cancelDeadline: found.deadline,
      cancellable: view === 'awaiting_notice' || view === 'created',
      createdAt: item.createdAt.toISOString(),
      warning: NOTICE_WARNING,
    });
  }
  return out;
}

/**
 * 窓口の申請のインタラクションを、承認用のオリジンに引き継ぐ（interaction.ts の GET /interaction/:uid から呼ぶ）。
 * 引き継ぎは、インタラクションごとに1つ。すでにあれば作り直さない（期限を延ばさない）。
 */
export async function startDeskHandoff(
  ctx: RouteContext,
  request: FastifyRequest,
  reply: FastifyReply,
  input: {
    readonly uid: string;
    readonly tenantId: TenantId;
    readonly clientId: string;
    readonly detail: DeskDetail;
  },
): Promise<FastifyReply> {
  const nowMs = ctx.nowMs();
  const existing = await loadHandoff(ctx.store, input.uid, nowMs);
  if (existing === undefined) {
    if (!ctx.limiter.take('deskByClient', input.clientId))
      return reply.code(429).send(RATE_LIMITED);
    const handoff: DeskHandoff = {
      uid: input.uid,
      tenantId: input.tenantId,
      clientId: input.clientId,
      detail: input.detail,
      device: deviceKindOf(request.headers['user-agent']),
      createdAt: nowMs,
      expiresAt: nowMs + DESK_TIMES.requestTtlSeconds * 1000,
      state: 'pending',
      failures: 0,
    };
    await saveHandoff(ctx.store, handoff, nowMs);
  } else if (existing.state !== 'pending') {
    return reply.redirect(`/interaction/${input.uid}/desk/finish`, 303);
  }
  return reply.redirect(`${ctx.approvalOrigin}/desk#${input.uid}`, 303);
}

export function registerDeskRoutes(ctx: RouteContext): void {
  const { app, onMain, onApproval, repo, keys, registry, limiter, ceremonies, store, provider } =
    ctx;
  /** 同じ引き継ぎの承認を、同時に2つ進めない（このプロセスの中）。 */
  const inFlight = new Set<string>();

  function finishUrl(uid: string): string {
    return `${ctx.origin}/interaction/${uid}/desk/finish`;
  }

  function uidOf(value: unknown): string | undefined {
    return typeof value === 'string' && UID_PATTERN.test(value) ? value : undefined;
  }

  /** 承認画面の中身（DESIGN.md 2章「窓口での承認（step-up）」の必須要素）。 */
  function cardOf(handoff: DeskHandoff) {
    const tenant = registry.tenants.get(handoff.tenantId);
    if (tenant === undefined) return undefined;
    const { detail } = handoff;
    return {
      company: tenant.displayName,
      operation: DESK_ACTION_LABELS[detail.action],
      lines:
        detail.choices === null
          ? []
          : [
              { label: '種別', value: DESK_CATEGORY_LABELS[detail.choices.category] },
              { label: '希望する言語', value: DESK_LANGUAGE_LABELS[detail.choices.language] },
            ],
      scope: DESK_SCOPE_TEXTS[detail.action],
      validity: DESK_VALIDITY_TEXT,
      change: DESK_CHANGE_TEXT,
      createdAt: new Date(handoff.createdAt).toISOString(),
      device: DEVICE_KINDS[handoff.device],
      expiresAt: new Date(handoff.expiresAt).toISOString(),
      warning: DESK_WARNING,
    };
  }

  async function challengeOf(handoff: DeskHandoff, nonce: string): Promise<string> {
    return toBase64Url(await keys.mac('approval_challenge', deskChallengeMessage(handoff, nonce)));
  }

  // ---- 本来のオリジン ----

  app.get('/op-approval/jwks', onMain, async () => ({
    keys: await keys.publicKeys('op_approval'),
  }));

  app.get('/interaction/:uid/desk/finish', onMain, async (request, reply) => {
    const uid = uidOf((request.params as { uid?: unknown }).uid);
    if (uid === undefined) return reply.code(400).send(FAILED);
    let details: Awaited<ReturnType<typeof provider.interactionDetails>>;
    try {
      details = await provider.interactionDetails(request.raw, reply.raw);
    } catch {
      return reply.code(400).send(FAILED);
    }
    if (details.uid !== uid) return reply.code(400).send(FAILED);
    const clientId = String(details.params.client_id);
    const entry = clientEntryOf(registry, clientId);
    const requested = deskDetailFromParam(details.params.authorization_details, entry.deskActions);
    const handoff = await store.take<DeskHandoff>(DESK_HANDOFF_KIND, uid);
    let result: InteractionResults = {
      error: 'access_denied',
      error_description: 'the end-user did not approve the request',
    };
    if (
      handoff !== undefined &&
      handoff.uid === uid &&
      handoff.state === 'approved' &&
      handoff.approval !== undefined &&
      handoff.clientId === clientId &&
      requested !== undefined &&
      sameDeskDetail(handoff.detail, requested)
    ) {
      const { userId, approvedAt, jwt } = handoff.approval;
      const grant = new provider.Grant({ accountId: userId, clientId });
      const scopes = String(details.params.scope ?? '')
        .split(' ')
        .filter((scope) => scope === 'openid' || scope === 'email');
      grant.addOIDCScope([...new Set(['openid', ...scopes])].join(' '));
      grant.addRar({ ...deskDetailJson(handoff.detail), approval: jwt } as never);
      const grantId = await grant.save();
      result = {
        login: {
          accountId: userId,
          acr: ACR_PASSKEY,
          ts: Math.floor(approvedAt / 1000),
          remember: false,
        },
        consent: { grantId },
      };
    }
    const redirectTo = await provider.interactionResult(request.raw, reply.raw, result, {
      mergeWithLastSubmission: false,
    });
    return reply.redirect(redirectTo, 303);
  });

  // ---- 承認用のオリジン：窓口での承認 ----

  app.get('/desk', onApproval, async (request, reply) =>
    ctx.sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'desk' })),
  );

  app.post('/api/desk/view', onApproval, async (request, reply) => {
    const uid = uidOf(bodyOf(request).uid);
    const handoff = uid === undefined ? undefined : await loadHandoff(store, uid, ctx.nowMs());
    const card = isOpen(handoff, ctx.nowMs()) ? cardOf(handoff) : undefined;
    if (card === undefined) return reply.code(400).send(FAILED);
    return card;
  });

  app.post('/api/desk/approve/options', onApproval, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const body = bodyOf(request);
    const uid = uidOf(body.uid);
    // 相手からの電話かを尋ねる問いに「自分から連絡した」と答えた要求にだけ、承認の選択肢を出す（D-38）。
    if (uid === undefined || body.call !== 'self') return reply.code(400).send(FAILED);
    const handoff = await loadHandoff(store, uid, ctx.nowMs());
    if (!isOpen(handoff, ctx.nowMs()) || cardOf(handoff) === undefined) {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    const challenge = await keys.mac('approval_challenge', deskChallengeMessage(handoff, nonce));
    return ceremonies.boundOptions({
      purpose: 'desk_approve',
      challenge,
      bind: uid,
      userId: null,
      ref: uid,
      nonce,
    });
  });

  app.post('/api/desk/approve/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    let target: DeskHandoff | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'desk_approve',
      // 結び付く相手は、儀式に覚えた uid（recompute の ref）。本文の値は使わない。
      bind: uidOf(body.uid) ?? '',
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref, nonce }) => {
        const handoff = await loadHandoff(store, ref, ctx.nowMs());
        if (!isOpen(handoff, ctx.nowMs())) return undefined;
        target = handoff;
        return challengeOf(handoff, nonce);
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    const { uid } = target;
    if (inFlight.has(uid)) return reply.code(409).send(FAILED);
    inFlight.add(uid);
    try {
      // 検証の間に、拒否、期限切れ、失敗の上限で引き継ぎが閉じていないかを、読み直して確かめる（承認と拒否の両方は通さない）。
      const handoff = await loadHandoff(store, uid, ctx.nowMs());
      if (!isOpen(handoff, ctx.nowMs())) return reply.code(401).send(FAILED);
      const { tenantId, clientId, detail } = handoff;
      const { userId } = result;
      // アサーションの利用者の sub が、申請の subject と一致し、その企業に接続済みのときだけ承認する（O-61、O-53）。
      const sub = await deriveSub(keys, tenantId, userId);
      if (sub !== detail.subject || !(await hasConnection(repo, userId, tenantId))) {
        await saveHandoff(store, { ...handoff, failures: handoff.failures + 1 }, ctx.nowMs());
        return reply.code(401).send(FAILED);
      }
      await ctx.recordUse(result);
      let changeId: string | null = null;
      if (isDeskWriteAction(detail.action)) {
        // 作成は、idp の項目と company-api の正本に記録してから承認を返す（O-63）。どこかで失敗すれば、承認を返さない。
        if (ctx.desk === undefined) return reply.code(503).send({ error: 'unavailable' });
        const item = await insertApprovingItem(repo, userId, tenantId);
        let recorded: Awaited<ReturnType<typeof ctx.desk.approve>>;
        try {
          recorded = await ctx.desk.approve({
            tenantId,
            userId,
            changeRef: item.changeRef,
            requestId: detail.identifier,
            action: detail.action,
          });
        } catch (error) {
          if (!(error instanceof DeskClientError)) throw error;
          // 正本に記録できたかが分からない。項目は approving のまま残し、受信箱を読むときに片付ける。
          return reply.code(503).send({ error: 'unavailable' });
        }
        if (!recorded.ok) {
          await deleteItem(repo, userId, item.itemId);
          await saveHandoff(store, { ...handoff, state: 'declined' }, ctx.nowMs());
          return reply.code(409).send(FAILED);
        }
        await markItemApproved(repo, userId, item.itemId);
        changeId = recorded.changeId;
      }
      const approvedAt = ctx.nowMs();
      const jwt = await signOpApproval(keys, {
        issuer: ctx.issuer,
        clientId,
        sub,
        detail,
        changeId,
        acr: ACR_PASSKEY,
        authTime: Math.floor(approvedAt / 1000),
      });
      await saveHandoff(
        store,
        { ...handoff, state: 'approved', approval: { userId, approvedAt, jwt } },
        approvedAt,
      );
      await auditApproved(repo, userId, tenantId, detail.action);
      request.log.info({ event: 'idp.desk_approved' });
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });

  app.post('/api/desk/decline', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const uid = uidOf(body.uid);
    const reason = body.reason;
    if (uid === undefined || typeof reason !== 'string' || !DECLINE_REASONS.has(reason)) {
      return reply.code(400).send(FAILED);
    }
    // 承認と同じ印を取ってから読む（承認の途中の引き継ぎは拒否にしない。承認と拒否の両方は通さない）。
    if (inFlight.has(uid)) return reply.code(400).send(FAILED);
    inFlight.add(uid);
    try {
      const handoff = await loadHandoff(store, uid, ctx.nowMs());
      if (handoff === undefined || handoff.state !== 'pending') return reply.code(400).send(FAILED);
      await saveHandoff(
        store,
        { ...handoff, state: 'declined', declineReason: reason as DeskDeclineReason },
        ctx.nowMs(),
      );
      await auditDeclined(repo, handoff.tenantId, reason as DeskDeclineReason);
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });

  // ---- 承認用のオリジン：窓口の作成の項目と取消 ----

  app.get('/api/desk-items', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    return { items: await deskItemEntries(ctx, current.session.userId) };
  });

  async function cancelChallenge(
    item: DeskItem,
    userId: WarifuUserId,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return keys.mac(
      'approval_challenge',
      deskCancelChallengeMessage({ item, userId, sessionRef, nonce }),
    );
  }

  app.post('/api/desk-items/cancel/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip) || !limiter.take('deskCancelByUser', userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const item = await findDeskItem(repo, userId, bodyOf(request).id);
    if (item === undefined || item.state !== 'approved') return reply.code(400).send(FAILED);
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'desk_cancel',
      challenge: await cancelChallenge(item, userId, ref, nonce),
      bind: ref,
      userId,
      ref: item.itemId,
      nonce,
    });
  });

  app.post('/api/desk-items/cancel/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    let target: DeskItem | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'desk_cancel',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: itemId, nonce }) => {
        const item = await findDeskItem(repo, userId, itemId);
        if (item === undefined || item.state !== 'approved') return undefined;
        target = item;
        return toBase64Url(await cancelChallenge(item, userId, ref, nonce));
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    if (ctx.desk === undefined) return reply.code(503).send({ error: 'unavailable' });
    const item: DeskItem = target;
    let cancelled: Awaited<ReturnType<typeof ctx.desk.cancel>>;
    try {
      cancelled = await ctx.desk.cancel({
        tenantId: item.tenantId,
        userId,
        changeRef: item.changeRef,
      });
    } catch (error) {
      if (!(error instanceof DeskClientError)) throw error;
      return reply.code(503).send({ error: 'unavailable' });
    }
    if (!cancelled.ok) {
      return reply
        .code(cancelled.reason === 'closed' ? 409 : 400)
        .send(cancelled.reason === 'closed' ? { error: 'closed' } : FAILED);
    }
    await auditCancelRequested(repo, userId, item.tenantId);
    request.log.info({ event: 'idp.desk_cancel_requested' });
    return { ok: true, state: cancelled.state };
  });
}
