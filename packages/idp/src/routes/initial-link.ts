// 既存会員の初回紐付けのルート（ADR 0028 の O-86・O-90・O-103）。窓口の操作別承認（routes/desk.ts）と同じ形。
//
// 本来のオリジン：
// - GET /interaction/:uid（interaction.ts）：要求に warifu_initial_link があれば、startInitialLinkHandoff で引き継ぎを
//   作り、承認用のオリジンの /initial-link に移らせる（uid は URL のフラグメントで渡す）。
// - GET /interaction/:uid/initial-link/finish：引き継ぎの結果で、インタラクションを完了する。最初の承認なら、Grant に
//   正本の状態（pending_notice）だけを入れる。最終の承認なら、紐付けの承認の JWT を入れる。それ以外は access_denied。
// - GET /initial-link/jwks：紐付けの承認の JWT の公開鍵。
// 承認用のオリジン：
// - GET /initial-link、POST /api/initial-link/view、/api/initial-link/approve/options、/api/initial-link/approve/verify、
//   /api/initial-link/decline：承認の画面と、承認（内容に結び付いた UV 付きのパスキー）と、承認しない（パスキーなし）。
// - GET /api/initial-link-items、POST /api/initial-link-items/cancel/options、/api/initial-link-items/cancel/verify：
//   初回紐付けの項目と、取消（承認用のセッションと、項目に結び付いた UV 付きのパスキー）。
//
// 応答の本文は固定の形だけ。移行専用ID、JWT は、ログにも応答のエラーにも出さない（不変条件4）。

import {
  randomBytesOf,
  type TenantId,
  toBase64Url,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { DeskClientError } from '@pii-token-vault/warifu-core/desk/client';
import {
  INITIAL_LINK_IDP_TIMES,
  type InitialLinkState,
} from '@pii-token-vault/warifu-core/desk/protocol';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { InteractionResults } from 'oidc-provider';
import { bodyOf, FAILED, RATE_LIMITED, RESTRICTED } from '../http.ts';
import { DEVICE_KINDS, deviceKindOf } from '../inbox.ts';
import {
  auditInitialLinkApproved,
  auditInitialLinkCancelRequested,
  auditInitialLinkDeclined,
  deleteInitialLinkItem,
  findInitialLinkItem,
  INITIAL_LINK_DECLINE_REASONS,
  INITIAL_LINK_HANDOFF_KIND,
  INITIAL_LINK_TEXTS,
  type InitialLinkDeclineReason,
  type InitialLinkDetail,
  type InitialLinkHandoff,
  type InitialLinkItem,
  initialLinkCancelChallengeMessage,
  initialLinkChallengeMessage,
  initialLinkDetailJson,
  insertApprovingInitialLinkItem,
  isOpenInitialLink,
  isTerminalInitialLinkState,
  listInitialLinkItems,
  loadInitialLinkHandoff,
  markInitialLinkItemApproved,
  sameInitialLinkDetail,
  saveInitialLinkHandoff,
  settleInitialLinkItems,
  signInitialLinkApproval,
} from '../initial-link.ts';
import { renderPage } from '../pages.ts';
import { ACR_PASSKEY, clientEntryOf } from '../provider.ts';
import { requestedDetailFromParam } from '../rar.ts';
import { isRecoveryRestricted } from '../recovery.ts';
import { hasConnection } from '../repo.ts';
import { deriveSub } from '../subject.ts';
import type { RouteContext } from './context.ts';

const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const DECLINE_REASONS: ReadonlySet<string> = new Set(INITIAL_LINK_DECLINE_REASONS);

/** 受信箱に出す初回紐付けの項目の状態（画面の文言は app.js の固定の語）。 */
export type InitialLinkItemView =
  | 'approving'
  | 'awaiting_notice'
  | 'waiting'
  | 'ready'
  | 'finalizing'
  | 'linked'
  | 'cancel_requested'
  | 'cancelled'
  | 'expired'
  | 'not_linked'
  | 'unknown';

export interface InitialLinkItemEntry {
  readonly id: string;
  readonly kind: 'initial_link';
  readonly company: string;
  readonly operation: string;
  readonly state: InitialLinkItemView;
  /** 待機が終わる日時（待機中だけ）。 */
  readonly waitUntil: string | null;
  readonly cancellable: boolean;
  readonly createdAt: string;
}

const VIEWS: Readonly<Record<InitialLinkState, InitialLinkItemView>> = Object.freeze({
  // prepared は、本人の承認の前で、受信箱の項目はない（来たら approving と同じに扱う）。
  prepared: 'approving',
  pending_notice: 'awaiting_notice',
  pending_link: 'waiting',
  awaiting_final: 'ready',
  approved: 'finalizing',
  linked: 'linked',
  cancel_requested: 'cancel_requested',
  cancelled: 'cancelled',
  expired: 'expired',
  not_linked: 'not_linked',
});

const CANCELLABLE: ReadonlySet<InitialLinkItemView> = new Set([
  'awaiting_notice',
  'waiting',
  'ready',
]);

/**
 * 利用者の初回紐付けの項目を、正本の状態と合わせて返す（受信箱と、承認用のオリジンの一覧で使う）。正本が終端なら、
 * 項目を片付ける。company-api につながらなければ、状態は unknown にする。
 */
export async function initialLinkItemEntries(
  ctx: RouteContext,
  userId: WarifuUserId,
): Promise<InitialLinkItemEntry[]> {
  const items = await listInitialLinkItems(ctx.repo, userId);
  if (items.length === 0) return [];
  const states = new Map<
    string,
    { state: InitialLinkState | 'unknown'; waitUntil: string | null }
  >();
  const reached = new Set<TenantId>();
  if (ctx.desk !== undefined) {
    const byTenant = new Map<TenantId, InitialLinkItem[]>();
    for (const item of items) {
      byTenant.set(item.tenantId, [...(byTenant.get(item.tenantId) ?? []), item]);
    }
    for (const [tenantId, group] of byTenant) {
      try {
        const result = await ctx.desk.initialLinkStatus({
          tenantId,
          userId,
          itemRefs: group.map((item) => item.linkRef),
        });
        for (const entry of result) {
          states.set(entry.itemRef, { state: entry.state, waitUntil: entry.waitUntil });
        }
        reached.add(tenantId);
      } catch (error) {
        if (!(error instanceof DeskClientError)) throw error;
      }
    }
  }
  const terminal: string[] = [];
  const missing: string[] = [];
  const recorded: string[] = [];
  for (const item of items) {
    if (!reached.has(item.tenantId)) continue;
    const state = states.get(item.linkRef)?.state ?? 'unknown';
    if (state === 'unknown') missing.push(item.itemId);
    else if (isTerminalInitialLinkState(state)) terminal.push(item.itemId);
    else if (item.state === 'approving') recorded.push(item.itemId);
  }
  await settleInitialLinkItems(ctx.repo, userId, { terminal, missing, recorded });
  const out: InitialLinkItemEntry[] = [];
  for (const item of items) {
    const tenant = ctx.registry.tenants.get(item.tenantId);
    if (tenant === undefined) continue;
    const found = states.get(item.linkRef) ?? { state: 'unknown' as const, waitUntil: null };
    const view: InitialLinkItemView =
      found.state === 'unknown'
        ? item.state === 'approving'
          ? 'approving'
          : 'unknown'
        : VIEWS[found.state];
    out.push({
      id: item.itemId,
      kind: 'initial_link',
      company: tenant.displayName,
      operation: INITIAL_LINK_TEXTS.operation,
      state: view,
      waitUntil: view === 'waiting' ? found.waitUntil : null,
      cancellable: item.state === 'approved' && CANCELLABLE.has(view),
      createdAt: item.createdAt.toISOString(),
    });
  }
  return out;
}

/**
 * 初回紐付けの申請のインタラクションを、承認用のオリジンに引き継ぐ（interaction.ts から呼ぶ）。
 * 引き継ぎは、インタラクションごとに1つ。すでにあれば作り直さない（期限を延ばさない）。
 */
export async function startInitialLinkHandoff(
  ctx: RouteContext,
  request: FastifyRequest,
  reply: FastifyReply,
  input: {
    readonly uid: string;
    readonly tenantId: TenantId;
    readonly clientId: string;
    readonly detail: InitialLinkDetail;
  },
): Promise<FastifyReply> {
  const nowMs = ctx.nowMs();
  const existing = await loadInitialLinkHandoff(ctx.store, input.uid, nowMs);
  if (existing === undefined) {
    if (!ctx.limiter.take('initialLinkByClient', input.clientId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const handoff: InitialLinkHandoff = {
      uid: input.uid,
      tenantId: input.tenantId,
      clientId: input.clientId,
      detail: input.detail,
      device: deviceKindOf(request.headers['user-agent']),
      createdAt: nowMs,
      expiresAt: nowMs + INITIAL_LINK_IDP_TIMES.requestTtlSeconds * 1000,
      state: 'pending',
      failures: 0,
    };
    await saveInitialLinkHandoff(ctx.store, handoff, nowMs);
  } else if (existing.state !== 'pending') {
    return reply.redirect(`/interaction/${input.uid}/initial-link/finish`, 303);
  }
  return reply.redirect(`${ctx.approvalOrigin}/initial-link#${input.uid}`, 303);
}

export function registerInitialLinkRoutes(ctx: RouteContext): void {
  const { app, onMain, onApproval, repo, keys, registry, limiter, ceremonies, store, provider } =
    ctx;
  /** 同じ引き継ぎの承認を、同時に2つ進めない（このプロセスの中）。 */
  const inFlight = new Set<string>();

  function finishUrl(uid: string): string {
    return `${ctx.origin}/interaction/${uid}/initial-link/finish`;
  }

  function uidOf(value: unknown): string | undefined {
    return typeof value === 'string' && UID_PATTERN.test(value) ? value : undefined;
  }

  /** 承認画面の中身（DESIGN.md 2章「初回紐付けの承認」「初回紐付けの最終確認」）。 */
  function cardOf(handoff: InitialLinkHandoff) {
    const tenant = registry.tenants.get(handoff.tenantId);
    if (tenant === undefined) return undefined;
    const final = handoff.detail.action === 'initial_link.finalize';
    return {
      company: tenant.displayName,
      operation: INITIAL_LINK_TEXTS.operation,
      stage: final ? ('final' as const) : ('initial' as const),
      purpose: INITIAL_LINK_TEXTS.purpose,
      permanent: INITIAL_LINK_TEXTS.permanent,
      explanation: final ? INITIAL_LINK_TEXTS.final : INITIAL_LINK_TEXTS.waiting,
      notice: final ? null : INITIAL_LINK_TEXTS.notice,
      createdAt: new Date(handoff.createdAt).toISOString(),
      device: DEVICE_KINDS[handoff.device],
      expiresAt: new Date(handoff.expiresAt).toISOString(),
    };
  }

  async function challengeOf(handoff: InitialLinkHandoff, nonce: string): Promise<string> {
    return toBase64Url(
      await keys.mac('approval_challenge', initialLinkChallengeMessage(handoff, nonce)),
    );
  }

  // ---- 本来のオリジン ----

  app.get('/initial-link/jwks', onMain, async () => ({
    keys: await keys.publicKeys('initial_link'),
  }));

  app.get('/interaction/:uid/initial-link/finish', onMain, async (request, reply) => {
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
    const requested = requestedDetailFromParam(details.params.authorization_details, entry);
    const handoff = await store.take<InitialLinkHandoff>(INITIAL_LINK_HANDOFF_KIND, uid);
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
      requested?.kind === 'initial_link' &&
      sameInitialLinkDetail(handoff.detail, requested.detail)
    ) {
      const { userId, approvedAt, jwt, state } = handoff.approval;
      const grant = new provider.Grant({ accountId: userId, clientId });
      const scopes = String(details.params.scope ?? '')
        .split(' ')
        .filter((scope) => scope === 'openid' || scope === 'email');
      grant.addOIDCScope([...new Set(['openid', ...scopes])].join(' '));
      grant.addRar({
        ...initialLinkDetailJson(handoff.detail),
        ...(jwt === undefined ? { state } : { approval: jwt }),
      } as never);
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

  // ---- 承認用のオリジン：初回紐付けの承認 ----

  app.get('/initial-link', onApproval, async (request, reply) =>
    ctx.sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'initial-link' })),
  );

  app.post('/api/initial-link/view', onApproval, async (request, reply) => {
    const uid = uidOf(bodyOf(request).uid);
    const handoff =
      uid === undefined ? undefined : await loadInitialLinkHandoff(store, uid, ctx.nowMs());
    const card = isOpenInitialLink(handoff, ctx.nowMs()) ? cardOf(handoff) : undefined;
    if (card === undefined) return reply.code(400).send(FAILED);
    return card;
  });

  app.post('/api/initial-link/approve/options', onApproval, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const uid = uidOf(bodyOf(request).uid);
    if (uid === undefined) return reply.code(400).send(FAILED);
    const handoff = await loadInitialLinkHandoff(store, uid, ctx.nowMs());
    if (!isOpenInitialLink(handoff, ctx.nowMs()) || cardOf(handoff) === undefined) {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    const challenge = await keys.mac(
      'approval_challenge',
      initialLinkChallengeMessage(handoff, nonce),
    );
    return ceremonies.boundOptions({
      purpose: 'initial_link_approve',
      challenge,
      bind: uid,
      userId: null,
      ref: uid,
      nonce,
    });
  });

  /** 最初の承認：受信箱の項目を先に記録してから、正本に承認を記録させる（O-103）。 */
  async function approveInitial(
    handoff: InitialLinkHandoff,
    userId: WarifuUserId,
  ): Promise<
    { readonly status: number; readonly body: object } | { readonly state: InitialLinkState }
  > {
    const desk = ctx.desk;
    if (desk === undefined) return { status: 503, body: { error: 'unavailable' } };
    const { tenantId, detail } = handoff;
    // 記録の前に、承認できる申請かを確かめる（受信箱に、記録できない項目を作らない）。
    const checked = await desk.initialLinkCheck({
      tenantId,
      userId,
      initialLinkId: detail.identifier,
    });
    if (!checked.ok) return { status: 409, body: FAILED };
    const item = await insertApprovingInitialLinkItem(repo, userId, tenantId);
    let recorded: Awaited<ReturnType<typeof desk.initialLinkApprove>>;
    try {
      recorded = await desk.initialLinkApprove({
        tenantId,
        userId,
        itemRef: item.linkRef,
        initialLinkId: detail.identifier,
      });
    } catch (error) {
      if (!(error instanceof DeskClientError)) throw error;
      // 正本に記録できたかが分からない。項目は approving のまま残し、受信箱を読むときに片付ける。
      return { status: 503, body: { error: 'unavailable' } };
    }
    if (!recorded.ok) {
      await deleteInitialLinkItem(repo, userId, item.itemId);
      return { status: 409, body: FAILED };
    }
    await markInitialLinkItemApproved(repo, userId, item.itemId);
    return { state: recorded.state };
  }

  /** 最終の承認：自分の項目を引き、正本に確かめさせて、移行専用ID を受け取る（O-86 の手順7）。 */
  async function approveFinal(
    handoff: InitialLinkHandoff,
    userId: WarifuUserId,
  ): Promise<
    { readonly status: number; readonly body: object } | { readonly initialLinkId: string }
  > {
    const desk = ctx.desk;
    if (desk === undefined) return { status: 503, body: { error: 'unavailable' } };
    const items = (await listInitialLinkItems(repo, userId, handoff.tenantId)).filter(
      (item) => item.state === 'approved',
    );
    for (const item of items) {
      let finalized: Awaited<ReturnType<typeof desk.initialLinkFinalize>>;
      try {
        finalized = await desk.initialLinkFinalize({
          tenantId: handoff.tenantId,
          userId,
          itemRef: item.linkRef,
          initialLinkId: handoff.detail.identifier,
        });
      } catch (error) {
        if (!(error instanceof DeskClientError)) throw error;
        return { status: 503, body: { error: 'unavailable' } };
      }
      if (finalized.ok) {
        // 正本が返した ID と、企業が PAR で送った ID が同じでなければ、承認を出さない。
        if (finalized.initialLinkId !== handoff.detail.identifier) break;
        return { initialLinkId: finalized.initialLinkId };
      }
      if (finalized.reason !== 'not_found') {
        return {
          status: 409,
          body: finalized.reason === 'not_ready' ? { error: 'not_ready' } : FAILED,
        };
      }
    }
    return { status: 409, body: FAILED };
  }

  app.post('/api/initial-link/approve/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    let target: InitialLinkHandoff | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'initial_link_approve',
      // 結び付く相手は、儀式に覚えた uid（recompute の ref）。本文の値は使わない。
      bind: uidOf(body.uid) ?? '',
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref, nonce }) => {
        const handoff = await loadInitialLinkHandoff(store, ref, ctx.nowMs());
        if (!isOpenInitialLink(handoff, ctx.nowMs())) return undefined;
        target = handoff;
        return challengeOf(handoff, nonce);
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    const { uid } = target;
    if (inFlight.has(uid)) return reply.code(409).send(FAILED);
    inFlight.add(uid);
    try {
      // 検証の間に、拒否、期限切れ、失敗の上限で引き継ぎが閉じていないかを、読み直して確かめる。
      const handoff = await loadInitialLinkHandoff(store, uid, ctx.nowMs());
      if (!isOpenInitialLink(handoff, ctx.nowMs())) return reply.code(401).send(FAILED);
      const { tenantId, clientId, detail } = handoff;
      const { userId } = result;
      // アサーションの利用者の sub が、申請の subject と一致し、その企業に接続済みのときだけ承認する（ADR 0026 の O-61）。
      const sub = await deriveSub(keys, tenantId, userId);
      if (sub !== detail.subject || !(await hasConnection(repo, userId, tenantId))) {
        await saveInitialLinkHandoff(
          store,
          { ...handoff, failures: handoff.failures + 1 },
          ctx.nowMs(),
        );
        return reply.code(401).send(FAILED);
      }
      await ctx.recordUse(result);
      // 回復の後7日の間は、初回紐付けの承認を出さない（ADR 0027 の O-80、ADR 0028 の O-86）。
      if (await isRecoveryRestricted(repo, userId)) return reply.code(409).send(RESTRICTED);
      const final = detail.action === 'initial_link.finalize';
      const approvedAt = ctx.nowMs();
      let approval: NonNullable<InitialLinkHandoff['approval']>;
      if (final) {
        const done = await approveFinal(handoff, userId);
        if (!('initialLinkId' in done)) return reply.code(done.status).send(done.body);
        const jwt = await signInitialLinkApproval(keys, {
          issuer: ctx.issuer,
          clientId,
          sub,
          initialLinkId: done.initialLinkId,
          acr: ACR_PASSKEY,
          authTime: Math.floor(approvedAt / 1000),
        });
        approval = { userId, approvedAt, jwt };
      } else {
        const done = await approveInitial(handoff, userId);
        if (!('state' in done)) {
          if (done.status === 409) {
            await saveInitialLinkHandoff(store, { ...handoff, state: 'declined' }, ctx.nowMs());
          }
          return reply.code(done.status).send(done.body);
        }
        approval = { userId, approvedAt, state: done.state };
      }
      await saveInitialLinkHandoff(store, { ...handoff, state: 'approved', approval }, approvedAt);
      await auditInitialLinkApproved(repo, userId, tenantId, final ? 'final' : 'initial');
      request.log.info({ event: 'idp.initial_link_approved', stage: final ? 'final' : 'initial' });
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });

  app.post('/api/initial-link/decline', onApproval, async (request, reply) => {
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
      const handoff = await loadInitialLinkHandoff(store, uid, ctx.nowMs());
      if (handoff === undefined || handoff.state !== 'pending') return reply.code(400).send(FAILED);
      await saveInitialLinkHandoff(
        store,
        { ...handoff, state: 'declined', declineReason: reason as InitialLinkDeclineReason },
        ctx.nowMs(),
      );
      await auditInitialLinkDeclined(repo, handoff.tenantId, reason as InitialLinkDeclineReason);
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });

  // ---- 承認用のオリジン：初回紐付けの項目と取消 ----

  app.get('/api/initial-link-items', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    return { items: await initialLinkItemEntries(ctx, current.session.userId) };
  });

  async function cancelChallenge(
    item: InitialLinkItem,
    userId: WarifuUserId,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return keys.mac(
      'approval_challenge',
      initialLinkCancelChallengeMessage({ item, userId, sessionRef, nonce }),
    );
  }

  app.post('/api/initial-link-items/cancel/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (
      !limiter.take('ceremonyByIp', request.ip) ||
      !limiter.take('initialLinkCancelByUser', userId)
    ) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const item = await findInitialLinkItem(repo, userId, bodyOf(request).id);
    if (item === undefined || item.state !== 'approved') return reply.code(400).send(FAILED);
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'initial_link_cancel',
      challenge: await cancelChallenge(item, userId, ref, nonce),
      bind: ref,
      userId,
      ref: item.itemId,
      nonce,
    });
  });

  app.post('/api/initial-link-items/cancel/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    let target: InitialLinkItem | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'initial_link_cancel',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: itemId, nonce }) => {
        const item = await findInitialLinkItem(repo, userId, itemId);
        if (item === undefined || item.state !== 'approved') return undefined;
        target = item;
        return toBase64Url(await cancelChallenge(item, userId, ref, nonce));
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    if (ctx.desk === undefined) return reply.code(503).send({ error: 'unavailable' });
    const item: InitialLinkItem = target;
    let cancelled: Awaited<ReturnType<typeof ctx.desk.initialLinkCancel>>;
    try {
      cancelled = await ctx.desk.initialLinkCancel({
        tenantId: item.tenantId,
        userId,
        itemRef: item.linkRef,
      });
    } catch (error) {
      if (!(error instanceof DeskClientError)) throw error;
      return reply.code(503).send({ error: 'unavailable' });
    }
    if (!cancelled.ok) {
      return reply
        .code(cancelled.reason === 'not_found' ? 400 : 409)
        .send(cancelled.reason === 'not_found' ? FAILED : { error: 'closed' });
    }
    await auditInitialLinkCancelRequested(repo, userId, item.tenantId);
    request.log.info({ event: 'idp.initial_link_cancel_requested' });
    return { ok: true, state: cancelled.state };
  });
}
