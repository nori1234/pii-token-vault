// 高リスクの操作の step-up のルート（ADR 0030 の O-113・O-114）。窓口の操作別承認（routes/desk.ts）と同じ形。
//
// 本来のオリジン：
// - GET /interaction/:uid（interaction.ts）：要求に warifu_operation があれば、startOperationHandoff で引き継ぎを作り、
//   承認用のオリジンの /operation に移らせる（uid は URL のフラグメントで渡す）。
// - GET /interaction/:uid/operation/finish：引き継ぎの結果で、インタラクションを完了する（承認なら、承認の JWT を入れた
//   Grant で同意する。それ以外は access_denied）。
// - GET /operation-approval/jwks：高リスクの操作の承認の JWT の公開鍵。
// 承認用のオリジン：
// - GET /operation、POST /api/operation/view、/api/operation/approve/options、/api/operation/approve/verify、
//   /api/operation/decline。
//
// 応答の本文は固定の形だけ。申請ID と内容、JWT は、ログにも応答のエラーにも出さない（不変条件4）。

import { randomBytesOf, type TenantId, toBase64Url } from '@pii-token-vault/warifu-core';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { InteractionResults } from 'oidc-provider';
import { bodyOf, FAILED, RATE_LIMITED, RESTRICTED } from '../http.ts';
import { DEVICE_KINDS, deviceKindOf } from '../inbox.ts';
import {
  auditOperationApproved,
  auditOperationDeclined,
  contentLines,
  DEMO_BANKS_NOTE,
  isOpenOperation,
  loadOperationHandoff,
  OPERATION_DECLINE_REASONS,
  OPERATION_HANDOFF_KIND,
  OPERATION_LABELS,
  OPERATION_TIMES,
  OPERATION_VALIDITY_TEXT,
  type OperationDeclineReason,
  type OperationDetail,
  type OperationHandoff,
  operationChallengeMessage,
  operationDetailJson,
  sameOperationDetail,
  saveOperationHandoff,
  signOperationApproval,
} from '../operation.ts';
import { renderPage } from '../pages.ts';
import { ACR_PASSKEY, clientEntryOf } from '../provider.ts';
import { requestedDetailFromParam } from '../rar.ts';
import { isRecoveryRestricted } from '../recovery.ts';
import { hasConnection } from '../repo.ts';
import { deriveSub } from '../subject.ts';
import type { RouteContext } from './context.ts';

const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const DECLINE_REASONS: ReadonlySet<string> = new Set(OPERATION_DECLINE_REASONS);
/** 端末での承認の固定の警告文（DESIGN.md 3章の A-2）。 */
const OPERATION_WARNING = 'A-2';

/** 高リスクの操作の申請を、承認用のオリジンに引き継ぐ（interaction.ts から呼ぶ）。期限は延ばさない。 */
export async function startOperationHandoff(
  ctx: RouteContext,
  request: FastifyRequest,
  reply: FastifyReply,
  input: {
    readonly uid: string;
    readonly tenantId: TenantId;
    readonly clientId: string;
    readonly detail: OperationDetail;
  },
): Promise<FastifyReply> {
  const nowMs = ctx.nowMs();
  const existing = await loadOperationHandoff(ctx.store, input.uid, nowMs);
  if (existing === undefined) {
    if (!ctx.limiter.take('operationByClient', input.clientId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    await saveOperationHandoff(
      ctx.store,
      {
        uid: input.uid,
        tenantId: input.tenantId,
        clientId: input.clientId,
        detail: input.detail,
        device: deviceKindOf(request.headers['user-agent']),
        createdAt: nowMs,
        expiresAt: nowMs + OPERATION_TIMES.requestTtlSeconds * 1000,
        state: 'pending',
        failures: 0,
      },
      nowMs,
    );
  } else if (existing.state !== 'pending') {
    return reply.redirect(`/interaction/${input.uid}/operation/finish`, 303);
  }
  return reply.redirect(`${ctx.approvalOrigin}/operation#${input.uid}`, 303);
}

export function registerOperationRoutes(ctx: RouteContext): void {
  const { app, onMain, onApproval, repo, keys, registry, limiter, ceremonies, store, provider } =
    ctx;
  const inFlight = new Set<string>();

  const finishUrl = (uid: string) => `${ctx.origin}/interaction/${uid}/operation/finish`;
  const uidOf = (value: unknown) =>
    typeof value === 'string' && UID_PATTERN.test(value) ? value : undefined;

  /** 承認画面の中身（DESIGN.md 2章「端末での承認（step-up）」）。 */
  function cardOf(handoff: OperationHandoff) {
    const tenant = registry.tenants.get(handoff.tenantId);
    if (tenant === undefined) return undefined;
    return {
      company: tenant.displayName,
      operation: OPERATION_LABELS[handoff.detail.action],
      lines: contentLines(handoff.detail),
      demoNote: DEMO_BANKS_NOTE,
      validity: OPERATION_VALIDITY_TEXT,
      createdAt: new Date(handoff.createdAt).toISOString(),
      device: DEVICE_KINDS[handoff.device],
      expiresAt: new Date(handoff.expiresAt).toISOString(),
      warning: OPERATION_WARNING,
    };
  }

  async function challengeOf(handoff: OperationHandoff, nonce: string): Promise<string> {
    return toBase64Url(
      await keys.mac('approval_challenge', operationChallengeMessage(handoff, nonce)),
    );
  }

  app.get('/operation-approval/jwks', onMain, async () => ({
    keys: await keys.publicKeys('operation_approval'),
  }));

  app.get('/interaction/:uid/operation/finish', onMain, async (request, reply) => {
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
    const handoff = await store.take<OperationHandoff>(OPERATION_HANDOFF_KIND, uid);
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
      requested?.kind === 'operation' &&
      sameOperationDetail(handoff.detail, requested.detail)
    ) {
      const { userId, approvedAt, jwt } = handoff.approval;
      const grant = new provider.Grant({ accountId: userId, clientId });
      grant.addOIDCScope('openid');
      grant.addRar({ ...operationDetailJson(handoff.detail), approval: jwt } as never);
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

  app.get('/operation', onApproval, async (request, reply) =>
    ctx.sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'operation' })),
  );

  app.post('/api/operation/view', onApproval, async (request, reply) => {
    const uid = uidOf(bodyOf(request).uid);
    const handoff =
      uid === undefined ? undefined : await loadOperationHandoff(store, uid, ctx.nowMs());
    const card = isOpenOperation(handoff, ctx.nowMs()) ? cardOf(handoff) : undefined;
    if (card === undefined) return reply.code(400).send(FAILED);
    return card;
  });

  app.post('/api/operation/approve/options', onApproval, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const uid = uidOf(bodyOf(request).uid);
    if (uid === undefined) return reply.code(400).send(FAILED);
    const handoff = await loadOperationHandoff(store, uid, ctx.nowMs());
    if (!isOpenOperation(handoff, ctx.nowMs()) || cardOf(handoff) === undefined) {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'operation_approve',
      challenge: await keys.mac('approval_challenge', operationChallengeMessage(handoff, nonce)),
      bind: uid,
      userId: null,
      ref: uid,
      nonce,
    });
  });

  app.post('/api/operation/approve/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    let target: OperationHandoff | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'operation_approve',
      bind: uidOf(body.uid) ?? '',
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref, nonce }) => {
        const handoff = await loadOperationHandoff(store, ref, ctx.nowMs());
        if (!isOpenOperation(handoff, ctx.nowMs())) return undefined;
        target = handoff;
        return challengeOf(handoff, nonce);
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    const { uid } = target;
    if (inFlight.has(uid)) return reply.code(409).send(FAILED);
    inFlight.add(uid);
    try {
      const handoff = await loadOperationHandoff(store, uid, ctx.nowMs());
      if (!isOpenOperation(handoff, ctx.nowMs())) return reply.code(401).send(FAILED);
      const { tenantId, clientId, detail } = handoff;
      const { userId } = result;
      const sub = await deriveSub(keys, tenantId, userId);
      if (sub !== detail.subject || !(await hasConnection(repo, userId, tenantId))) {
        await saveOperationHandoff(
          store,
          { ...handoff, failures: handoff.failures + 1 },
          ctx.nowMs(),
        );
        return reply.code(401).send(FAILED);
      }
      await ctx.recordUse(result);
      // 回復の後7日の間は、高リスクの操作の承認を出さない（ADR 0027 の O-80）。
      if (await isRecoveryRestricted(repo, userId)) return reply.code(409).send(RESTRICTED);
      const approvedAt = ctx.nowMs();
      const jwt = await signOperationApproval(keys, {
        issuer: ctx.issuer,
        clientId,
        sub,
        detail,
        acr: ACR_PASSKEY,
        authTime: Math.floor(approvedAt / 1000),
      });
      // 監査を先に残す。監査に失敗したら、承認を引き継ぎに入れない（監査のない承認を、企業に渡さない）。
      await auditOperationApproved(repo, userId, tenantId);
      await saveOperationHandoff(
        store,
        { ...handoff, state: 'approved', approval: { userId, approvedAt, jwt } },
        approvedAt,
      );
      request.log.info({ event: 'idp.operation_approved' });
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });

  app.post('/api/operation/decline', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const uid = uidOf(body.uid);
    const reason = body.reason;
    if (uid === undefined || typeof reason !== 'string' || !DECLINE_REASONS.has(reason)) {
      return reply.code(400).send(FAILED);
    }
    if (inFlight.has(uid)) return reply.code(400).send(FAILED);
    inFlight.add(uid);
    try {
      const handoff = await loadOperationHandoff(store, uid, ctx.nowMs());
      if (handoff === undefined || handoff.state !== 'pending') return reply.code(400).send(FAILED);
      await saveOperationHandoff(
        store,
        { ...handoff, state: 'declined', declineReason: reason as OperationDeclineReason },
        ctx.nowMs(),
      );
      await auditOperationDeclined(repo, handoff.tenantId, reason as OperationDeclineReason);
      return { redirectTo: finishUrl(uid) };
    } finally {
      inFlight.delete(uid);
    }
  });
}
