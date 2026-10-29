// 承認用のオリジン：承認用のログイン、承認待ちの一覧、承認と拒否（DESIGN.md 原則8、ADR 0023）。

import { randomBytesOf, toBase64Url, type WarifuUserId } from '@pii-token-vault/warifu-core';
import { bodyOf, FAILED, RATE_LIMITED } from '../http.ts';
import {
  type ApprovalDecision,
  approvalChallengeMessage,
  DEVICE_KINDS,
  decideApproval,
  findPendingApproval,
  listPendingApprovals,
  type PendingApproval,
} from '../inbox.ts';
import { APPROVAL_SESSION_COOKIE } from '../sessions.ts';
import type { RouteContext } from './context.ts';

const DECISIONS: ReadonlySet<string> = new Set<ApprovalDecision>(['approved', 'denied']);
/**
 * 承認の画面に出す固定の警告文（DESIGN.md 3章）。文言は画面の側の定数だけを使い、ここでは ID だけを渡す。
 * M6 は端末での承認（A-2）だけ。窓口での承認（A-1）は、画面の必須要素とともに M7 で足す。
 */
const WARNING_OF = Object.freeze({ device: 'A-2' } as const);

export function registerApprovalRoutes(ctx: RouteContext): void {
  const { app, onApproval, repo, keys, registry, approvalTypes, limiter, ceremonies } = ctx;

  /** 承認画面の中身（DESIGN.md 1章の順：企業名、操作の種類、操作の内容、要求の時刻と端末、補足）。 */
  function approvalCardOf(item: PendingApproval) {
    const def = approvalTypes.get(item.type);
    const tenant = registry.tenants.get(item.tenantId);
    if (def === undefined || tenant === undefined) return undefined;
    return {
      id: item.itemId,
      company: tenant.displayName,
      operation: def.operation,
      lines: def.lines(item.content),
      createdAt: item.createdAt.toISOString(),
      device: DEVICE_KINDS[item.device],
      expiresAt: item.expiresAt.toISOString(),
      warning: WARNING_OF[def.channel],
    };
  }

  async function approvalChallenge(
    item: PendingApproval,
    userId: WarifuUserId,
    decision: ApprovalDecision,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return keys.mac(
      'approval_challenge',
      approvalChallengeMessage({ item, userId, decision, sessionRef, nonce }),
    );
  }

  app.post('/api/approvals/login/options', onApproval, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    return ceremonies.authenticationOptions({ purpose: 'approval_login', bind: '' });
  });

  app.post('/api/approvals/login/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'approval_login',
      bind: '',
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    ctx.setCookie(reply, APPROVAL_SESSION_COOKIE, await ctx.approvalSessions.create(result.userId));
    return { ok: true };
  });

  app.get('/api/approvals', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const pending = await listPendingApprovals(repo, current.session.userId);
    return { approvals: pending.map(approvalCardOf).filter((card) => card !== undefined) };
  });

  app.post('/api/approvals/decide/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip) || !limiter.take('approvalByUser', userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const body = bodyOf(request);
    const decision = body.decision;
    if (typeof decision !== 'string' || !DECISIONS.has(decision)) {
      return reply.code(400).send(FAILED);
    }
    const item = await findPendingApproval(repo, userId, body.id);
    if (item === undefined || approvalCardOf(item) === undefined) {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    const challenge = await approvalChallenge(
      item,
      userId,
      decision as ApprovalDecision,
      ref,
      nonce,
    );
    return ceremonies.approvalOptions({
      challenge,
      bind: ref,
      userId,
      itemId: item.itemId,
      decision: decision as ApprovalDecision,
      nonce,
    });
  });

  app.post('/api/approvals/decide/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    const result = await ceremonies.verifyApproval({
      ceremonyId: body.ceremonyId,
      response: body.response,
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ itemId, decision, nonce }) => {
        const item = await findPendingApproval(repo, userId, itemId);
        if (item === undefined) return undefined;
        return toBase64Url(await approvalChallenge(item, userId, decision, ref, nonce));
      },
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    // 状態の変更は1つの文で行う。同じ要求に、承認と拒否の両方は通らない（ADR 0006、ADR 0023）。
    const decided = await decideApproval(repo, {
      userId,
      itemId: result.itemId,
      decision: result.decision,
    });
    if (decided === undefined) return reply.code(409).send({ error: 'already_decided' });
    // 企業へ結果を引き渡す後処理は、M6 では持たない（確実な引き渡しは M7 で決める。ADR 0023）。
    return { ok: true, decision: result.decision };
  });
}
