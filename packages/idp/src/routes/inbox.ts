// PWA（本来のオリジン）：受信箱の一覧と、知らせの既読（ADR 0023）。

import { bodyOf, FAILED, RATE_LIMITED } from '../http.ts';
import { type InboxItem, isItemId, listInbox, markNoticeRead, NOTICE_TYPES } from '../inbox.ts';
import type { RouteContext } from './context.ts';

export function registerInboxRoutes(ctx: RouteContext): void {
  const { app, onMain, repo, registry, approvalTypes, limiter } = ctx;

  /** 受信箱の項目を、画面に出す形にする。文言は型が決めたものだけ。企業名は登録簿の値。 */
  function inboxEntryOf(item: InboxItem) {
    if (item.kind === 'notice') {
      if (!Object.hasOwn(NOTICE_TYPES, item.type)) return undefined;
      const def = NOTICE_TYPES[item.type as keyof typeof NOTICE_TYPES];
      return {
        id: item.itemId,
        kind: 'notice' as const,
        title: def.title,
        lines: def.lines(item.content),
        state: item.state,
        createdAt: item.createdAt.toISOString(),
      };
    }
    const def = approvalTypes.get(item.type);
    const tenant = item.tenantId === null ? undefined : registry.tenants.get(item.tenantId);
    if (def === undefined || tenant === undefined || item.expiresAt === null) return undefined;
    const expired = item.state === 'pending' && item.expiresAt.getTime() <= ctx.nowMs();
    return {
      id: item.itemId,
      kind: 'approval' as const,
      title: '確認待ち',
      company: tenant.displayName,
      operation: def.operation,
      state: expired ? 'expired' : item.state,
      createdAt: item.createdAt.toISOString(),
      expiresAt: item.expiresAt.toISOString(),
    };
  }

  app.get('/api/inbox', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const items = await listInbox(repo, current.session.userId);
    const entries = items.map(inboxEntryOf).filter((entry) => entry !== undefined);
    return {
      items: entries,
      pendingApprovals: entries.filter((e) => e.kind === 'approval' && e.state === 'pending')
        .length,
    };
  });

  app.post('/api/inbox/read', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const id = bodyOf(request).id;
    const ok = isItemId(id) && (await markNoticeRead(repo, current.session.userId, id));
    if (!ok) return reply.code(400).send(FAILED);
    return { ok: true };
  });
}
