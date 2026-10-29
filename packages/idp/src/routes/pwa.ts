// PWA（本来のオリジン）：アカウントの作成とログイン、ログアウト、自分の情報、step-up、メール、パスキー。

import { fromBase64Url, newWarifuUserId, toBase64Url } from '@pii-token-vault/warifu-core';
import { currentAlias } from '../alias.ts';
import { confirmEmailVerification, startEmailVerification } from '../email.ts';
import { bodyOf, cookieOf, FAILED, isRecord, RATE_LIMITED } from '../http.ts';
import {
  addCredential,
  createAccount,
  deleteCredential,
  emailStatus,
  listConnections,
  listCredentials,
} from '../repo.ts';
import { PWA_SESSION_COOKIE } from '../sessions.ts';
import type { RouteContext } from './context.ts';

export function registerPwaRoutes(ctx: RouteContext): void {
  const { app, onMain, repo, keys, registry, sessions, limiter, ceremonies } = ctx;

  // ---- アカウントの作成とログイン ----

  app.post('/api/register/options', onMain, async (request, reply) => {
    if (
      !limiter.take('accountCreateByIp', request.ip) ||
      !limiter.take('ceremonyByIp', request.ip)
    ) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const userId = newWarifuUserId();
    return ceremonies.registrationOptions({ purpose: 'create', userId, bind: '' });
  });

  app.post('/api/register/verify', onMain, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyRegistration({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'create',
      bind: '',
    });
    if (!result.ok) return reply.code(400).send(FAILED);
    await createAccount(repo, result.userId, result.credential);
    ctx.setCookie(reply, PWA_SESSION_COOKIE, await sessions.create(result.userId));
    return { ok: true };
  });

  app.post('/api/login/options', onMain, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    return ceremonies.authenticationOptions({ purpose: 'login', bind: '' });
  });

  app.post('/api/login/verify', onMain, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'login',
      bind: '',
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    ctx.setCookie(reply, PWA_SESSION_COOKIE, await sessions.create(result.userId));
    return { ok: true };
  });

  app.post('/api/logout', onMain, async (request, reply) => {
    await sessions.destroy(cookieOf(request, PWA_SESSION_COOKIE));
    ctx.clearCookie(reply, PWA_SESSION_COOKIE);
    return { ok: true };
  });

  // ---- ログインした後 ----

  app.get('/api/me', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    const { userId } = current.session;
    const [email, credentials, connections] = await Promise.all([
      emailStatus(repo, userId),
      listCredentials(repo, userId),
      listConnections(repo, userId),
    ]);
    const companies = [];
    for (const connection of connections) {
      const tenant = registry.tenants.get(connection.tenantId);
      if (tenant === undefined) continue;
      companies.push({
        name: tenant.displayName,
        alias: (await currentAlias(repo, keys, tenant, userId)) ?? null,
        connectedAt: connection.consentedAt.toISOString(),
      });
    }
    return {
      fresh: sessions.isFresh(current.session),
      email: {
        registered: email.registered,
        updatedAt: email.updatedAt?.toISOString() ?? null,
        pendingUntil: email.pendingUntil?.toISOString() ?? null,
      },
      passkeys: credentials.map((c) => ({
        id: toBase64Url(c.credentialId),
        synced: c.backupEligible,
        createdAt: c.createdAt.toISOString(),
        lastUsedAt: c.lastUsedAt?.toISOString() ?? null,
      })),
      companies,
    };
  });

  app.post('/api/stepup/options', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    return ceremonies.authenticationOptions({ purpose: 'stepup', bind: current.session.ref });
  });

  app.post('/api/stepup/verify', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'stepup',
      bind: current.session.ref,
      expectedUserId: current.session.userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    await sessions.markAuthenticated(current.cookie, result.userId);
    return { ok: true };
  });

  // 登録済みかどうかで応答を変えない（不変条件10）。形の違う入力とレート制限だけは別の応答にする
  // （どちらも、そのアドレスが登録済みかどうかとは関係しない）。
  app.post('/api/email/start', onMain, async (request, reply) => {
    const current = await ctx.requireFreshSession(request, reply);
    if (current === undefined) return reply;
    const result = await startEmailVerification(ctx.emailDeps, {
      userId: current.session.userId,
      email: bodyOf(request).email,
      ip: request.ip,
    });
    if (result === 'invalid_input') return reply.code(400).send({ error: 'invalid_input' });
    if (result === 'rate_limited') return reply.code(429).send(RATE_LIMITED);
    return reply.code(202).send({ status: 'sent' });
  });

  app.post('/api/email/confirm', onMain, async (request, reply) => {
    const current = await ctx.requireSession(request, reply);
    if (current === undefined) return reply;
    const result = await confirmEmailVerification(ctx.emailDeps, {
      userId: current.session.userId,
      code: bodyOf(request).code,
    });
    if (result === 'invalid') return reply.code(400).send(FAILED);
    return { ok: true };
  });

  app.post('/api/passkeys/options', onMain, async (request, reply) => {
    const current = await ctx.requireFreshSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const existing = await listCredentials(repo, current.session.userId);
    return ceremonies.registrationOptions({
      purpose: 'add',
      userId: current.session.userId,
      bind: current.session.ref,
      excludeCredentialIds: existing.map((c) => c.credentialId),
    });
  });

  app.post('/api/passkeys/verify', onMain, async (request, reply) => {
    const current = await ctx.requireFreshSession(request, reply);
    if (current === undefined) return reply;
    const body = bodyOf(request);
    const result = await ceremonies.verifyRegistration({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'add',
      bind: current.session.ref,
    });
    if (!result.ok || result.userId !== current.session.userId) return reply.code(400).send(FAILED);
    await addCredential(repo, result.userId, result.credential);
    return { ok: true };
  });

  app.post('/api/passkeys/delete', onMain, async (request, reply) => {
    const current = await ctx.requireFreshSession(request, reply);
    if (current === undefined) return reply;
    const id = bodyOf(request).id;
    let credentialId: Uint8Array;
    try {
      credentialId = typeof id === 'string' ? fromBase64Url(id) : new Uint8Array();
    } catch {
      return reply.code(400).send(FAILED);
    }
    if (credentialId.byteLength < 16) return reply.code(400).send(FAILED);
    const deleted = await deleteCredential(repo, current.session.userId, credentialId);
    if (!deleted) return reply.code(400).send(FAILED);
    // パスキーを消したら、その利用者のセッション（PWA、承認用のオリジン、OIDC）をすべて消す（ADR 0018、ADR 0023）。
    sessions.revokeUser(current.session.userId);
    ctx.approvalSessions.revokeUser(current.session.userId);
    ctx.store.deleteWhere(
      'Session',
      (value) => isRecord(value) && value.accountId === current.session.userId,
    );
    ctx.clearCookie(reply, PWA_SESSION_COOKIE);
    return { ok: true, reloginRequired: true };
  });
}
