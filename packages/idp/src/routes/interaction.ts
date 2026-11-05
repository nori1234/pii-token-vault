// OIDC のインタラクション（本来のオリジン）：ログイン、アカウントの作成、接続の同意、中止。
// 窓口の申請（authorization_details の warifu_desk）のインタラクションは、承認用のオリジンに引き継ぐ（routes/desk.ts。
// ADR 0026 の O-61）。そのインタラクションでは、ここのログイン、アカウントの作成、同意を受け付けない（通常のログインに
// 縮退させない。D-20）。

import { newWarifuUserId, type TenantId, type WarifuUserId } from '@pii-token-vault/warifu-core';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { ensureFirstAlias } from '../alias.ts';
import { deskDetailFromParam } from '../desk.ts';
import { bodyOf, FAILED, RATE_LIMITED } from '../http.ts';
import { renderPage } from '../pages.ts';
import { ACR_PASSKEY, clientEntryOf } from '../provider.ts';
import { createAccount, recordConnection, recordSubject } from '../repo.ts';
import { deriveSub } from '../subject.ts';
import type { RouteContext } from './context.ts';
import { startDeskHandoff } from './desk.ts';

const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export function registerInteractionRoutes(ctx: RouteContext): void {
  const { app, onMain, repo, keys, registry, provider, limiter, ceremonies } = ctx;

  async function detailsOf(request: FastifyRequest, reply: FastifyReply) {
    const uid = (request.params as { uid?: unknown }).uid;
    if (typeof uid !== 'string' || !UID_PATTERN.test(uid)) return undefined;
    try {
      const details = await provider.interactionDetails(request.raw, reply.raw);
      if (details.uid !== uid) return undefined;
      const entry = clientEntryOf(registry, String(details.params.client_id));
      const tenant = registry.tenants.get(entry.tenantId);
      if (tenant === undefined) return undefined;
      const desk = details.params.authorization_details !== undefined;
      return { details, uid, tenant, entry, desk };
    } catch {
      return undefined;
    }
  }

  /** 通常のログイン、アカウントの作成、同意のインタラクション（窓口の申請でないもの）。 */
  async function plainDetailsOf(request: FastifyRequest, reply: FastifyReply) {
    const found = await detailsOf(request, reply);
    return found === undefined || found.desk ? undefined : found;
  }

  async function finishLogin(request: FastifyRequest, reply: FastifyReply, userId: WarifuUserId) {
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      { login: { accountId: userId, acr: ACR_PASSKEY, remember: true } },
      { mergeWithLastSubmission: false },
    );
    return { redirectTo };
  }

  async function deny(
    request: FastifyRequest,
    reply: FastifyReply,
    description = 'the request was not accepted',
  ) {
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      { error: 'access_denied', error_description: description },
      { mergeWithLastSubmission: false },
    );
    return { redirectTo };
  }

  app.get('/interaction/:uid', onMain, async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (found.desk) {
      const detail = deskDetailFromParam(
        found.details.params.authorization_details,
        found.entry.deskActions,
      );
      if (detail === undefined) {
        const { redirectTo } = await deny(request, reply);
        return reply.redirect(redirectTo, 303);
      }
      return startDeskHandoff(ctx, request, reply, {
        uid: found.uid,
        tenantId: found.tenant.tenantId as TenantId,
        clientId: found.entry.clientId,
        detail,
      });
    }
    const prompt = found.details.prompt.name === 'consent' ? 'consent' : 'login';
    return ctx.sendHtml(request, reply, (nonce) =>
      renderPage({
        nonce,
        page: 'interaction',
        uid: found.uid,
        prompt,
        companyName: found.tenant.displayName,
      }),
    );
  });

  app.post('/interaction/:uid/login/options', onMain, async (request, reply) => {
    const found = await plainDetailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    return ceremonies.authenticationOptions({ purpose: 'login', bind: `interaction:${found.uid}` });
  });

  app.post('/interaction/:uid/login/verify', onMain, async (request, reply) => {
    const found = await plainDetailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'login',
      bind: `interaction:${found.uid}`,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    return finishLogin(request, reply, result.userId);
  });

  app.post('/interaction/:uid/register/options', onMain, async (request, reply) => {
    const found = await plainDetailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (
      !limiter.take('accountCreateByIp', request.ip) ||
      !limiter.take('ceremonyByIp', request.ip)
    ) {
      return reply.code(429).send(RATE_LIMITED);
    }
    return ceremonies.registrationOptions({
      purpose: 'create',
      userId: newWarifuUserId(),
      bind: `interaction:${found.uid}`,
    });
  });

  app.post('/interaction/:uid/register/verify', onMain, async (request, reply) => {
    const found = await plainDetailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    const body = bodyOf(request);
    const result = await ceremonies.verifyRegistration({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'create',
      bind: `interaction:${found.uid}`,
    });
    if (!result.ok) return reply.code(400).send(FAILED);
    await createAccount(repo, result.userId, result.credential);
    return finishLogin(request, reply, result.userId);
  });

  app.post('/interaction/:uid/consent', onMain, async (request, reply) => {
    const found = await plainDetailsOf(request, reply);
    if (found === undefined || found.details.prompt.name !== 'consent')
      return reply.code(400).send(FAILED);
    const accountId = found.details.session?.accountId;
    if (accountId === undefined) return reply.code(400).send(FAILED);
    const userId = accountId as WarifuUserId;
    if (bodyOf(request).decision !== 'connect') {
      return deny(request, reply, 'the end-user did not connect');
    }
    await ensureFirstAlias(repo, keys, found.tenant, userId);
    const tenantId = found.tenant.tenantId as TenantId;
    await recordSubject(repo, tenantId, userId, await deriveSub(keys, tenantId, userId));
    await recordConnection(repo, userId, tenantId);
    const grant = new provider.Grant({
      accountId: userId,
      clientId: String(found.details.params.client_id),
    });
    grant.addOIDCScope('openid email');
    const grantId = await grant.save();
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      { consent: { grantId } },
      { mergeWithLastSubmission: true },
    );
    return { redirectTo };
  });

  app.post('/interaction/:uid/abort', onMain, async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    return deny(request, reply, 'the end-user cancelled');
  });
}
