// idp のアプリ（plan 9章、ADR 0018）。Fastify 5 に、oidc-provider を @fastify/middie で /oidc に載せる。
// oidc-provider の経路には、Fastify のボディ解析を通さない（middie は onRequest で処理し、応答を終える）。
//
// ルート（x-idp-routes で一覧を固定する）：
// - PWA：GET /、/assets/*、/api/*（登録、ログイン、step-up、メール、パスキー、自分の情報、ログアウト）
// - インタラクション：GET /interaction/:uid と、その下の POST（ログイン、アカウント作成、接続の同意、中止）
// - OIDC：/oidc/*（discovery、jwks、認可、トークン）
// 逆引き（sub・別名から本物の連絡先や属性を返す）ルートと、管理用のルートは作らない（不変条件2）。
//
// 守り：
// - Host は設定した1つだけ（DNS リバインディング）。POST は同じオリジンの Origin だけ（/oidc を除く）。
// - JSON 以外の本文は受け付けない。本文は 16KB まで。
// - エラーの応答に、受け取った値もライブラリのメッセージも入れない。ログは warifu-core の許可リスト（ADR 0017）。
// - 登録済みかどうかで、応答の本文・ステータスを変えない（不変条件10。メールの登録）。

import middie from '@fastify/middie';
import {
  fromBase64Url,
  newWarifuUserId,
  randomBytesOf,
  type TenantId,
  toBase64Url,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { createDb, type Db, type DbConnection } from '@pii-token-vault/warifu-core/db';
import { createIdpKeyClient, type IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import type { KeysvcConnection } from '@pii-token-vault/warifu-core/keys/protocol';
import { createLogger, type LogLevel } from '@pii-token-vault/warifu-core/log';
import fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';
import type Provider from 'oidc-provider';
import { currentAlias, ensureFirstAlias } from './alias.ts';
import { confirmEmailVerification, type EmailFlowDeps, startEmailVerification } from './email.ts';
import { type Mailer, MemoryOutbox } from './mailer.ts';
import {
  type Assets,
  DEFAULT_CSP,
  htmlCsp,
  loadAssets,
  newNonce,
  renderPage,
  SECURITY_HEADERS,
} from './pages.ts';
import { ACR_PASSKEY, buildProvider, clientEntryOf, OIDC_MOUNT } from './provider.ts';
import { RateLimiter } from './rate-limit.ts';
import { parseRegistry, type Registry } from './registry.ts';
import {
  addCredential,
  createAccount,
  deleteCredential,
  emailStatus,
  findCredential,
  listConnections,
  listCredentials,
  type RepoDeps,
  recordConnection,
  recordCredentialUse,
  recordSubject,
} from './repo.ts';
import { PWA_SESSION_COOKIE, type PwaSession, PwaSessions } from './sessions.ts';
import { loadSigningKey } from './signing-key.ts';
import { MacMemoryStore, StorageFullError } from './storage.ts';
import { deriveSub } from './subject.ts';
import { Ceremonies } from './webauthn.ts';

export interface IdpOptions {
  /** 例：http://localhost:4300。WebAuthn の expectedOrigin はポート込みでこれに固定する。 */
  readonly origin: string;
  /** WebAuthn の RP ID。ローカルでは localhost。 */
  readonly rpId: string;
  /** 登録簿の設定（registry.ts で検査する）。 */
  readonly registry: { readonly tenants: unknown; readonly clients: unknown };
  readonly keysvc: KeysvcConnection;
  readonly db: DbConnection;
  readonly mailer?: Mailer;
  readonly now?: () => Date;
  readonly logLevel?: LogLevel;
  readonly logWrite?: (line: string) => void;
  /** テストで、oidc-provider が外へつなごうとしたかを数える。 */
  readonly onOutboundAttempt?: () => void;
}

export interface Idp {
  readonly app: FastifyInstance;
  readonly provider: Provider;
  readonly issuer: string;
  readonly registry: Registry;
  readonly mailer: Mailer;
  readonly store: MacMemoryStore;
  readonly db: Db;
  /** Fastify に登録したルート（メソッドとパス）。x-idp-routes で一覧を固定する。 */
  routes(): readonly string[];
  close(): Promise<void>;
}

const JSON_LIMIT = 16 * 1024;
const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** 応答の本文は固定の形だけ。値を入れない。 */
const FAILED = Object.freeze({ error: 'failed' });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bodyOf(request: FastifyRequest): Record<string, unknown> {
  return isRecord(request.body) ? request.body : {};
}

function cookieOf(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (typeof header !== 'string') return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

export async function createIdp(options: IdpOptions): Promise<Idp> {
  const originUrl = new URL(options.origin);
  if (originUrl.origin !== options.origin) throw new Error('origin は正規化した形で渡す');
  const issuer = `${options.origin}${OIDC_MOUNT}`;
  const secureCookie = originUrl.protocol === 'https:';
  const now = options.now ?? (() => new Date());
  const nowMs = () => now().getTime();

  const registry = parseRegistry(options.registry);
  const keys: IdpKeyClient = createIdpKeyClient(options.keysvc);
  const db = createDb({ service: 'idp', connection: options.db });
  const repo: RepoDeps = { db, keys, now };
  const store = new MacMemoryStore(keys, nowMs);
  const sessions = new PwaSessions(store, nowMs);
  const limiter = new RateLimiter(nowMs);
  const mailer = options.mailer ?? new MemoryOutbox();
  const ceremonies = new Ceremonies(store, {
    rpId: options.rpId,
    rpName: '割符',
    origin: options.origin,
  });
  const emailDeps: EmailFlowDeps = { repo, keys, mailer, limiter };
  const signingKey = await loadSigningKey(keys);
  const provider = buildProvider({
    issuer,
    registry,
    keys,
    repo,
    store,
    signingKey,
    ...(options.onOutboundAttempt === undefined
      ? {}
      : { onOutboundAttempt: options.onOutboundAttempt }),
  });
  const assets: Assets = loadAssets();

  const app = fastify({
    loggerInstance: createLogger({
      component: 'idp',
      ...(options.logLevel === undefined ? {} : { level: options.logLevel }),
      ...(options.logWrite === undefined ? {} : { write: options.logWrite }),
    }) as unknown as FastifyBaseLogger,
    bodyLimit: JSON_LIMIT,
    return503OnClosing: true,
    trustProxy: false,
  });
  const routes: string[] = [];
  app.addHook('onRoute', (route) => {
    for (const method of [route.method].flat()) routes.push(`${method} ${route.url}`);
  });
  // JSON 以外の本文は受け付けない（Fastify は既定で text/plain も解析する）。
  app.removeContentTypeParser('text/plain');

  // DNS リバインディング対策：Host は設定した1つだけ。/oidc を含むすべての経路に先にかける。
  app.addHook('onRequest', async (request, reply) => {
    if (request.headers.host !== originUrl.host) {
      return reply
        .code(421)
        .header('content-type', 'application/json')
        .send({ error: 'misdirected' });
    }
    // 状態を変える要求は、同じオリジンからだけ（クッキーは SameSite も付ける）。/oidc は企業のサーバーからも来る。
    if (
      request.method !== 'GET' &&
      request.method !== 'HEAD' &&
      !request.url.startsWith(`${OIDC_MOUNT}/`)
    ) {
      if (request.headers.origin !== options.origin) {
        return reply
          .code(403)
          .header('content-type', 'application/json')
          .send({ error: 'forbidden' });
      }
    }
  });

  await app.register(middie, { hook: 'onRequest' });
  app.use(OIDC_MOUNT, provider.callback());

  app.addHook('onSend', async (request, reply, payload) => {
    reply.headers(SECURITY_HEADERS);
    const nonce = (request as FastifyRequest & { cspNonce?: string }).cspNonce;
    reply.header('content-security-policy', nonce === undefined ? DEFAULT_CSP : htmlCsp(nonce));
    return payload;
  });

  app.setErrorHandler((error, _request, reply) => {
    // ライブラリやスキーマ検証のメッセージには、受け取った値が入ることがあるので、外に出さない。
    if (error instanceof StorageFullError) return reply.code(503).send({ error: 'busy' });
    const status = isRecord(error) && typeof error.statusCode === 'number' ? error.statusCode : 500;
    if (status >= 400 && status < 500) return reply.code(400).send({ error: 'bad_request' });
    return reply.code(500).send({ error: 'internal_error' });
  });
  app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: 'not_found' }));

  function sendHtml(request: FastifyRequest, reply: FastifyReply, html: (nonce: string) => string) {
    const nonce = newNonce(randomBytesOf(16));
    (request as FastifyRequest & { cspNonce?: string }).cspNonce = nonce;
    return reply.type('text/html; charset=utf-8').send(html(nonce));
  }

  function setSessionCookie(reply: FastifyReply, value: string): void {
    const attributes = [
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      ...(secureCookie ? ['Secure'] : []),
    ];
    reply.header('set-cookie', `${PWA_SESSION_COOKIE}=${value}; ${attributes.join('; ')}`);
  }

  function clearSessionCookie(reply: FastifyReply): void {
    const attributes = [
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=0',
      ...(secureCookie ? ['Secure'] : []),
    ];
    reply.header('set-cookie', `${PWA_SESSION_COOKIE}=; ${attributes.join('; ')}`);
  }

  async function sessionOf(
    request: FastifyRequest,
  ): Promise<{ session: PwaSession; cookie: string } | undefined> {
    const cookie = cookieOf(request, PWA_SESSION_COOKIE);
    const session = await sessions.get(cookie);
    return session === undefined || cookie === undefined ? undefined : { session, cookie };
  }

  const findForLogin = (userId: WarifuUserId, credentialId: Uint8Array) =>
    findCredential(repo, userId, credentialId);
  const admitLogin = (ip: string) => (userId: WarifuUserId) =>
    limiter.take('loginByUser', userId) && limiter.take('loginByIp', ip);

  // ---- 画面と配信物 ----

  app.get('/', async (request, reply) =>
    sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'home' })),
  );
  app.get('/assets/app.js', async (_request, reply) =>
    reply.type('text/javascript; charset=utf-8').send(assets.appJs),
  );
  app.get('/assets/app.css', async (_request, reply) =>
    reply.type('text/css; charset=utf-8').send(assets.appCss),
  );
  app.get('/assets/webauthn.js', async (_request, reply) =>
    reply.type('text/javascript; charset=utf-8').send(assets.webauthnJs),
  );

  // ---- PWA：アカウントの作成とログイン ----

  app.post('/api/register/options', async (request, reply) => {
    if (
      !limiter.take('accountCreateByIp', request.ip) ||
      !limiter.take('ceremonyByIp', request.ip)
    ) {
      return reply.code(429).send({ error: 'rate_limited' });
    }
    const userId = newWarifuUserId();
    return ceremonies.registrationOptions({ purpose: 'create', userId, bind: '' });
  });

  app.post('/api/register/verify', async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyRegistration({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'create',
      bind: '',
    });
    if (!result.ok) return reply.code(400).send(FAILED);
    await createAccount(repo, result.userId, result.credential);
    setSessionCookie(reply, await sessions.create(result.userId));
    return { ok: true };
  });

  app.post('/api/login/options', async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'login', bind: '' });
  });

  app.post('/api/login/verify', async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'login',
      bind: '',
      find: findForLogin,
      admit: admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await recordCredentialUse(
      repo,
      result.userId,
      result.credentialId,
      result.newSignCount,
      result.backedUp,
    );
    setSessionCookie(reply, await sessions.create(result.userId));
    return { ok: true };
  });

  app.post('/api/logout', async (request, reply) => {
    await sessions.destroy(cookieOf(request, PWA_SESSION_COOKIE));
    clearSessionCookie(reply);
    return { ok: true };
  });

  // ---- PWA：ログインした後 ----

  app.get('/api/me', async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
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

  app.post('/api/stepup/options', async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'stepup', bind: current.session.ref });
  });

  app.post('/api/stepup/verify', async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'stepup',
      bind: current.session.ref,
      expectedUserId: current.session.userId,
      find: findForLogin,
      admit: admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await recordCredentialUse(
      repo,
      result.userId,
      result.credentialId,
      result.newSignCount,
      result.backedUp,
    );
    await sessions.markAuthenticated(current.cookie, result.userId);
    return { ok: true };
  });

  /** step-up（5分以内の認証）が要る操作の前に呼ぶ。 */
  async function freshSessionOf(request: FastifyRequest, reply: FastifyReply) {
    const current = await sessionOf(request);
    if (current === undefined) {
      void reply.code(401).send({ error: 'login_required' });
      return undefined;
    }
    if (!sessions.isFresh(current.session)) {
      void reply.code(401).send({ error: 'reauth_required' });
      return undefined;
    }
    return current;
  }

  // 登録済みかどうかで応答を変えない（不変条件10）。形の違う入力とレート制限だけは別の応答にする
  // （どちらも、そのアドレスが登録済みかどうかとは関係しない）。
  app.post('/api/email/start', async (request, reply) => {
    const current = await freshSessionOf(request, reply);
    if (current === undefined) return reply;
    const result = await startEmailVerification(emailDeps, {
      userId: current.session.userId,
      email: bodyOf(request).email,
      ip: request.ip,
    });
    if (result === 'invalid_input') return reply.code(400).send({ error: 'invalid_input' });
    if (result === 'rate_limited') return reply.code(429).send({ error: 'rate_limited' });
    return reply.code(202).send({ status: 'sent' });
  });

  app.post('/api/email/confirm', async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    const result = await confirmEmailVerification(emailDeps, {
      userId: current.session.userId,
      code: bodyOf(request).code,
    });
    if (result === 'invalid') return reply.code(400).send(FAILED);
    return { ok: true };
  });

  app.post('/api/passkeys/options', async (request, reply) => {
    const current = await freshSessionOf(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    const existing = await listCredentials(repo, current.session.userId);
    return ceremonies.registrationOptions({
      purpose: 'add',
      userId: current.session.userId,
      bind: current.session.ref,
      excludeCredentialIds: existing.map((c) => c.credentialId),
    });
  });

  app.post('/api/passkeys/verify', async (request, reply) => {
    const current = await freshSessionOf(request, reply);
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

  app.post('/api/passkeys/delete', async (request, reply) => {
    const current = await freshSessionOf(request, reply);
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
    // パスキーを消したら、その利用者のセッション（PWA と OIDC）をすべて消す（ADR 0018）。
    sessions.revokeUser(current.session.userId);
    store.deleteWhere(
      'Session',
      (value) => isRecord(value) && value.accountId === current.session.userId,
    );
    clearSessionCookie(reply);
    return { ok: true, reloginRequired: true };
  });

  // ---- OIDC のインタラクション（ログインと、接続の同意） ----

  async function detailsOf(request: FastifyRequest, reply: FastifyReply) {
    const uid = (request.params as { uid?: unknown }).uid;
    if (typeof uid !== 'string' || !UID_PATTERN.test(uid)) return undefined;
    try {
      const details = await provider.interactionDetails(request.raw, reply.raw);
      if (details.uid !== uid) return undefined;
      const entry = clientEntryOf(registry, String(details.params.client_id));
      const tenant = registry.tenants.get(entry.tenantId);
      if (tenant === undefined) return undefined;
      return { details, uid, tenant };
    } catch {
      return undefined;
    }
  }

  app.get('/interaction/:uid', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    const prompt = found.details.prompt.name === 'consent' ? 'consent' : 'login';
    return sendHtml(request, reply, (nonce) =>
      renderPage({
        nonce,
        page: 'interaction',
        uid: found.uid,
        prompt,
        companyName: found.tenant.displayName,
      }),
    );
  });

  async function finishLogin(request: FastifyRequest, reply: FastifyReply, userId: WarifuUserId) {
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      { login: { accountId: userId, acr: ACR_PASSKEY, remember: true } },
      { mergeWithLastSubmission: false },
    );
    return { redirectTo };
  }

  app.post('/interaction/:uid/login/options', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'login', bind: `interaction:${found.uid}` });
  });

  app.post('/interaction/:uid/login/verify', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'login',
      bind: `interaction:${found.uid}`,
      find: findForLogin,
      admit: admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await recordCredentialUse(
      repo,
      result.userId,
      result.credentialId,
      result.newSignCount,
      result.backedUp,
    );
    return finishLogin(request, reply, result.userId);
  });

  app.post('/interaction/:uid/register/options', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (
      !limiter.take('accountCreateByIp', request.ip) ||
      !limiter.take('ceremonyByIp', request.ip)
    ) {
      return reply.code(429).send({ error: 'rate_limited' });
    }
    return ceremonies.registrationOptions({
      purpose: 'create',
      userId: newWarifuUserId(),
      bind: `interaction:${found.uid}`,
    });
  });

  app.post('/interaction/:uid/register/verify', async (request, reply) => {
    const found = await detailsOf(request, reply);
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

  app.post('/interaction/:uid/consent', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined || found.details.prompt.name !== 'consent')
      return reply.code(400).send(FAILED);
    const accountId = found.details.session?.accountId;
    if (accountId === undefined) return reply.code(400).send(FAILED);
    const userId = accountId as WarifuUserId;
    const decision = bodyOf(request).decision;
    if (decision !== 'connect') {
      const redirectTo = await provider.interactionResult(
        request.raw,
        reply.raw,
        { error: 'access_denied', error_description: 'the end-user did not connect' },
        { mergeWithLastSubmission: false },
      );
      return { redirectTo };
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

  app.post('/interaction/:uid/abort', async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    const redirectTo = await provider.interactionResult(
      request.raw,
      reply.raw,
      { error: 'access_denied', error_description: 'the end-user cancelled' },
      { mergeWithLastSubmission: false },
    );
    return { redirectTo };
  });

  return {
    app,
    provider,
    issuer,
    registry,
    mailer,
    store,
    db,
    routes: () => [...routes].sort(),
    async close() {
      await app.close();
      await db.close();
    },
  };
}
