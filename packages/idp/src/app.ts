// idp のアプリ（plan 9章、ADR 0018）。Fastify 5 に、oidc-provider を @fastify/middie で /oidc に載せる。
// oidc-provider の経路には、Fastify のボディ解析を通さない（middie は onRequest で処理し、応答を終える）。
//
// オリジンは2つ（DESIGN.md 原則8、ADR 0023）。Host で振り分け、ルートはどちらか一方のオリジンにだけ登録する。
// - 本来のオリジン（origin）：PWA、インタラクション、OIDC。
// - 承認用のオリジン（approvalOrigin）：承認待ちの画面と、承認と拒否の API だけ。OIDC は置かない。
//
// ルート（x-idp-routes で一覧を固定する）：
// - PWA：GET /、/assets/*、/api/*（登録、ログイン、step-up、メール、パスキー、受信箱、自分の情報、ログアウト）
// - インタラクション：GET /interaction/:uid と、その下の POST（ログイン、アカウント作成、接続の同意、中止）
// - OIDC：/oidc/*（discovery、jwks、認可、トークン）
// - 承認用のオリジン：GET /、/assets/*、/api/approvals/*（承認用のログイン、承認待ちの一覧、承認と拒否）
// 逆引き（sub・別名から本物の連絡先や属性を返す）ルートと、管理用のルートは作らない（不変条件2）。
//
// 守り：
// - Host は設定した2つだけ（DNS リバインディング）。POST は同じオリジンの Origin だけ（/oidc を除く）。
// - セッションのクッキーは、オリジンごとに名前を分け、それぞれのオリジンのルートでだけ読む。
// - JSON 以外の本文は受け付けない。本文は 16KB まで。
// - エラーの応答に、受け取った値もライブラリのメッセージも入れない。ログは warifu-core の許可リスト（ADR 0017）。
// - 登録済みかどうかで、応答の本文・ステータスを変えない（不変条件10。メールの登録）。

import { createServer, type Server } from 'node:http';
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
import {
  type ApprovalDecision,
  type ApprovalType,
  ApprovalTypes,
  approvalChallengeMessage,
  DEVICE_KINDS,
  type DeviceKind,
  decideApproval,
  findPendingApproval,
  type InboxItem,
  isItemId,
  listInbox,
  listPendingApprovals,
  markNoticeRead,
  NOTICE_TYPES,
  type PendingApproval,
  type RequestApprovalResult,
  requestApproval,
} from './inbox.ts';
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
import {
  APPROVAL_SESSION_COOKIE,
  APPROVAL_SESSION_POLICY,
  PWA_SESSION_COOKIE,
  type PwaSession,
  PwaSessions,
} from './sessions.ts';
import { loadSigningKey } from './signing-key.ts';
import { MacMemoryStore, StorageFullError } from './storage.ts';
import { deriveSub } from './subject.ts';
import { Ceremonies } from './webauthn.ts';

export interface IdpOptions {
  /** 例：http://localhost:4300。WebAuthn の expectedOrigin はポート込みでこれに固定する。 */
  readonly origin: string;
  /**
   * 承認用のオリジン（DESIGN.md 原則8）。例：http://localhost:4301。origin と違うもので、ホスト名は RP ID か、
   * その下の名前にする。承認用のログインと、承認と拒否の expectedOrigin は、これに固定する。
   */
  readonly approvalOrigin: string;
  /** 承認待ちの型（ADR 0023）。M6 では製品の型はまだない（M7 で足す）。 */
  readonly approvalTypes?: readonly ApprovalType[];
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
  readonly approvalOrigin: string;
  readonly registry: Registry;
  readonly mailer: Mailer;
  readonly store: MacMemoryStore;
  readonly db: Db;
  /** Fastify に登録したルート（メソッドとパス。承認用のオリジンのものは末尾に「 (approval)」）。x-idp-routes で一覧を固定する。 */
  routes(): readonly string[];
  /**
   * 承認待ちを作る（M7 の CIBA などが使う。HTTP のルートはない）。型は approvalTypes で渡したものだけ。
   */
  requestApproval(input: {
    readonly userId: WarifuUserId;
    readonly tenantId: TenantId;
    readonly type: string;
    readonly details: unknown;
    readonly ttlSeconds: number;
    /** 要求の端末（要求を出したブラウザの User-Agent を deviceKindOf にかけたもの）。 */
    readonly device: DeviceKind;
  }): Promise<RequestApprovalResult>;
  /**
   * 承認用のオリジンを、別のポートで待ち受ける（ローカルの開発とテスト。本番は前段で Host を振り分ける）。
   * 同じアプリの処理に渡し、Host で承認用のルートを選ぶ。
   */
  listenApproval(input: { readonly host: string; readonly port: number }): Promise<void>;
  close(): Promise<void>;
}

const JSON_LIMIT = 16 * 1024;
const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const DECISIONS: ReadonlySet<string> = new Set<ApprovalDecision>(['approved', 'denied']);
/**
 * 承認の画面に出す固定の警告文（DESIGN.md 3章）。文言は画面の側の定数だけを使い、ここでは ID だけを渡す。
 * M6 は端末での承認（A-2）だけ。窓口での承認（A-1）は、画面の必須要素とともに M7 で足す。
 */
const WARNING_OF = Object.freeze({ device: 'A-2' } as const);

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
  const approvalUrl = new URL(options.approvalOrigin);
  if (approvalUrl.origin !== options.approvalOrigin || approvalUrl.origin === originUrl.origin) {
    throw new Error('approvalOrigin は、origin と違う正規化したオリジンで渡す');
  }
  if (approvalUrl.protocol !== originUrl.protocol)
    throw new Error('2つのオリジンの scheme をそろえる');
  for (const url of [originUrl, approvalUrl]) {
    if (url.hostname !== options.rpId && !url.hostname.endsWith(`.${options.rpId}`)) {
      throw new Error('オリジンのホスト名は、RP ID か、その下の名前にする');
    }
  }
  const mainHost = originUrl.host;
  const approvalHost = approvalUrl.host;
  /** 本来のオリジンだけのルート。 */
  const onMain = { constraints: { host: mainHost } };
  /** 承認用のオリジンだけのルート。 */
  const onApproval = { constraints: { host: approvalHost } };
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
  const approvalSessions = new PwaSessions(store, nowMs, APPROVAL_SESSION_POLICY);
  const approvalTypes = new ApprovalTypes(options.approvalTypes ?? []);
  const inboxDeps = { ...repo, approvalTypes };
  const limiter = new RateLimiter(nowMs);
  const mailer = options.mailer ?? new MemoryOutbox();
  const ceremonies = new Ceremonies(store, {
    rpId: options.rpId,
    rpName: '割符',
    origin: options.origin,
    approvalOrigin: options.approvalOrigin,
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
    const host = (route.constraints as { host?: unknown } | undefined)?.host;
    const suffix = host === approvalHost ? ' (approval)' : '';
    for (const method of [route.method].flat()) routes.push(`${method} ${route.url}${suffix}`);
  });
  // JSON 以外の本文は受け付けない（Fastify は既定で text/plain も解析する）。
  app.removeContentTypeParser('text/plain');

  // DNS リバインディング対策：Host は設定した2つだけ。/oidc を含むすべての経路に先にかける。
  app.addHook('onRequest', async (request, reply) => {
    const host = request.headers.host;
    if (host !== mainHost && host !== approvalHost) {
      return reply
        .code(421)
        .header('content-type', 'application/json')
        .send({ error: 'misdirected' });
    }
    const isOidc = request.url === OIDC_MOUNT || request.url.startsWith(`${OIDC_MOUNT}/`);
    // 承認用のオリジンには OIDC を置かない（middie より先に止める）。
    if (host === approvalHost && isOidc) {
      return reply
        .code(404)
        .header('content-type', 'application/json')
        .send({ error: 'not_found' });
    }
    // 状態を変える要求は、同じオリジンからだけ（クッキーは SameSite も付ける）。/oidc は企業のサーバーからも来る。
    if (request.method !== 'GET' && request.method !== 'HEAD' && !isOidc) {
      const expected = host === approvalHost ? options.approvalOrigin : options.origin;
      if (request.headers.origin !== expected) {
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

  function setCookie(reply: FastifyReply, name: string, value: string): void {
    const attributes = [
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      ...(secureCookie ? ['Secure'] : []),
    ];
    reply.header('set-cookie', `${name}=${value}; ${attributes.join('; ')}`);
  }

  function clearCookie(reply: FastifyReply, name: string): void {
    const attributes = [
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=0',
      ...(secureCookie ? ['Secure'] : []),
    ];
    reply.header('set-cookie', `${name}=; ${attributes.join('; ')}`);
  }

  const setSessionCookie = (reply: FastifyReply, value: string) =>
    setCookie(reply, PWA_SESSION_COOKIE, value);
  const clearSessionCookie = (reply: FastifyReply) => clearCookie(reply, PWA_SESSION_COOKIE);

  /** PWA のセッション（本来のオリジンのルートだけが呼ぶ）。 */
  async function sessionOf(
    request: FastifyRequest,
  ): Promise<{ session: PwaSession; cookie: string } | undefined> {
    const cookie = cookieOf(request, PWA_SESSION_COOKIE);
    const session = await sessions.get(cookie);
    return session === undefined || cookie === undefined ? undefined : { session, cookie };
  }

  /** 承認用のオリジンのセッション（承認用のルートだけが呼ぶ）。 */
  async function approvalSessionOf(
    request: FastifyRequest,
  ): Promise<{ session: PwaSession; cookie: string } | undefined> {
    const cookie = cookieOf(request, APPROVAL_SESSION_COOKIE);
    const session = await approvalSessions.get(cookie);
    return session === undefined || cookie === undefined ? undefined : { session, cookie };
  }

  const findForLogin = (userId: WarifuUserId, credentialId: Uint8Array) =>
    findCredential(repo, userId, credentialId);
  const admitLogin = (ip: string) => (userId: WarifuUserId) =>
    limiter.take('loginByUser', userId) && limiter.take('loginByIp', ip);

  // ---- 画面と配信物 ----

  app.get('/', onMain, async (request, reply) =>
    sendHtml(request, reply, (nonce) =>
      renderPage({ nonce, page: 'home', approvalOrigin: options.approvalOrigin }),
    ),
  );
  app.get('/', onApproval, async (request, reply) =>
    sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'approval' })),
  );
  // 配信物は、どちらのオリジンにも同じものを置く（中身に資格情報や鍵はない）。
  for (const site of [onMain, onApproval]) {
    app.get('/assets/app.js', site, async (_request, reply) =>
      reply.type('text/javascript; charset=utf-8').send(assets.appJs),
    );
    app.get('/assets/app.css', site, async (_request, reply) =>
      reply.type('text/css; charset=utf-8').send(assets.appCss),
    );
    app.get('/assets/webauthn.js', site, async (_request, reply) =>
      reply.type('text/javascript; charset=utf-8').send(assets.webauthnJs),
    );
  }

  // ---- PWA：アカウントの作成とログイン ----

  app.post('/api/register/options', onMain, async (request, reply) => {
    if (
      !limiter.take('accountCreateByIp', request.ip) ||
      !limiter.take('ceremonyByIp', request.ip)
    ) {
      return reply.code(429).send({ error: 'rate_limited' });
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
    setSessionCookie(reply, await sessions.create(result.userId));
    return { ok: true };
  });

  app.post('/api/login/options', onMain, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'login', bind: '' });
  });

  app.post('/api/login/verify', onMain, async (request, reply) => {
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

  app.post('/api/logout', onMain, async (request, reply) => {
    await sessions.destroy(cookieOf(request, PWA_SESSION_COOKIE));
    clearSessionCookie(reply);
    return { ok: true };
  });

  // ---- PWA：ログインした後 ----

  app.get('/api/me', onMain, async (request, reply) => {
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

  app.post('/api/stepup/options', onMain, async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'stepup', bind: current.session.ref });
  });

  app.post('/api/stepup/verify', onMain, async (request, reply) => {
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
  app.post('/api/email/start', onMain, async (request, reply) => {
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

  app.post('/api/email/confirm', onMain, async (request, reply) => {
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    const result = await confirmEmailVerification(emailDeps, {
      userId: current.session.userId,
      code: bodyOf(request).code,
    });
    if (result === 'invalid') return reply.code(400).send(FAILED);
    return { ok: true };
  });

  app.post('/api/passkeys/options', onMain, async (request, reply) => {
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

  app.post('/api/passkeys/verify', onMain, async (request, reply) => {
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

  app.post('/api/passkeys/delete', onMain, async (request, reply) => {
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
    // パスキーを消したら、その利用者のセッション（PWA、承認用のオリジン、OIDC）をすべて消す（ADR 0018、ADR 0023）。
    sessions.revokeUser(current.session.userId);
    approvalSessions.revokeUser(current.session.userId);
    store.deleteWhere(
      'Session',
      (value) => isRecord(value) && value.accountId === current.session.userId,
    );
    clearSessionCookie(reply);
    return { ok: true, reloginRequired: true };
  });

  // ---- PWA：受信箱（ADR 0023） ----

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
    const expired = item.state === 'pending' && item.expiresAt.getTime() <= nowMs();
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
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send({ error: 'rate_limited' });
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
    const current = await sessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send({ error: 'rate_limited' });
    }
    const id = bodyOf(request).id;
    const ok = isItemId(id) && (await markNoticeRead(repo, current.session.userId, id));
    if (!ok) return reply.code(400).send(FAILED);
    return { ok: true };
  });

  // ---- 承認用のオリジン：ログイン、承認待ちの一覧、承認と拒否（ADR 0023） ----

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
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'approval_login', bind: '' });
  });

  app.post('/api/approvals/login/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'approval_login',
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
    setCookie(reply, APPROVAL_SESSION_COOKIE, await approvalSessions.create(result.userId));
    return { ok: true };
  });

  app.get('/api/approvals', onApproval, async (request, reply) => {
    const current = await approvalSessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send({ error: 'rate_limited' });
    }
    const pending = await listPendingApprovals(repo, current.session.userId);
    return { approvals: pending.map(approvalCardOf).filter((card) => card !== undefined) };
  });

  app.post('/api/approvals/decide/options', onApproval, async (request, reply) => {
    const current = await approvalSessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip) || !limiter.take('approvalByUser', userId)) {
      return reply.code(429).send({ error: 'rate_limited' });
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
    const current = await approvalSessionOf(request);
    if (current === undefined) return reply.code(401).send({ error: 'login_required' });
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    const result = await ceremonies.verifyApproval({
      ceremonyId: body.ceremonyId,
      response: body.response,
      bind: ref,
      expectedUserId: userId,
      find: findForLogin,
      admit: admitLogin(request.ip),
      recompute: async ({ itemId, decision, nonce }) => {
        const item = await findPendingApproval(repo, userId, itemId);
        if (item === undefined) return undefined;
        return toBase64Url(await approvalChallenge(item, userId, decision, ref, nonce));
      },
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await recordCredentialUse(
      repo,
      result.userId,
      result.credentialId,
      result.newSignCount,
      result.backedUp,
    );
    // 状態の変更は1つの文で行う。同じ要求に、承認と拒否の両方は通らない（ADR 0006、ADR 0023）。
    const decided = await decideApproval(inboxDeps, {
      userId,
      itemId: result.itemId,
      decision: result.decision,
    });
    if (decided === undefined) return reply.code(409).send({ error: 'already_decided' });
    // 企業へ結果を引き渡す後処理は、M6 では持たない（確実な引き渡しは M7 で決める。ADR 0023）。
    return { ok: true, decision: result.decision };
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

  app.get('/interaction/:uid', onMain, async (request, reply) => {
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

  app.post('/interaction/:uid/login/options', onMain, async (request, reply) => {
    const found = await detailsOf(request, reply);
    if (found === undefined) return reply.code(400).send(FAILED);
    if (!limiter.take('ceremonyByIp', request.ip))
      return reply.code(429).send({ error: 'rate_limited' });
    return ceremonies.authenticationOptions({ purpose: 'login', bind: `interaction:${found.uid}` });
  });

  app.post('/interaction/:uid/login/verify', onMain, async (request, reply) => {
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

  app.post('/interaction/:uid/register/options', onMain, async (request, reply) => {
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

  app.post('/interaction/:uid/register/verify', onMain, async (request, reply) => {
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

  app.post('/interaction/:uid/consent', onMain, async (request, reply) => {
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

  app.post('/interaction/:uid/abort', onMain, async (request, reply) => {
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

  let approvalServer: Server | undefined;

  return {
    app,
    provider,
    issuer,
    approvalOrigin: options.approvalOrigin,
    registry,
    mailer,
    store,
    db,
    routes: () => [...routes].sort(),
    requestApproval: (input) => requestApproval(inboxDeps, input),
    async listenApproval(input) {
      await app.ready();
      if (approvalServer !== undefined) throw new Error('承認用のオリジンは、すでに待ち受けている');
      // Fastify の処理（app.routing）に渡す。serverFactory は使わない（使うと、Fastify が localhost の
      // 2つ目以降のアドレス（::1 と 127.0.0.1 など）で待ち受けなくなる）。
      const server = createServer((req, res) => app.routing(req, res));
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(input.port, input.host, () => resolve());
      });
      approvalServer = server;
    },
    async close() {
      const server = approvalServer;
      if (server !== undefined) {
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        });
      }
      await app.close();
      await db.close();
    },
  };
}
