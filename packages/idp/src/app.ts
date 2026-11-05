// idp のアプリ（plan 9章、ADR 0018）。Fastify 5 に、oidc-provider を @fastify/middie で /oidc に載せる。
// oidc-provider の経路には、Fastify のボディ解析を通さない（middie は onRequest で処理し、応答を終える）。
//
// オリジンは2つ（DESIGN.md 原則8、ADR 0023）。Host で振り分け、ルートはどちらか一方のオリジンにだけ登録する。
// - 本来のオリジン（origin）：PWA、インタラクション、OIDC。
// - 承認用のオリジン（approvalOrigin）：承認待ちの画面と、承認と拒否の API だけ。OIDC は置かない。
//
// ルート（x-idp-routes で一覧を固定する）。群ごとに routes/ に置き、ここでは共通の守りと登録だけを行う：
// - 画面と配信物（routes/screens.ts）：GET /、/assets/*（どちらのオリジンにも）
// - PWA（routes/pwa.ts、routes/inbox.ts）：/api/*（登録、ログイン、step-up、メール、パスキー、受信箱、自分の情報、ログアウト）
// - インタラクション（routes/interaction.ts）：GET /interaction/:uid と、その下の POST（ログイン、アカウント作成、接続の同意、中止）
// - OIDC：/oidc/*（discovery、jwks、認可、トークン）
// - 承認用のオリジン（routes/approvals.ts）：/api/approvals/*（承認用のログイン、承認待ちの一覧、承認と拒否）
// - 窓口の操作別承認（routes/desk.ts。ADR 0026）：本来のオリジンの GET /interaction/:uid/desk/finish と
//   GET /op-approval/jwks、承認用のオリジンの GET /desk と /api/desk/*（承認、承認しない）と /api/desk-items/*
//   （窓口の作成の項目と取消）
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
import { randomBytesOf, type TenantId, type WarifuUserId } from '@pii-token-vault/warifu-core';
import { createDb, type Db, type DbConnection } from '@pii-token-vault/warifu-core/db';
import { createDeskClient, type DeskConnection } from '@pii-token-vault/warifu-core/desk/client';
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
import type { EmailFlowDeps } from './email.ts';
import { cookieOf, isRecord, LOGIN_REQUIRED } from './http.ts';
import {
  type ApprovalType,
  ApprovalTypes,
  type DeviceKind,
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
  SECURITY_HEADERS,
} from './pages.ts';
import { buildProvider, OIDC_MOUNT } from './provider.ts';
import { RateLimiter } from './rate-limit.ts';
import { parseRegistry, type Registry } from './registry.ts';
import { findCredential, type RepoDeps, recordCredentialUse } from './repo.ts';
import { registerApprovalRoutes } from './routes/approvals.ts';
import type { CurrentSession, RouteContext } from './routes/context.ts';
import { registerDeskRoutes } from './routes/desk.ts';
import { registerInboxRoutes } from './routes/inbox.ts';
import { registerInteractionRoutes } from './routes/interaction.ts';
import { registerPwaRoutes } from './routes/pwa.ts';
import { registerScreenRoutes } from './routes/screens.ts';
import {
  APPROVAL_SESSION_COOKIE,
  APPROVAL_SESSION_POLICY,
  PWA_SESSION_COOKIE,
  PwaSessions,
} from './sessions.ts';
import { loadSigningKey } from './signing-key.ts';
import { MacMemoryStore, StorageFullError } from './storage.ts';
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
  /** company-api の窓口の内部 API（ADR 0026）。なければ、窓口の作成の承認と取消を受け付けない（照会は受け付ける）。 */
  readonly desk?: DeskConnection;
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
    limiter,
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

  function cookieAttributes(extra: readonly string[]): string {
    return [
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      ...extra,
      ...(secureCookie ? ['Secure'] : []),
    ].join('; ');
  }

  /** セッションを読む。なければ 401 を送って undefined を返す。 */
  async function requireSessionIn(
    sessionStore: PwaSessions,
    cookieName: string,
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<CurrentSession | undefined> {
    const cookie = cookieOf(request, cookieName);
    const session = await sessionStore.get(cookie);
    if (session === undefined || cookie === undefined) {
      void reply.code(401).send(LOGIN_REQUIRED);
      return undefined;
    }
    return { session, cookie };
  }

  const ctx: RouteContext = {
    app,
    onMain,
    onApproval,
    origin: options.origin,
    approvalOrigin: options.approvalOrigin,
    issuer,
    registry,
    keys,
    repo,
    store,
    sessions,
    approvalSessions,
    approvalTypes,
    limiter,
    ceremonies,
    emailDeps,
    provider,
    desk: options.desk === undefined ? undefined : createDeskClient(options.desk),
    assets,
    nowMs,
    sendHtml,
    setCookie(reply, name, value) {
      reply.header('set-cookie', `${name}=${value}; ${cookieAttributes([])}`);
    },
    clearCookie(reply, name) {
      reply.header('set-cookie', `${name}=; ${cookieAttributes(['Max-Age=0'])}`);
    },
    requireSession: (request, reply) =>
      requireSessionIn(sessions, PWA_SESSION_COOKIE, request, reply),
    async requireFreshSession(request, reply) {
      const current = await requireSessionIn(sessions, PWA_SESSION_COOKIE, request, reply);
      if (current === undefined) return undefined;
      if (!sessions.isFresh(current.session)) {
        void reply.code(401).send({ error: 'reauth_required' });
        return undefined;
      }
      return current;
    },
    requireApprovalSession: (request, reply) =>
      requireSessionIn(approvalSessions, APPROVAL_SESSION_COOKIE, request, reply),
    findForLogin: (userId, credentialId) => findCredential(repo, userId, credentialId),
    admitLogin: (ip) => (userId) =>
      limiter.take('loginByUser', userId) && limiter.take('loginByIp', ip),
    recordUse: (result) =>
      recordCredentialUse(
        repo,
        result.userId,
        result.credentialId,
        result.newSignCount,
        result.backedUp,
      ),
  };

  registerScreenRoutes(ctx);
  registerPwaRoutes(ctx);
  registerInboxRoutes(ctx);
  registerApprovalRoutes(ctx);
  registerInteractionRoutes(ctx);
  registerDeskRoutes(ctx);

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
