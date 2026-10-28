// company-api のアプリ（plan 3-1・3-2、RP-73、CAP-30〜34、ADR 0022）。Fastify 5。
//
// ルート（x-company-api-routes で一覧を固定する）：
// - POST /token：private_key_jwt の client_credentials で、テナントの JWT を出す。
// - POST /v1/aliases/rotate：sub の利用者の別名を次の世代にする（テナントの JWT が要る）。
// - POST /v1/events/verification：検証の SET を、登録した受け口に送らせる（テナントの JWT が要る）。
// - GET /jwks：SET の検証に使う公開鍵（ES256）。
// 逆引き（sub・別名から本物の連絡先や属性を返す）ルート、参加の状態を書き換えるルート、管理用のルートは作らない
// （不変条件2、ADR 0010、CAP-32）。
//
// 守り：
// - Host は issuer の1つだけ。本文は JSON（/v1/*）とフォーム（/token）だけで、8KB まで。
// - エラーの応答は固定の本文だけ（受け取った値もライブラリのメッセージも入れない）。ログは warifu-core の許可リスト。
// - DB は withTenant だけ。テナントはテナントの JWT から決め、要求の本文からは取らない（テスト6）。

import { createDb, type Db, type DbConnection } from '@pii-token-vault/warifu-core/db';
import {
  type CompanyApiKeyClient,
  createCompanyApiKeyClient,
} from '@pii-token-vault/warifu-core/keys/company-api';
import type { KeysvcConnection } from '@pii-token-vault/warifu-core/keys/protocol';
import { createLogger, type LogLevel } from '@pii-token-vault/warifu-core/log';
import {
  createSenderWebhookClient,
  type SenderConnection,
} from '@pii-token-vault/warifu-core/sender/client';
import fastify, { type FastifyBaseLogger, type FastifyInstance, type FastifyReply } from 'fastify';
import { rotateAlias, SUB_PATTERN } from './aliases.ts';
import { type CompanyApiConfig, parseCompanyApiConfig } from './config.ts';
import { PublicKeyCache } from './jwt.ts';
import { deliverDue, enqueueEvent, STATE_PATTERN } from './outbox.ts';
import { type CompanyApiLimitName, companyApiLimiter } from './rate-limit.ts';
import { ACCESS_TOKEN_TTL_SECONDS, type Caller, TOKEN_SCOPE, TokenService } from './tokens.ts';

export interface CompanyApiOptions {
  /** 登録簿の設定（config.ts で検査する）。 */
  readonly config: { readonly issuer: unknown; readonly tenants: unknown };
  readonly keysvc: KeysvcConnection;
  readonly db: DbConnection;
  /** sender の内部 API。なければ SET を送らない（送信待ちに残る）。 */
  readonly sender?: SenderConnection;
  readonly now?: () => Date;
  readonly logLevel?: LogLevel;
  readonly logWrite?: (line: string) => void;
  /** 送信待ちを見る間隔。0 なら自分では回さない（テストが deliverDue を呼ぶ）。既定は5秒。 */
  readonly deliveryIntervalMs?: number;
}

export interface CompanyApi {
  readonly app: FastifyInstance;
  readonly config: CompanyApiConfig;
  readonly db: Db;
  /** Fastify に登録したルート（メソッドとパス）。x-company-api-routes で一覧を固定する。 */
  routes(): readonly string[];
  deliverDue(): Promise<{ delivered: number; retry: number; dropped: number }>;
  close(): Promise<void>;
}

const BODY_LIMIT = 8 * 1024;

const ERROR = Object.freeze({
  invalid_token: { error: 'invalid_token' },
  invalid_request: { error: 'invalid_request' },
  not_found: { error: 'not_found' },
  rate_limited: { error: 'rate_limited' },
  webhook_not_registered: { error: 'webhook_not_registered' },
  internal_error: { error: 'internal_error' },
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: unknown, required: readonly string[], optional: readonly string[] = []) {
  if (!isRecord(value)) return undefined;
  const keys = Object.keys(value);
  if (!required.every((key) => keys.includes(key))) return undefined;
  if (!keys.every((key) => required.includes(key) || optional.includes(key))) return undefined;
  return value;
}

export async function createCompanyApi(options: CompanyApiOptions): Promise<CompanyApi> {
  const config = parseCompanyApiConfig(options.config);
  const issuerUrl = new URL(config.issuer);
  const now = options.now ?? (() => new Date());
  const nowMs = () => now().getTime();
  const keys: CompanyApiKeyClient = createCompanyApiKeyClient(options.keysvc);
  const db = createDb({ service: 'company-api', connection: options.db });
  const tokens = new TokenService({ config, keys, now });
  const cache = new PublicKeyCache(keys, nowMs);
  const limiter = companyApiLimiter(nowMs);
  const log = createLogger({
    component: 'company-api',
    ...(options.logLevel === undefined ? {} : { level: options.logLevel }),
    ...(options.logWrite === undefined ? {} : { write: options.logWrite }),
  });
  const sender =
    options.sender === undefined ? undefined : createSenderWebhookClient(options.sender);
  const outboxDeps = { config, db, keys, cache, sender, log, now };

  const app = fastify({
    loggerInstance: log as unknown as FastifyBaseLogger,
    bodyLimit: BODY_LIMIT,
    return503OnClosing: true,
    trustProxy: false,
  });
  const routes: string[] = [];
  app.addHook('onRoute', (route) => {
    for (const method of [route.method].flat()) routes.push(`${method} ${route.url}`);
  });
  app.removeContentTypeParser('text/plain');
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string', bodyLimit: BODY_LIMIT },
    (_request, body, done) => done(null, new URLSearchParams(String(body))),
  );
  app.addHook('onRequest', async (request, reply) => {
    if (request.headers.host !== issuerUrl.host) {
      return reply.code(421).send({ error: 'misdirected' });
    }
    reply.header('cache-control', 'no-store');
  });
  app.setErrorHandler((error, _request, reply) => {
    const status = isRecord(error) && typeof error.statusCode === 'number' ? error.statusCode : 500;
    if (status >= 400 && status < 500) return reply.code(400).send(ERROR.invalid_request);
    log.error({ event: 'company_api.request_failed', err: error });
    return reply.code(500).send(ERROR.internal_error);
  });
  app.setNotFoundHandler((_request, reply) => reply.code(404).send(ERROR.not_found));

  const limited = (reply: FastifyReply, name: CompanyApiLimitName, key: string): boolean => {
    if (limiter.take(name, key)) return false;
    void reply.code(429).header('retry-after', '60').send(ERROR.rate_limited);
    return true;
  };

  /** テナントの JWT を確かめる。だめなら 401 を返して undefined。 */
  const callerOf = async (
    authorization: string | undefined,
    reply: FastifyReply,
  ): Promise<Caller | undefined> => {
    const caller = await tokens.authenticate(authorization);
    if (caller === undefined) {
      void reply
        .code(401)
        .header('www-authenticate', 'Bearer error="invalid_token"')
        .send(ERROR.invalid_token);
      return undefined;
    }
    if (limited(reply, 'apiByTenant', caller.tenant.tenantId)) return undefined;
    return caller;
  };

  app.post('/token', async (request, reply) => {
    if (limited(reply, 'tokenByIp', request.ip)) return reply;
    if (!(request.body instanceof URLSearchParams)) {
      return reply.code(400).send(ERROR.invalid_request);
    }
    const result = await tokens.issue(request.body);
    if (!result.ok) {
      log.info({ event: 'company_api.token_refused', reason: result.error });
      return reply
        .code(result.error === 'invalid_client' ? 401 : 400)
        .send({ error: result.error });
    }
    if (limited(reply, 'tokenByClient', result.token.clientId)) return reply;
    return {
      access_token: result.token.accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: TOKEN_SCOPE,
    };
  });

  app.post('/v1/aliases/rotate', async (request, reply) => {
    const caller = await callerOf(request.headers.authorization, reply);
    if (caller === undefined) return reply;
    const body = exactKeys(request.body, ['sub']);
    if (body === undefined || typeof body.sub !== 'string' || !SUB_PATTERN.test(body.sub)) {
      return reply.code(400).send(ERROR.invalid_request);
    }
    if (limited(reply, 'rotateByTenant', caller.tenant.tenantId)) return reply;
    const alias = await rotateAlias({ db, keys, now }, caller.tenant, body.sub);
    if (alias === undefined) return reply.code(404).send(ERROR.not_found);
    log.info({ event: 'company_api.alias_rotated' });
    return { alias };
  });

  app.post('/v1/events/verification', async (request, reply) => {
    const caller = await callerOf(request.headers.authorization, reply);
    if (caller === undefined) return reply;
    const body = exactKeys(request.body ?? {}, [], ['state']);
    const state = body?.state;
    if (
      body === undefined ||
      (state !== undefined && (typeof state !== 'string' || !STATE_PATTERN.test(state)))
    ) {
      return reply.code(400).send(ERROR.invalid_request);
    }
    if (caller.tenant.webhookUrl === undefined) {
      return reply.code(409).send(ERROR.webhook_not_registered);
    }
    if (limited(reply, 'verificationByTenant', caller.tenant.tenantId)) return reply;
    await enqueueEvent({ db, now }, caller.tenant, {
      type: 'verification',
      state: typeof state === 'string' ? state : null,
    });
    return reply.code(202).send({ ok: true });
  });

  app.get('/jwks', async () => ({ keys: await cache.get('set') }));

  let timer: ReturnType<typeof setInterval> | undefined;
  let running: Promise<unknown> | undefined;
  const runDelivery = () => {
    running ??= deliverDue(outboxDeps)
      .catch((err: unknown) => log.error({ event: 'company_api.delivery_failed', err }))
      .finally(() => {
        running = undefined;
      });
    return running;
  };
  const interval = options.deliveryIntervalMs ?? 5000;
  if (interval > 0) {
    timer = setInterval(runDelivery, interval);
    timer.unref();
  }

  return {
    app,
    config,
    db,
    routes: () => [...routes].sort(),
    deliverDue: () => deliverDue(outboxDeps),
    async close() {
      if (timer !== undefined) clearInterval(timer);
      await running;
      await app.close();
      await db.close();
    },
  };
}
