// demo-rp（企業の参照実装。plan 10章 M9、ADR 0029 の O-109）。A社は架空のデモ証券、B社は予約サイト。
//
// - ログインは、割符の OIDC（パスキー）だけ（RP-04）。利用者の識別は (iss, sub) の組だけ（RP-01）。別名は鍵にも検索にも使わない。
// - 出金先の変更（A社）は、割符の高リスクの操作の承認だけを根拠にする（RP-09・RP-10。payout.ts）。
// - 窓口は、利用者が選んだ注文1件の照会だけを、割符の窓口の承認で許す（RP-20〜RP-27。desk-routes.ts）。
// - 旧会員の引き継ぎ（A社。初回紐付け）は、旧パスキーの確かめと、割符の初回紐付けの承認で行う（legacy-routes.ts）。
// - 割符へは、rp-kit の SDK と、transport.ts の通信の関数でつなぐ。ほかのファイルは、外へつながない。
// - 申請ID、移行専用ID、会員参照、トークンは、サーバーのメモリにだけ置き、ログ、URL、画面に出さない（不変条件4）。

import { readFileSync } from 'node:fs';
import {
  type CompanyApiClient,
  createCompanyApiClient,
  createWarifuClient,
  newRandomId,
  type PendingAuthorization,
  RpKitError,
  type Send,
  setRefusalOf,
  type VerifiedSet,
  type WarifuClient,
  type WarifuClientConfig,
  type WarifuLogin,
} from '@pii-token-vault/rp-kit';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { registerDeskRoutes } from './desk-routes.ts';
import { registerLegacyRoutes } from './legacy-routes.ts';
import { cspOf, esc, type PageInput, page, postButton } from './pages.ts';
import {
  completePayoutChange,
  createPayoutRequest,
  displayOf,
  findUsableRequest,
  inRecoveryHold,
} from './payout.ts';
import { type Account, accountKeyOf, type DemoState, emptyState, type Session } from './state.ts';
import { MemoryStore } from './store.ts';
import { createTransport } from './transport.ts';

type Jwk = WarifuClientConfig['privateKey'];

export interface DemoRpConfig {
  /** securities：A社のデモ証券。reservations：B社の予約サイト。 */
  readonly company: 'securities' | 'reservations';
  readonly displayName: string;
  /** この企業のサイトのオリジン（redirect_uri は `${origin}/callback`）。 */
  readonly origin: string;
  readonly idpOrigin: string;
  /**
   * 割符の承認用のオリジン（step-up の承認の画面）。フォームの送信の後のリダイレクトが、ここまで進むので、
   * CSP の form-action に入れる。demo-rp からは、ここにはつながない。
   */
  readonly idpApprovalOrigin?: string;
  readonly oidc: { readonly clientId: string; readonly kid: string; readonly privateKey: Jwk };
  /** company-api（SET の検証と、初回紐付け）。なければ、SET を受けず、旧会員の引き継ぎも出さない。 */
  readonly companyApi?: {
    readonly origin: string;
    readonly tenantId: string;
    readonly clientId: string;
    readonly kid: string;
    readonly privateKey: Jwk;
  };
  /** 旧会員の引き継ぎ（A社）。移行プロファイルの版は、割符の登録と同じ値。 */
  readonly initialLink?: { readonly profileVersion: number };
  /** 公式窓口（登録済みの窓口と担当者。RP-25）。 */
  readonly desk?: { readonly name: string; readonly staff: string };
  /** 窓口担当者の画面を開く合言葉（デモ。従業員の認証は、企業の既存の仕組みの代わり）。 */
  readonly staffKey?: string;
  /** デモ用の旧会員を、画面から用意できるようにする。 */
  readonly demoSeed?: boolean;
  /** 既定は transport.ts（設定のオリジンにだけつなぐ）。テストは、割符を立てた補助の関数を渡す。 */
  readonly send?: Send;
  readonly now?: () => Date;
  /** テスト用：ID トークンを確かめる時計だけを分ける（テストの idp は、ID トークンを実際の時計で出す）。 */
  readonly oidcNow?: () => Date;
}

export interface CallbackInput {
  readonly login: WarifuLogin;
  readonly pending: PendingAuthorization;
  readonly ref: string | null;
  readonly session: Session;
  readonly account: Account;
}

/** ルートの集まりが共有するもの。 */
export interface Ctx {
  readonly app: FastifyInstance;
  readonly config: DemoRpConfig;
  readonly store: MemoryStore<DemoState>;
  readonly warifu: WarifuClient;
  readonly company: CompanyApiClient | null;
  nowMs(): number;
  sessionOf(request: FastifyRequest, reply: FastifyReply): Promise<Session>;
  updateSession(sessionId: string, change: (session: Session) => void): Promise<void>;
  accountOf(session: Session): Promise<Account | undefined>;
  html(reply: FastifyReply, input: Omit<PageInput, 'company'>): FastifyReply;
  go(reply: FastifyReply, path: string, notice?: string): FastifyReply;
  /** 進行中の認可の要求をセッションに置いて、割符の画面へ移らせる。 */
  begin(
    reply: FastifyReply,
    session: Session,
    kind: string,
    ref: string | null,
    started: { readonly url: string; readonly pending: PendingAuthorization },
  ): Promise<FastifyReply>;
  /** 割符から戻ってきたときの処理（step-up の種類ごと）。戻り値は、移る先のパス。 */
  onCallback(kind: string, handler: (input: CallbackInput) => Promise<string>): void;
  onSet(handler: (set: VerifiedSet) => Promise<void>): void;
  bodyOf(request: FastifyRequest): Record<string, unknown>;
}

export interface DemoRp {
  readonly app: FastifyInstance;
  readonly store: MemoryStore<DemoState>;
  /** 登録したルート（「GET /path」の形。ルート一覧のテストで固定する）。 */
  readonly routes: readonly string[];
  /** 受け取って確かめた SET の記録（jti、発行の時刻、受け取った時刻、イベントの種類だけ。中身は残さない）。 */
  readonly setLog: readonly { jti: string; iat: number; receivedAt: number; events: string[] }[];
  listen(port: number): Promise<string>;
  close(): Promise<void>;
}

const ACCOUNT_RECOVERED = 'urn:warifu:secevent:account-recovered';

export async function createDemoRp(config: DemoRpConfig): Promise<DemoRp> {
  const nowMs = () => (config.now?.() ?? new Date()).getTime();
  const send =
    config.send ??
    createTransport([config.idpOrigin, ...(config.companyApi ? [config.companyApi.origin] : [])]);
  const warifu = await createWarifuClient({
    idpOrigin: config.idpOrigin,
    clientId: config.oidc.clientId,
    redirectUri: `${config.origin}/callback`,
    privateKey: config.oidc.privateKey,
    kid: config.oidc.kid,
    send,
    ...((config.oidcNow ?? config.now) === undefined
      ? {}
      : { now: (config.oidcNow ?? config.now) as () => Date }),
  });
  const company =
    config.companyApi === undefined
      ? null
      : await createCompanyApiClient({
          ...config.companyApi,
          send,
          ...(config.now ? { now: config.now } : {}),
        });
  const store = new MemoryStore<DemoState>(emptyState());
  const cookieName = `demo_rp_${config.company}_session`;
  const secure = config.origin.startsWith('https:');
  const callbacks = new Map<string, (input: CallbackInput) => Promise<string>>();
  const setHandlers: ((set: VerifiedSet) => Promise<void>)[] = [];
  const setLog: { jti: string; iat: number; receivedAt: number; events: string[] }[] = [];

  const app = Fastify({ logger: false, bodyLimit: 32 * 1024 });
  const routes: string[] = [];
  app.addHook('onRoute', (route) => {
    for (const method of [route.method].flat()) {
      if (method !== 'HEAD') routes.push(`${method} ${route.url}`);
    }
  });
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (_request, body, done) => done(null, Object.fromEntries(new URLSearchParams(String(body)))),
  );
  app.addContentTypeParser(
    'application/secevent+jwt',
    { parseAs: 'string' },
    (_request, body, done) => done(null, body),
  );
  // POST は、このサイトの画面からだけ受ける（Origin の一致）。SET の受け口は、署名で確かめる。
  app.addHook('onRequest', async (request, reply) => {
    if (request.method !== 'POST' || request.url === '/warifu/events') return;
    if (request.headers.origin !== config.origin)
      return reply.code(403).send({ error: 'forbidden' });
  });
  app.addHook('onSend', async (_request, reply) => {
    reply.header(
      'content-security-policy',
      cspOf([config.idpOrigin, ...(config.idpApprovalOrigin ? [config.idpApprovalOrigin] : [])]),
    );
    reply.header('x-content-type-options', 'nosniff');
    // no-referrer にすると、ブラウザは同じサイトのフォームの POST でも Origin を null にする（上の Origin の検査が通らない）。
    // same-origin なら、ほかのサイト（割符を含む）には Referer を送らない。
    reply.header('referrer-policy', 'same-origin');
    reply.header('cache-control', 'no-store');
  });

  function setCookie(reply: FastifyReply, sessionId: string): void {
    reply.header(
      'set-cookie',
      `${cookieName}=${sessionId}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`,
    );
  }

  function cookieOf(request: FastifyRequest): string | undefined {
    for (const part of String(request.headers.cookie ?? '').split(';')) {
      const index = part.indexOf('=');
      if (index > 0 && part.slice(0, index).trim() === cookieName)
        return part.slice(index + 1).trim();
    }
    return undefined;
  }

  async function newSession(reply: FastifyReply, accountKey: string | null): Promise<Session> {
    const session: Session = {
      sessionId: newRandomId(),
      accountKey,
      pending: null,
      legacy: null,
      challenge: null,
      staff: false,
      createdAt: nowMs(),
    };
    await store.transaction((state) => {
      state.sessions.set(session.sessionId, session);
    });
    setCookie(reply, session.sessionId);
    return session;
  }

  const ctx: Ctx = {
    app,
    config,
    store,
    warifu,
    company,
    nowMs,
    async sessionOf(request, reply) {
      const id = cookieOf(request);
      const found =
        id === undefined ? undefined : await store.read((state) => state.sessions.get(id));
      return found ?? newSession(reply, null);
    },
    async updateSession(sessionId, change) {
      await store.transaction((state) => {
        const session = state.sessions.get(sessionId);
        if (session !== undefined) change(session);
      });
    },
    async accountOf(session) {
      const key = session.accountKey;
      return key === null ? undefined : store.read((state) => state.accounts.get(key));
    },
    html(reply, input) {
      return reply
        .type('text/html; charset=utf-8')
        .send(page({ ...input, company: config.displayName }));
    },
    go(reply, path, notice) {
      return reply.redirect(notice === undefined ? path : `${path}?n=${notice}`, 303);
    },
    async begin(reply, session, kind, ref, started) {
      await ctx.updateSession(session.sessionId, (s) => {
        s.pending = { kind, value: started.pending, ref };
      });
      return reply.redirect(started.url, 303);
    },
    onCallback(kind, handler) {
      callbacks.set(kind, handler);
    },
    onSet(handler) {
      setHandlers.push(handler);
    },
    bodyOf(request) {
      const body = request.body;
      return typeof body === 'object' && body !== null && !Array.isArray(body)
        ? (body as Record<string, unknown>)
        : {};
    },
  };

  const noticeOf = (request: FastifyRequest) => {
    const n = (request.query as { n?: unknown }).n;
    return typeof n === 'string' ? n : undefined;
  };

  // ---- 配信物 ----

  const publicDir = new URL('../public/', import.meta.url);
  const css = readFileSync(new URL('demo.css', publicDir));
  const js = readFileSync(new URL('demo.js', publicDir));
  const webauthnJs = readFileSync(
    new URL('../dist/bundle/index.umd.min.js', import.meta.resolve('@simplewebauthn/browser')),
  );
  app.get('/assets/demo.css', async (_request, reply) =>
    reply.type('text/css; charset=utf-8').send(css),
  );
  app.get('/assets/demo.js', async (_request, reply) =>
    reply.type('text/javascript; charset=utf-8').send(js),
  );
  app.get('/assets/webauthn.js', async (_request, reply) =>
    reply.type('text/javascript; charset=utf-8').send(webauthnJs),
  );

  // ---- ログイン（割符の OIDC だけ） ----

  app.get('/', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    if (account === undefined) {
      return ctx.html(reply, {
        title: 'ログイン',
        notice: noticeOf(request),
        body: [
          '<p>このサイトには、割符のパスキーでログインします。メールアドレスやパスワードは使いません。</p>',
          postButton('/login', '割符でログイン'),
          config.initialLink === undefined ? '' : '<p><a href="/legacy">旧会員の引き継ぎ</a></p>',
          config.desk === undefined ? '' : '<p><a href="/staff">窓口担当者の画面（デモ）</a></p>',
        ].join('\n'),
      });
    }
    const orders = await store.read((state) =>
      [...state.orders.values()].filter((order) => order.accountKey === account.key),
    );
    const hold = inRecoveryHold(account.recoveredAt, nowMs());
    const destination = account.payoutDestination;
    return ctx.html(reply, {
      title: 'マイページ',
      notice: noticeOf(request),
      body: [
        hold
          ? '<p class="hold" id="recovery-hold">割符のアカウントを回復した後の8日間は、出金先の変更などの重要な手続きを受け付けません。</p>'
          : '',
        `<h2>${config.company === 'securities' ? '注文' : '予約'}</h2>`,
        `<ul id="orders">${orders.map((o) => `<li>${esc(o.label)}：${esc(o.status)}</li>`).join('')}</ul>`,
        ...(config.company === 'securities'
          ? [
              '<h2>出金先</h2>',
              destination === null
                ? '<p id="payout">出金先は、まだ登録していません。</p>'
                : `<p id="payout">金融機関コード ${esc(destination.bankCode)}、支店コード ${esc(destination.branchCode)}、口座番号の末尾 ${esc(destination.accountNumber.slice(-4))}</p>`,
              '<p><a href="/payout">出金先を変更する</a></p>',
            ]
          : []),
        config.desk === undefined ? '' : '<p><a href="/desk">窓口に連絡するとき</a></p>',
        config.initialLink === undefined
          ? ''
          : account.legacyMemberId === null
            ? '<p><a href="/legacy">旧会員の引き継ぎ</a></p>'
            : '<p id="legacy-linked">旧会員は、引き継ぎ済みです。</p>',
        postButton('/logout', 'ログアウト'),
      ].join('\n'),
    });
  });

  app.post('/login', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    return ctx.begin(reply, session, 'login', null, await warifu.authorize({ scope: 'openid' }));
  });

  app.post('/logout', async (request, reply) => {
    const id = cookieOf(request);
    if (id !== undefined) {
      await store.transaction((state) => {
        state.sessions.delete(id);
      });
    }
    await newSession(reply, null);
    return ctx.go(reply, '/', 'signed_out');
  });

  /** ID トークンの (iss, sub) で、アカウントを引くか作る（RP-01）。別名や email クレームは見ない。 */
  async function signIn(reply: FastifyReply, old: Session, login: WarifuLogin): Promise<void> {
    const key = accountKeyOf(login.iss, login.sub);
    const now = nowMs();
    await store.transaction((state) => {
      let account = state.accounts.get(key);
      if (account === undefined) {
        account = {
          key,
          iss: login.iss,
          sub: login.sub,
          createdAt: now,
          payoutDestination: null,
          recoveredAt: null,
          legacyMemberId: null,
        };
        state.accounts.set(key, account);
        const orderId = newRandomId(16);
        state.orders.set(orderId, {
          orderId,
          accountKey: key,
          label: config.company === 'securities' ? '投資信託の買付（デモ）' : '宿泊の予約（デモ）',
          status: '受付済み',
        });
      }
      // recovered_at は、制限を強める方向にだけ使う（RP-54）。
      if (login.recoveredAt !== null) {
        account.recoveredAt = Math.max(account.recoveredAt ?? 0, login.recoveredAt);
      }
      state.sessions.delete(old.sessionId);
    });
    // ログインのたびに、セッションの ID を作り直す（固定されたセッションを使わせない）。
    await newSession(reply, key);
  }

  app.get('/callback', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    // 進行中の要求は、一度だけ使う。取り出しと消去を、まとめて行う（同時に来た2つ目には渡さない）。
    // state の合わない戻り（古い要求の戻りや、よそから開かせた URL）では、進行中の要求を消さない。
    const returned = (request.query as { state?: unknown }).state;
    const pending = await store.transaction((state) => {
      const stored = state.sessions.get(session.sessionId);
      const taken = stored?.pending ?? null;
      if (stored === undefined || taken === null) return null;
      if ((taken.value as PendingAuthorization).state !== returned) return null;
      stored.pending = null;
      return taken;
    });
    if (pending === null) return ctx.go(reply, '/', 'failed');
    const value = pending.value as PendingAuthorization;
    let login: WarifuLogin;
    try {
      login = await warifu.finish(`${config.origin}${request.url}`, value);
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      return ctx.go(reply, '/', error.code === 'rejected' ? 'declined' : 'failed');
    }
    if (pending.kind === 'login') {
      await signIn(reply, session, login);
      return ctx.go(reply, '/', 'signed_in');
    }
    // step-up は、ログイン中の利用者と同じ (iss, sub) のものだけを受け取る。
    const account = await ctx.accountOf(session);
    const handler = callbacks.get(pending.kind);
    if (
      account === undefined ||
      handler === undefined ||
      accountKeyOf(login.iss, login.sub) !== account.key
    ) {
      return ctx.go(reply, '/', 'failed');
    }
    try {
      return reply.redirect(
        await handler({ login, pending: value, ref: pending.ref, session, account }),
        303,
      );
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      return ctx.go(reply, '/', 'failed');
    }
  });

  // ---- 出金先の変更（A社。RP-09・RP-10） ----

  if (config.company === 'securities') {
    app.get('/payout', async (request, reply) => {
      const session = await ctx.sessionOf(request, reply);
      if ((await ctx.accountOf(session)) === undefined) return ctx.go(reply, '/', 'login_required');
      return ctx.html(reply, {
        title: '出金先の変更',
        notice: noticeOf(request),
        body: [
          '<p>新しい出金先を入力すると、割符の画面で、金融機関、支店、口座番号の末尾4桁を確かめてから承認します。承認の後に内容を変えることはできません（変えるときは、もう一度、初めから入力します）。</p>',
          '<p>デモで使える金融機関コードは 9991（支店 001・101・201）と 9992（支店 001・301）です。</p>',
          '<form method="post" action="/payout/request">',
          '<label>金融機関コード（4桁）<input name="bankCode" inputmode="numeric" pattern="[0-9]{4}" required></label>',
          '<label>支店コード（3桁）<input name="branchCode" inputmode="numeric" pattern="[0-9]{3}" required></label>',
          '<label>口座番号（7桁）<input name="accountNumber" inputmode="numeric" pattern="[0-9]{7}" required autocomplete="off"></label>',
          '<button type="submit">割符で確認して変更する</button>',
          '</form>',
          '<p><a href="/">戻る</a></p>',
        ].join('\n'),
      });
    });

    app.post('/payout/request', async (request, reply) => {
      const session = await ctx.sessionOf(request, reply);
      const account = await ctx.accountOf(session);
      if (account === undefined) return ctx.go(reply, '/', 'login_required');
      // 責務1・2：ここで内容の全体を固定する。前の申請は使えなくなる。
      const created = await createPayoutRequest(store, {
        accountKey: account.key,
        destination: ctx.bodyOf(request),
        nowMs: nowMs(),
      });
      if (!created.ok) {
        return ctx.go(
          reply,
          '/payout',
          created.reason === 'recovery_hold' ? 'payout_hold' : 'payout_invalid',
        );
      }
      try {
        const started = await warifu.pushOperation({
          action: 'payout_destination.change',
          requestId: created.request.requestId,
          sub: account.sub,
          content: displayOf(created.request.destination),
        });
        return await ctx.begin(reply, session, 'payout', created.request.requestId, started);
      } catch (error) {
        if (!(error instanceof RpKitError)) throw error;
        // 割符の対応表にない金融機関など。
        return ctx.go(reply, '/payout', error.code === 'rejected' ? 'payout_invalid' : 'failed');
      }
    });

    ctx.onCallback('payout', async ({ login, pending, ref, account }) => {
      if (ref === null) return '/?n=failed';
      const found = await findUsableRequest(store, {
        requestId: ref,
        accountKey: account.key,
        nowMs: nowMs(),
      });
      if (!found.ok) return '/payout?n=payout_stale';
      // 割符の承認を、この申請ID と、固定した内容の表示の項目で確かめる（RP-10）。
      await warifu.verifyOperationApproval(login, pending, {
        requestId: found.request.requestId,
        content: displayOf(found.request.destination),
      });
      // 責務3：変更と、申請を使い済みにする更新を、まとめて確定する。変更先は、固定した内容だけから取る。
      const done = await completePayoutChange(store, {
        requestId: found.request.requestId,
        accountKey: account.key,
        nowMs: nowMs(),
      });
      if (done.ok) return '/?n=payout_changed';
      return done.reason === 'recovery_hold' ? '/payout?n=payout_hold' : '/payout?n=payout_stale';
    });
  }

  // ---- 割符からの知らせ（SET。RP-50・RP-52） ----

  ctx.onSet(async (set) => {
    const recovered = set.events[ACCOUNT_RECOVERED];
    if (recovered === undefined || set.subId === null) return;
    const day = recovered.recovered_at;
    if (typeof day !== 'number') return;
    const key = accountKeyOf(warifu.issuer, set.subId);
    await store.transaction((state) => {
      const account = state.accounts.get(key);
      if (account !== undefined) account.recoveredAt = Math.max(account.recoveredAt ?? 0, day);
    });
  });

  app.post('/warifu/events', async (request, reply) => {
    if (company === null) return reply.code(404).send({ err: 'invalid_request' });
    let set: VerifiedSet;
    try {
      set = await company.verifySet(String(request.body));
    } catch (error) {
      // SET を確かめて通らなければ、RFC 8935 の失敗の形に、割符が決めた理由（set_too_old、iat_in_future）を添える。
      // 割符は、古いと言われた SET を新しい jti と iat で送り直す。割符の公開鍵を取れないなど、確かめられなかったときは
      // 503 にして、割符に送り直させる（spec 02 の7章）。連絡先での再確認には逃がさない（RP-52）。
      const refusal = setRefusalOf(error);
      return refusal.body === null
        ? reply.code(refusal.status).send()
        : reply.code(refusal.status).send(refusal.body);
    }
    const seen = await store.read((state) => state.seenSetJtis.has(set.jti));
    if (!seen) {
      // 処理は、何度呼んでも同じ結果になる形にしてある。処理が済んでから、受け取ったことを記録する。
      for (const handler of setHandlers) await handler(set);
      await store.transaction((state) => {
        state.seenSetJtis.add(set.jti);
      });
      setLog.push({
        jti: set.jti,
        iat: set.iat,
        receivedAt: nowMs(),
        events: Object.keys(set.events),
      });
    }
    return reply.code(202).send();
  });

  if (config.desk !== undefined) registerDeskRoutes(ctx);
  if (config.company === 'securities' && config.initialLink !== undefined && company !== null) {
    registerLegacyRoutes(ctx, company, config.initialLink);
  }

  return {
    app,
    store,
    routes,
    setLog,
    async listen(port) {
      await app.listen({ port, host: 'localhost' });
      return config.origin;
    },
    async close() {
      await app.close();
    },
  };
}
