// demo-rp を、テストの中の割符（idp、company-api、sender）につなぐ補助（ADR 0029）。
// - demo-rp はソケットを開かず、Fastify の inject で呼ぶ（オリジンは、どこにもつながない名前）。
// - 割符への通信は、idp へは fetch（リダイレクトに従わない）、company-api へは inject。demo-rp 自身の transport.ts は、
//   packages/demo-rp/test/transport.test.ts で確かめる。
// - 利用者の操作は、DemoBrowser（demo-rp の画面）と、idp の Browser（割符の画面）で行う。

import { createDemoRp, type DemoRp, type DemoRpConfig } from '../../packages/demo-rp/src/app.ts';
import type { HttpRequest, Send } from '../../packages/rp-kit/src/transport.ts';
import { ISSUER as COMPANY_ORIGIN } from './company-api.ts';
import type { DeskWorld } from './desk.ts';
import { actOnInteraction, type Browser, type TestClient } from './idp.ts';
import { companySend, idpSend, jwkOf } from './rp-kit.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';

export const DEMO_ORIGIN_A = 'http://localhost:65101';
export const DEMO_ORIGIN_B = 'http://localhost:65102';
export const STAFF_KEY = 'demo-staff-key';

export interface InjectResult {
  readonly status: number;
  readonly location: string | undefined;
  readonly text: string;
  readonly json: Record<string, unknown>;
}

/** demo-rp の画面を使うブラウザ役（クッキーを持ち、フォームを送る）。 */
export class DemoBrowser {
  readonly demo: DemoRp;
  readonly origin: string;
  readonly cookies = new Map<string, string>();
  /** 旧パスキーを持つ認証器（demo-rp のオリジン）。 */
  readonly legacy: SoftAuthenticator;

  constructor(demo: DemoRp, origin: string, legacy?: SoftAuthenticator) {
    this.demo = demo;
    this.origin = origin;
    this.legacy = legacy ?? new SoftAuthenticator(origin);
  }

  async request(
    method: 'GET' | 'POST',
    path: string,
    options: { form?: Record<string, string>; json?: unknown; origin?: string | null } = {},
  ): Promise<InjectResult> {
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const origin = options.origin === undefined ? this.origin : options.origin;
    const res = await this.demo.app.inject({
      method,
      url: path,
      headers: {
        ...(cookie === '' ? {} : { cookie }),
        ...(method === 'POST' && origin !== null ? { origin } : {}),
        ...(method === 'POST'
          ? {
              'content-type':
                options.json === undefined
                  ? 'application/x-www-form-urlencoded'
                  : 'application/json',
            }
          : {}),
      },
      ...(method === 'POST'
        ? {
            payload:
              options.json === undefined
                ? new URLSearchParams(options.form ?? {}).toString()
                : JSON.stringify(options.json),
          }
        : {}),
    });
    const setCookie = res.headers['set-cookie'];
    for (const line of Array.isArray(setCookie)
      ? setCookie
      : setCookie
        ? [String(setCookie)]
        : []) {
      const pair = line.split(';')[0] ?? '';
      const index = pair.indexOf('=');
      if (index > 0) this.cookies.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
    }
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(res.body) as Record<string, unknown>;
    } catch {
      json = {};
    }
    const location = res.headers.location;
    return {
      status: res.statusCode,
      location: typeof location === 'string' ? location : undefined,
      text: res.body,
      json,
    };
  }

  get(path: string) {
    return this.request('GET', path);
  }

  post(path: string, form: Record<string, string> = {}) {
    return this.request('POST', path, { form });
  }

  /** 割符から戻ってきた URL（redirect_uri）を開き、demo-rp の中のリダイレクトを1回たどる。 */
  async openCallback(url: string): Promise<{ callback: InjectResult; page: InjectResult }> {
    const target = new URL(url);
    if (target.origin !== this.origin) throw new Error('demo-rp の戻り先ではない');
    const callback = await this.get(`${target.pathname}${target.search}`);
    if (callback.location === undefined) return { callback, page: callback };
    return { callback, page: await this.get(callback.location) };
  }

  /** 旧パスキーで確かめる（/legacy の画面のボタンと同じ）。 */
  async verifyLegacy(): Promise<InjectResult> {
    const options = await this.request('POST', '/legacy/options', { json: {} });
    const response = this.legacy.get(options.json as never, undefined, { origin: this.origin });
    return this.request('POST', '/legacy/verify', { json: { response } });
  }

  /** デモ用の旧会員と旧パスキーを用意する。 */
  async seedLegacy(): Promise<InjectResult> {
    const options = await this.request('POST', '/legacy/demo/options', { json: {} });
    const response = this.legacy.create(options.json as never);
    return this.request('POST', '/legacy/demo/verify', { json: { response } });
  }
}

/** idp と company-api へ、オリジンで振り分ける通信の関数。 */
export function worldSend(world: DeskWorld): Send {
  const toCompany = companySend(world.company);
  return (request: HttpRequest) =>
    new URL(request.url).origin === COMPANY_ORIGIN ? toCompany(request) : idpSend(request);
}

export async function startDemoRp(
  world: DeskWorld,
  input: {
    readonly company: DemoRpConfig['company'];
    readonly origin: string;
    readonly client: TestClient;
    readonly tenantIndex: number;
    readonly now: () => Date;
    readonly initialLink?: boolean;
    /** demo-rp から割符への通信に、障害を差し込む（テスト用。既定は、そのまま割符に渡す）。 */
    readonly wrapSend?: (send: Send) => Send;
  },
): Promise<DemoRp> {
  const tenant = world.company.tenants[input.tenantIndex];
  if (tenant === undefined) throw new Error('準備に失敗した');
  return createDemoRp({
    company: input.company,
    displayName: input.company === 'securities' ? 'デモ証券' : 'デモ予約',
    origin: input.origin,
    idpOrigin: world.t.origin,
    oidc: {
      clientId: input.client.clientId,
      kid: input.client.kid,
      privateKey: await jwkOf(input.client.privateKey),
    },
    companyApi: {
      origin: COMPANY_ORIGIN,
      tenantId: tenant.tenantId,
      clientId: tenant.client.clientId,
      kid: tenant.client.kid,
      privateKey: await jwkOf(tenant.client.privateKey),
    },
    ...(input.initialLink === true ? { initialLink: { profileVersion: 3 } } : {}),
    desk: { name: 'デモ証券 お客さま窓口', staff: '担当 A' },
    staffKey: STAFF_KEY,
    demoSeed: true,
    send: input.wrapSend === undefined ? worldSend(world) : input.wrapSend(worldSend(world)),
    // 結果の報告の送信待ちは、テストが flushReports で送る（自分では回さない）。
    reportIntervalMs: 0,
    now: input.now,
    // テストの idp は、ID トークンを実際の時計で出す。
    oidcNow: () => new Date(),
  });
}

export interface DemoUser {
  /** demo-rp の画面。 */
  readonly site: DemoBrowser;
  /** 割符の本来のオリジンと、承認用のオリジン（同じ認証器）。 */
  readonly browser: Browser;
  readonly approval: Browser;
}

/** demo-rp が返した割符の URL から、ログイン（または登録と同意）を済ませて、戻りの URL を返す。 */
export async function passWarifuLogin(
  browser: Browser,
  url: string,
  mode: 'register' | 'login',
): Promise<string> {
  let current = await browser.follow(url);
  for (let step = 0; step < 4 && current.external === undefined; step += 1) {
    if (!current.path.startsWith('/interaction/')) throw new Error('インタラクションに来ていない');
    const action = current.last.text.includes('data-prompt="consent"') ? 'connect' : mode;
    const acted = await actOnInteraction(browser, current.path, action);
    if (acted.followed === undefined)
      throw new Error(`インタラクションが失敗した（${acted.result.status}）`);
    current = acted.followed;
  }
  if (current.external === undefined) throw new Error('企業に戻ってこない');
  return current.external.href;
}

/** demo-rp に、割符でログインする。 */
export async function demoSignIn(
  user: DemoUser,
  mode: 'register' | 'login',
): Promise<InjectResult> {
  const started = await user.site.post('/login');
  if (started.location === undefined) throw new Error('割符の画面に移らない');
  const back = await passWarifuLogin(user.browser, started.location, mode);
  return (await user.site.openCallback(back)).page;
}

/**
 * 割符の承認用のオリジンの画面（/desk、/operation、/initial-link）で、パスキーで承認して、企業への戻りの URL を返す。
 * 承認しなければ undefined と、承認の応答を返す。
 */
export async function approveAtWarifu(
  user: DemoUser,
  url: string,
  page: '/desk' | '/operation' | '/initial-link',
): Promise<{ back: string | undefined; status: number; card: Record<string, unknown> }> {
  const arrived = await user.browser.follow(url);
  if (arrived.external?.pathname !== page) throw new Error('承認用のオリジンに引き継がれない');
  const uid = arrived.external.hash.slice(1);
  const api = `/api${page}`;
  const card = (await user.approval.post(`${api}/view`, { uid })).json;
  const started = await user.approval.post(`${api}/approve/options`, {
    uid,
    ...(page === '/desk' ? { call: 'self' } : {}),
  });
  if (started.status !== 200) return { back: undefined, status: started.status, card };
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approved = await user.approval.post(`${api}/approve/verify`, {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  if (approved.status !== 200) return { back: undefined, status: approved.status, card };
  const finished = await user.browser.follow(String(approved.json.redirectTo));
  return { back: finished.external?.href, status: approved.status, card };
}

/** sender が企業の受け口に送った SET を、demo-rp の受け口に渡す（テストでは、受け口は sender の補助の中にある）。 */
export async function forwardSets(
  world: DeskWorld,
  demos: Readonly<Record<string, DemoRp>>,
  from: number,
): Promise<number[]> {
  const statuses: number[] = [];
  for (const request of world.sender.requests.slice(from)) {
    const demo = demos[request.url];
    if (demo === undefined) continue;
    const res = await demo.app.inject({
      method: 'POST',
      url: '/warifu/events',
      headers: { 'content-type': 'application/secevent+jwt' },
      payload: request.body,
    });
    statuses.push(res.statusCode);
  }
  return statuses;
}
