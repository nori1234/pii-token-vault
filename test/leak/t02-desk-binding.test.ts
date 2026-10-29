// テスト2：申請の結び付き（plan 11章 テスト2、ADR 0025、ADR 0026）。
// 申請（PAR の authorization_details）は、企業のクライアントと、申請の主体と、内容と、期限に結び付く。
// request_uri を知っているだけでは承認できず、別の企業・期限切れ・再利用・形の違うものは断る。通常のログインへ
// 縮退しない。操作ごとの承認は、ID トークンと取り違えない。テスト4（窓口の承認の sub）もここで確かめる。

import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ALL_DESK_ACTIONS,
  approveDesk,
  arriveAtDesk,
  connectedUser,
  type DeskWorld,
  deskDetail,
  deskFlow,
  pushRequest,
  startDeskWorld,
  verifyOpApproval,
} from '../setup/desk.ts';
import { Browser, codeFlow } from '../setup/idp.ts';

let world: DeskWorld;
let clock = Date.now();
/** テナント1とテナント2に接続した利用者（アカウントの作成には IP ごとの上限があるので、使い回す）。 */
let user: Awaited<ReturnType<typeof connectedUser>>;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [
      { tenant: 0 },
      { tenant: 0 },
      { tenant: 1 },
      { tenant: 0, deskActions: ['desk.case.status.read'] },
      { tenant: 0, deskActions: [] },
    ],
    now: () => new Date(clock),
  });
  user = await connectedUser(world, client(0));
  await codeFlow(world.t, user.browser, client(2), { mode: 'session' });
});

afterAll(async () => {
  await world?.stop();
});

function client(index: number) {
  const found = world.t.clients[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

describe('漏えい：申請の結び付き（plan 11章 テスト2）', () => {
  it('PAR の受け口は、企業のクライアント認証（private_key_jwt）がなければ受け付けない', async () => {
    // 攻撃者が持っている情報：企業の client_id（公開の値）と、利用者の sub
    // 試す経路：client assertion なしで PAR を送る。別の企業の鍵で作った assertion で送る
    // 期待する結果：どちらも 401 invalid_client。request_uri は出ない
    // plan 11章：テスト2（ADR 0025 の O-52）
    const bare = await pushRequest(
      world.t,
      client(0),
      [deskDetail(user.sub)],
      {},
      { assertion: false },
    );
    expect([bare.status, bare.body.error]).toEqual([401, 'invalid_client']);
    const other = client(2);
    const forged = await pushRequest(
      world.t,
      { ...client(0), privateKey: other.privateKey, kid: other.kid },
      [deskDetail(user.sub)],
    );
    expect([forged.status, forged.body.error]).toEqual([401, 'invalid_client']);
  });

  it('request_uri は、発行した企業の client_id でしか使えず、期限の後と、応答の後には使えない', async () => {
    // 攻撃者が持っている情報：漏れた request_uri（履歴、Referer。ADR 0025 の残るリスク）
    // 試す経路：A社の request_uri を B社の client_id で開く。60秒を過ぎてから開く。承認して企業に戻った後に、
    //           同じ request_uri をもう一度開く
    // 期待する結果：どれも窓口の承認の画面に進まない（引き継ぎを作らない）
    // plan 11章：テスト2（ADR 0025 の O-53）
    const par = await pushRequest(world.t, client(0), [deskDetail(user.sub)]);
    expect(par.body.expires_in).toBe(60);
    const crossed = await arriveAtDesk(
      new Browser(world.t.origin),
      client(2),
      String(par.requestUri),
    );
    expect(crossed.uid).toBeUndefined();

    const expiring = await pushRequest(world.t, client(0), [deskDetail(user.sub)]);
    clock += 61_000;
    const late = await arriveAtDesk(
      new Browser(world.t.origin),
      client(0),
      String(expiring.requestUri),
    );
    expect(late.uid).toBeUndefined();

    const used = await pushRequest(world.t, client(0), [deskDetail(user.sub)]);
    const arrived = await arriveAtDesk(user.browser, client(0), String(used.requestUri));
    const approved = await approveDesk(user.approval, String(arrived.uid));
    expect(approved.status).toBe(200);
    const finished = await user.browser.follow(String(approved.json.redirectTo));
    expect(finished.external?.searchParams.get('code')).not.toBeNull();
    const again = await arriveAtDesk(
      new Browser(world.t.origin),
      client(0),
      String(used.requestUri),
    );
    expect(again.uid).toBeUndefined();
  });

  it('認可の入口は、割符の PAR の urn の形でない request_uri と、URL の authorization_details を 400 で断る', async () => {
    // 攻撃者が持っている情報：企業の client_id（公開の値）
    // 試す経路：外の URL、別の urn、形の崩れた urn の request_uri で入口を開く。申請を URL に載せて入口を開く
    //           （request_uri の有無の両方）。resource を付けて開く
    // 期待する結果：どれも 400 の固定の画面。外へ取りに行かない（oidc-provider の fetch は呼ばれない）
    // plan 11章：テスト2（ADR 0025 の O-50、O-51。不変条件7）
    const browser = new Browser(world.t.origin);
    const detail = JSON.stringify([deskDetail(user.sub)]);
    const valid = await pushRequest(world.t, client(0), [deskDetail(user.sub)]);
    const cases: Record<string, string>[] = [
      { request_uri: 'https://attacker.example/request.jwt' },
      { request_uri: 'urn:example:request:abcdefghijklmnopqrstu' },
      { request_uri: 'urn:ietf:params:oauth:request_uri:has spaces in it......' },
      { request_uri: `urn:ietf:params:oauth:request_uri:${'a'.repeat(200)}` },
      { authorization_details: detail },
      { request_uri: String(valid.requestUri), authorization_details: detail },
      { request_uri: String(valid.requestUri), resource: 'https://api.example' },
    ];
    for (const extra of cases) {
      const params = new URLSearchParams({ client_id: client(0).clientId, ...extra });
      const result = await browser.get(`/oidc/auth?${params}`);
      expect([Object.keys(extra).join(','), result.status]).toEqual([
        Object.keys(extra).join(','),
        400,
      ]);
      expect(result.text).toContain('要求の形が違います');
    }
    expect(world.t.outboundAttempts()).toBe(0);
  });

  it.each([
    ['actions がない', (s: string) => [deskDetail(s, { actions: undefined })]],
    [
      '操作が2つ',
      (s: string) => [deskDetail(s, { actions: ['desk.case.create', 'desk.case.status.read'] })],
    ],
    ['申請が2件', (s: string) => [deskDetail(s), deskDetail(s)]],
    ['知らない型', (s: string) => [deskDetail(s, { type: 'payment_initiation' })]],
    ['subject がない', (s: string) => [deskDetail(s, { subject: undefined })]],
    ['subject の形が違う', () => [deskDetail('someone@example.com')]],
    ['申請ID が短い', (s: string) => [deskDetail(s, { identifier: 'short' })]],
    ['作成なのに choices がない', (s: string) => [deskDetail(s, { choices: undefined })]],
    [
      '照会なのに choices がある',
      (s: string) => [deskDetail(s, { actions: ['desk.case.status.read'] })],
    ],
    [
      '種別が決めた語でない',
      (s: string) => [deskDetail(s, { choices: { category: 'refund', language: 'ja' } })],
    ],
    [
      'choices に余分な項目',
      (s: string) => [
        deskDetail(s, { choices: { category: 'general', language: 'ja', free_text: 'x' } }),
      ],
    ],
    ['配列でない', (s: string) => deskDetail(s)],
    ['JSON でない', () => '[{"type":'],
  ] as const)('型に合わない申請（%s）は、PAR の受け口で断る', async (_name, make) => {
    // 攻撃者が持っている情報：企業のサーバーを操れる立場（ATK-03）。型の外の項目で、割符の画面や企業の処理を
    //                       操りたい
    // 試す経路：authorization_details の形を1つずつ崩して PAR を送る
    // 期待する結果：400（invalid_authorization_details か invalid_request）。request_uri は出ない。通常のログインの
    //               要求として受け付けることもしない
    // plan 11章：テスト2（D-20）
    const par = await pushRequest(world.t, client(0), make(user.sub) as never);
    expect(par.status).toBe(400);
    expect(['invalid_authorization_details', 'invalid_request']).toContain(par.body.error);
    expect(par.requestUri).toBeUndefined();
  });

  it('企業ごとに許した操作だけを受け付ける（許していないクライアントは、型 warifu_desk も送れない）', async () => {
    // 攻撃者が持っている情報：照会だけを許されたクライアントの資格情報、窓口を許されていないクライアントの資格情報
    // 試す経路：照会だけのクライアントで作成を求める。窓口のないクライアントで照会を求める
    // 期待する結果：どちらも 400 invalid_authorization_details。照会だけのクライアントの照会は受け付ける
    // plan 11章：テスト2（D-06）
    const create = await pushRequest(world.t, client(3), [deskDetail(user.sub)]);
    expect([create.status, create.body.error]).toEqual([400, 'invalid_authorization_details']);
    const read = deskDetail(user.sub, { actions: ['desk.case.status.read'] });
    delete read.choices;
    expect((await pushRequest(world.t, client(3), [read])).status).toBe(201);
    const none = await pushRequest(world.t, client(4), [read]);
    expect([none.status, none.body.error]).toEqual([400, 'invalid_authorization_details']);
    expect(ALL_DESK_ACTIONS).toHaveLength(3);
  });

  it('PAR の受け口でも、id_token_hint、request、request_uri、registration は 400（500 にならない）', async () => {
    // 攻撃者が持っている情報：企業のクライアントの資格情報（ATK-03）
    // 試す経路：PAR の本文に、ID トークンのヒント、要求オブジェクト、外の request_uri、動的登録の項目を足す。
    //           claims を足す
    // 期待する結果：前の4つは 400。claims は捨てられ、効き目がない（201 で、ID トークンにも余分なクレームが出ない）
    // plan 11章：テスト2（ADR 0025 の O-52）
    const flow = await codeFlow(world.t, user.browser, client(0), { mode: 'session' });
    const cases: Record<string, string>[] = [
      { id_token_hint: flow.idToken },
      { request: 'eyJhbGciOiJub25lIn0.e30.' },
      { request_uri: 'https://attacker.example/r' },
      { registration: '{"redirect_uris":["https://attacker.example/cb"]}' },
    ];
    for (const extra of cases) {
      const par = await pushRequest(world.t, client(0), [deskDetail(user.sub)], extra);
      expect([Object.keys(extra)[0], par.status]).toEqual([Object.keys(extra)[0], 400]);
    }
    const claims = await pushRequest(world.t, client(0), [deskDetail(user.sub)], {
      claims: JSON.stringify({ id_token: { email: { essential: true } } }),
    });
    expect(claims.status).toBe(201);
    expect(world.t.outboundAttempts()).toBe(0);
  });

  it('窓口の申請のインタラクションでは、通常のログインと同意を受け付けない（縮退しない）', async () => {
    // 攻撃者が持っている情報：窓口の申請の request_uri と、攻撃者自身のパスキー
    // 試す経路：承認用のオリジンに行かず、本来のオリジンのインタラクションのログイン、アカウントの作成、同意を呼ぶ
    // 期待する結果：どれも 400。窓口の承認なしに、企業に認可コードが渡ることはない
    // plan 11章：テスト2（D-20、D-35）
    const par = await pushRequest(world.t, client(0), [deskDetail(user.sub)]);
    const { uid } = await arriveAtDesk(user.browser, client(0), String(par.requestUri));
    for (const path of ['login/options', 'register/options', 'consent']) {
      const result = await user.browser.post(`/interaction/${uid}/${path}`, {
        decision: 'connect',
      });
      expect([path, result.status]).toEqual([path, 400]);
    }
  });

  it('承認のアサーションは、承認用のオリジンの、その申請の内容にだけ結び付く', async () => {
    // 攻撃者が持っている情報：利用者のブラウザで動くスクリプト（本来のオリジン）、別の申請の選択肢
    // 試す経路：本来のオリジンを名乗るアサーションで承認する。申請 A の選択肢で作ったアサーションを、申請 B の
    //           uid で送る。期限（5分）を過ぎてから承認する
    // 期待する結果：どれも 401 か 400。承認されない
    // plan 11章：テスト2（D-04、ADR 0023 の O-43、O-45）
    const a = await arriveAtDesk(
      user.browser,
      client(0),
      String((await pushRequest(world.t, client(0), [deskDetail(user.sub)])).requestUri),
    );
    const wrongOrigin = await approveDesk(user.approval, String(a.uid), { origin: world.t.origin });
    expect(wrongOrigin.status).toBe(401);
    const b = await arriveAtDesk(
      new Browser(world.t.origin, user.browser.authenticator),
      client(0),
      String((await pushRequest(world.t, client(0), [deskDetail(user.sub)])).requestUri),
    );
    const started = await user.approval.post('/api/desk/approve/options', {
      uid: a.uid,
      call: 'self',
    });
    const response = user.approval.authenticator.get(started.json.options as never, undefined, {
      origin: user.approval.origin,
    });
    const swapped = await user.approval.post('/api/desk/approve/verify', {
      uid: b.uid,
      ceremonyId: started.json.ceremonyId,
      response,
    });
    expect(swapped.status).toBe(401);
    const c = await arriveAtDesk(
      new Browser(world.t.origin, user.browser.authenticator),
      client(0),
      String((await pushRequest(world.t, client(0), [deskDetail(user.sub)])).requestUri),
    );
    clock += 5 * 60_000 + 1000;
    expect((await approveDesk(user.approval, String(c.uid))).status).toBe(400);
    expect((await user.approval.post('/api/desk/view', { uid: c.uid })).status).toBe(400);
  });

  it('URL にほかの項目を足しても、PAR で送った内容が使われる（ブラウザでの差し替えはできない）', async () => {
    // 攻撃者が持っている情報：利用者のブラウザの URL を書き換えられる（中継の詐欺のリンク）
    // 試す経路：request_uri の URL に、別の redirect_uri、scope、state を足して入口を開き、承認する
    // 期待する結果：企業への戻り先は登録した redirect_uri、state は PAR で送ったもの。承認の中身も PAR のもの
    // plan 11章：テスト2（D-20、ADR 0025）
    const detail = deskDetail(user.sub);
    const par = await pushRequest(world.t, client(0), [detail]);
    const params = new URLSearchParams({
      client_id: client(0).clientId,
      request_uri: String(par.requestUri),
      redirect_uri: 'http://127.0.0.1:65000/attacker',
      scope: 'openid email',
      state: 'attacker-state',
    });
    const followed = await user.browser.follow(`/oidc/auth?${params}`);
    const uid = followed.external?.hash.slice(1);
    expect(uid).toBeDefined();
    const approved = await approveDesk(user.approval, String(uid));
    const finished = await user.browser.follow(String(approved.json.redirectTo));
    expect(`${finished.external?.origin}${finished.external?.pathname}`).toBe(
      client(0).redirectUri,
    );
    expect(finished.external?.searchParams.get('state')).toBe(par.state);
  });

  it('操作ごとの承認と ID トークンは、鍵と typ が違い、取り違えない', async () => {
    // 攻撃者が持っている情報：利用者の通常のログインの ID トークン（企業の手元で漏れた）
    // 試す経路：ID トークンを、操作ごとの承認として検証する。通常のログインのトークンの応答を見る
    // 期待する結果：検証に失敗する（typ と鍵が違う）。通常のログインの応答には authorization_details がない
    // plan 11章：テスト2（D-22）
    const flow = await codeFlow(world.t, user.browser, client(0), { mode: 'session' });
    expect(flow.tokenResponse).not.toHaveProperty('authorization_details');
    await expect(
      verifyOpApproval(world.t, flow.idToken, { clientId: client(0).clientId }),
    ).rejects.toThrow();
  });

  it('窓口の承認の sub は、同じテナントのクライアントでは同じで、別のテナントでは別（テスト4）', async () => {
    // 攻撃者が持っている情報：2社に届いた操作ごとの承認（企業をまたいで突き合わせようとする者）
    // 試す経路：同じ利用者が、テナント1の2つのクライアントと、テナント2のクライアントで、窓口の照会を承認する
    // 期待する結果：テナント1の2つは同じ sub（ID トークンの sub とも同じ）。テナント2は別の sub。
    //               操作ごとの承認の jti は、承認ごとに違う
    // plan 11章：テスト4（ADR 0026）
    const browser = user.browser;
    const first = user;
    const subs: string[] = [];
    const jtis: string[] = [];
    for (const index of [0, 1, 2]) {
      const login = await codeFlow(world.t, browser, client(index), { mode: 'session' });
      const detail = deskDetail(String(login.claims.sub), { actions: ['desk.case.status.read'] });
      delete detail.choices;
      const flow = await deskFlow(world, first, client(index), detail);
      const payload = decodeJwt(String(flow.approvalJwt));
      expect(payload.sub).toBe(login.claims.sub);
      subs.push(String(payload.sub));
      jtis.push(String(payload.jti));
    }
    expect(subs[0]).toBe(subs[1]);
    expect(subs[2]).not.toBe(subs[0]);
    expect(new Set(jtis).size).toBe(3);
  });
});
