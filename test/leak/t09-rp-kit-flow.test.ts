// テスト9：企業の側を rp-kit の SDK で書いたときに、割符（idp、company-api、sender）と端から端まで動くこと
// （plan 11章 テスト9、ADR 0028、ADR 0029 の O-108）。企業が書くのは通信の関数（test/setup/rp-kit.ts）だけで、
// 要求の組み立て、応答と承認の JWT と SET の検証は SDK が行う。利用者の操作は、テストのブラウザ役が行う。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type CompanyApiClient,
  createCompanyApiClient,
  createWarifuClient,
  type PendingAuthorization,
  RpKitError,
  type WarifuClient,
} from '../../packages/rp-kit/src/index.ts';
import { ISSUER as COMPANY_ORIGIN } from '../setup/company-api.ts';
import { connectedUser, type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import type { Browser } from '../setup/idp.ts';
import { companySend, idpSend, jwkOf } from '../setup/rp-kit.ts';

const HOUR = 3600 * 1000;
let clock = Date.now();
const now = () => new Date(clock);
let world: DeskWorld;
let warifu: WarifuClient;
let company: CompanyApiClient;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0, initialLink: true }],
    now,
    initialLink: true,
  });
  const idpClient = world.t.clients[0];
  const tenant = world.company.tenants[0];
  if (idpClient === undefined || tenant === undefined) throw new Error('準備に失敗した');
  warifu = await createWarifuClient({
    idpOrigin: world.t.origin,
    clientId: idpClient.clientId,
    redirectUri: idpClient.redirectUri,
    privateKey: await jwkOf(idpClient.privateKey),
    kid: idpClient.kid,
    send: idpSend,
    // ID トークンは oidc-provider が実際の時計で署名する（テストの時計を進めても変わらない）ので、SDK も実際の時計で確かめる。
  });
  company = await createCompanyApiClient({
    origin: COMPANY_ORIGIN,
    clientId: tenant.client.clientId,
    tenantId: tenant.tenantId,
    privateKey: await jwkOf(tenant.client.privateKey),
    kid: tenant.client.kid,
    send: companySend(world.company),
    now,
  });
});

afterAll(async () => {
  await world?.stop();
});

/** 利用者：SDK が作った認可の URL に進み、承認用のオリジンでパスキーで承認して、企業に戻る。 */
async function approveAt(
  user: { readonly browser: Browser; readonly approval: Browser },
  url: string,
  page: '/initial-link' | '/desk',
): Promise<string> {
  const arrived = await user.browser.follow(url);
  if (arrived.external?.pathname !== page) throw new Error('承認用のオリジンに引き継がれない');
  const uid = arrived.external.hash.slice(1);
  const api = page === '/desk' ? '/api/desk' : '/api/initial-link';
  const started = await user.approval.post(`${api}/approve/options`, {
    uid,
    ...(page === '/desk' ? { call: 'self' } : {}),
  });
  if (started.status !== 200) throw new Error(`承認を始められない（${started.status}）`);
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approved = await user.approval.post(`${api}/approve/verify`, {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  if (approved.status !== 200) throw new Error(`承認できない（${approved.status}）`);
  const finished = await user.browser.follow(String(approved.json.redirectTo));
  if (finished.external === undefined) throw new Error('企業に戻ってこない');
  return finished.external.href;
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    if (!(error instanceof RpKitError)) throw error;
    return error.code;
  }
}

describe('テスト9：rp-kit の SDK で書いた企業と、割符（ADR 0029）', () => {
  it('ログインから初回紐付けの完了まで、企業の側は SDK だけで進み、SET も SDK で確かめられる', async () => {
    // 攻撃者が持っている情報：なし（正規の流れ。企業が SDK で組み込むときの形を確かめる）
    // 試す経路：SDK のログイン → 仮申請と証跡 → 最初の承認 → 待機の SET（SDK で検証）→ 24時間 → 最終の証跡 →
    //           最終の承認（SDK で紐付けの承認の JWT を検証）→ 結果の報告
    // 期待する結果：どの段も SDK が通す。ID トークンの sub は承認の sub と同じ。同じ結果の2回目の読み取りは replayed
    // plan 11章：テスト9
    const user = await connectedUser(world, world.t.clients[0] as never);
    const login = await warifu.authorize();
    const signedIn = await warifu.finish(
      (await user.browser.follow(login.url)).external?.href ?? '',
      login.pending,
    );
    expect(signedIn.sub).toBe(user.sub);
    expect(signedIn.acr).toBe('urn:warifu:acr:passkey');

    const memberRef = randomBytes(18).toString('base64url');
    const initialLinkId = await company.initialLink.prepare({
      requestId: randomBytes(18).toString('base64url'),
      memberRef,
    });
    const proof = {
      initialLinkId,
      memberRef,
      credentialKind: 'passkey' as const,
      profileVersion: 3,
      authEpoch: 7,
    };
    await company.initialLink.submitProof({ ...proof, stage: 'initial' });

    const first = await warifu.pushInitialLink({
      action: 'initial_link.approve',
      initialLinkId,
      sub: signedIn.sub,
    });
    const firstLogin = await warifu.finish(
      await approveAt(user, first.url, '/initial-link'),
      first.pending,
    );
    expect(await warifu.readInitialLink(firstLogin, first.pending)).toEqual({
      stage: 'approve',
      state: 'pending_notice',
    });

    clock += 61_000;
    const before = world.sender.requests.length;
    expect(await world.company.api.deliverDue()).toMatchObject({ delivered: 1 });
    const set = await company.verifySet(String(world.sender.requests[before]?.body));
    expect(set.events).toEqual({
      'urn:warifu:secevent:initial-link-waiting': { initial_link_id: initialLinkId },
    });

    clock += 24 * HOUR + 1000;
    await company.initialLink.submitProof({ ...proof, stage: 'final' });
    const final = await warifu.pushInitialLink({
      action: 'initial_link.finalize',
      initialLinkId,
      sub: signedIn.sub,
    });
    const finalLogin = await warifu.finish(
      await approveAt(user, final.url, '/initial-link'),
      final.pending,
    );
    expect(finalLogin.sub).toBe(signedIn.sub);
    expect(await warifu.readInitialLink(finalLogin, final.pending)).toMatchObject({
      stage: 'finalize',
      initialLinkId,
    });
    expect(await codeOf(warifu.readInitialLink(finalLogin, final.pending))).toBe('replayed');
    await company.initialLink.report({ initialLinkId, result: 'linked' });
  });

  it('窓口の照会の承認は SDK で通り、同じ結果を初回紐付けとして読ませると断る', async () => {
    // 攻撃者が持っている情報：窓口の照会の承認（企業のサーバーの記録から漏れた結果）
    // 試す経路：窓口の照会を SDK で承認させ、その結果を初回紐付けの結果として読ませる。別の申請と取り違えさせる
    // 期待する結果：照会の承認は通る。初回紐付けとしても、別の申請としても verification_failed
    // plan 11章：テスト1（RP-21）、テスト9
    const user = await connectedUser(world, world.t.clients[0] as never);
    const requestId = randomBytes(16).toString('base64url');
    const desk = await warifu.pushDesk({
      action: 'desk.case.status.read',
      requestId,
      sub: user.sub,
    });
    const deskLogin = await warifu.finish(await approveAt(user, desk.url, '/desk'), desk.pending);
    expect(await codeOf(warifu.readInitialLink(deskLogin, desk.pending))).toBe(
      'verification_failed',
    );
    const other: PendingAuthorization = {
      ...desk.pending,
      detail: { ...desk.pending.detail, identifier: randomBytes(16).toString('base64url') },
    };
    expect(await codeOf(warifu.verifyDeskApproval(deskLogin, other))).toBe('verification_failed');
    expect(await warifu.verifyDeskApproval(deskLogin, desk.pending)).toMatchObject({
      action: 'desk.case.status.read',
      requestId,
      changeId: null,
    });
  });

  it('戻りの URL の state、別の redirect_uri、割符が断った要求は、SDK が失敗にする', async () => {
    // 攻撃者が持っている情報：別の利用者の認可コード付きの戻りの URL（CSRF やコードの差し込み）
    // 試す経路：state の違う戻りの URL、別のパスへの戻り、割符が断る PAR（許していない操作）を SDK に渡す
    // 期待する結果：verification_failed、または rejected（割符の error の値だけ）
    // plan 11章：テスト9、テスト6
    const user = await connectedUser(world, world.t.clients[0] as never);
    const login = await warifu.authorize();
    const back = new URL((await user.browser.follow(login.url)).external?.href ?? '');
    const forged = new URL(back);
    forged.searchParams.set('state', 'forged-state');
    expect(await codeOf(warifu.finish(forged.href, login.pending))).toBe('verification_failed');
    const elsewhere = new URL(back);
    elsewhere.pathname = '/elsewhere';
    expect(await codeOf(warifu.finish(elsewhere.href, login.pending))).toBe('verification_failed');
    const refused = await codeOf(
      warifu.pushDesk({
        action: 'desk.order.status.read',
        requestId: 'short',
        sub: user.sub,
      }),
    );
    expect(refused).toBe('rejected');
  });
});
