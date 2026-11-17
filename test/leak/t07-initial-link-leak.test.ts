// テスト7（plan 11章）：既存会員の初回紐付けの値を、割符の DB（pg_dump。全サービスのスキーマ）とログに残さない
// （不変条件4、ADR 0020、ADR 0028 の O-87）。
// 企業の側は rp-kit の SDK（割符へのログインと承認、company-api の初回紐付け）で書き、どちらの通信の関数も包んで、
// 企業と割符の間を行き来した値（移行証跡の JWT、移行専用ID、申請ID、会員参照、client assertion、company-api の
// トークン、認可コード、ID トークン、最終の承認の JWT）を集める。待機の SET も足す。紐付けの完了までと、証跡を出した
// まま承認しなかった申請の後で、DB を丸ごと取り出し、ログと合わせて、値の形を変えて探す。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createCompanyApiClient, createWarifuClient } from '../../packages/rp-kit/src/index.ts';
import type { HttpRequest, HttpResponse, Send } from '../../packages/rp-kit/src/transport.ts';
import { userIdOf } from '../setup/approvals.ts';
import { ISSUER as COMPANY_ORIGIN } from '../setup/company-api.ts';
import { connectedUser, type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import { dumpWorkerDatabase, leaksIn } from '../setup/dump.ts';
import type { Browser } from '../setup/idp.ts';
import { companySend, idpSend, jwkOf } from '../setup/rp-kit.ts';

const HOUR = 3600 * 1000;
/** 本文の項目のうち、探すもの（申請の中身の版や種類などの、秘密でない項目は除く）。 */
const KEYS = [
  'client_assertion',
  'code',
  'code_verifier',
  'access_token',
  'id_token',
  'refresh_token',
  'request_uri',
  'proof',
  'initial_link_id',
  'request_id',
  'member_ref',
] as const;

let clock = Date.now();
let world: DeskWorld;
const exchanged: string[] = [];

/** 送った本文（フォームか JSON）と受け取った本文（JSON）から、探す値を集める。 */
function collect(body: string | undefined): void {
  if (body === undefined || body === '') return;
  let fields: Record<string, unknown>;
  try {
    fields = JSON.parse(body) as Record<string, unknown>;
  } catch {
    fields = Object.fromEntries(new URLSearchParams(body));
  }
  if (fields === null || typeof fields !== 'object') return;
  for (const key of KEYS) {
    const value = fields[key];
    if (typeof value === 'string' && value !== '') exchanged.push(value);
  }
  for (const detail of Array.isArray(fields.authorization_details)
    ? (fields.authorization_details as Record<string, unknown>[])
    : []) {
    if (typeof detail.approval === 'string') exchanged.push(detail.approval);
  }
}

function recording(send: Send): Send {
  return async (request: HttpRequest): Promise<HttpResponse> => {
    const response = await send(request);
    collect(request.body);
    collect(response.body);
    return response;
  };
}

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0, initialLink: true }],
    now: () => new Date(clock),
    initialLink: true,
  });
});

afterAll(async () => {
  await world?.stop();
});

/** 利用者：承認用のオリジンで、初回紐付けの申請をパスキーで承認して、企業への戻りの URL を返す。 */
async function approveAt(user: { browser: Browser; approval: Browser }, url: string) {
  const arrived = await user.browser.follow(url);
  if (arrived.external?.pathname !== '/initial-link') throw new Error('承認用のオリジンに来ない');
  const uid = arrived.external.hash.slice(1);
  const started = await user.approval.post('/api/initial-link/approve/options', { uid });
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approved = await user.approval.post('/api/initial-link/approve/verify', {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  expect(approved.status).toBe(200);
  const finished = await user.browser.follow(String(approved.json.redirectTo));
  return String(finished.external?.href);
}

describe('テスト7：初回紐付けの値を、DB とログに残さない', () => {
  it('紐付けの完了と、承認しなかった申請の後に、DB を丸ごと取り出しても、ログにも、値がない', async () => {
    // 攻撃者が持っている情報：割符の DB を丸ごと読める立場（pg_dump、ATK-06）と、idp・company-api・sender のログを
    //                         読める立場
    // 試す経路：企業が SDK で仮申請し、最初の証跡を出し、利用者が最初の承認をする。待機の SET を受け、24時間の後に
    //           最終の証跡を出し、利用者が最終の承認をして、企業が紐付けて報告する。別の旧会員で、仮申請と最初の証跡の
    //           まま承認しない申請を残す。その後で、DB を丸ごと取り出し、ログと合わせて探す
    // 期待する結果：移行証跡、移行専用ID、申請ID、会員参照、client assertion、company-api のトークン、認可コード、
    //               ID トークン、最終の承認の JWT、待機の SET が、DB にもログにも出ない
    // plan 11章：テスト7
    const idpClient = world.t.clients[0];
    const tenant = world.company.tenants[0];
    if (idpClient === undefined || tenant === undefined) throw new Error('準備に失敗した');
    const warifu = await createWarifuClient({
      idpOrigin: world.t.origin,
      clientId: idpClient.clientId,
      redirectUri: idpClient.redirectUri,
      privateKey: await jwkOf(idpClient.privateKey),
      kid: idpClient.kid,
      send: recording(idpSend),
    });
    const company = await createCompanyApiClient({
      origin: COMPANY_ORIGIN,
      clientId: tenant.client.clientId,
      tenantId: tenant.tenantId,
      privateKey: await jwkOf(tenant.client.privateKey),
      kid: tenant.client.kid,
      send: recording(companySend(world.company)),
      now: () => new Date(clock),
    });
    const user = await connectedUser(world, idpClient);
    const login = await warifu.authorize();
    const signedIn = await warifu.finish(
      (await user.browser.follow(login.url)).external?.href ?? '',
      login.pending,
    );

    // 紐付けの完了まで。
    const memberRef = randomBytes(18).toString('base64url');
    const requestId = randomBytes(18).toString('base64url');
    const initialLinkId = await company.initialLink.prepare({ requestId, memberRef });
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
    await warifu.finish(await approveAt(user, first.url), first.pending);
    clock += 61_000;
    const before = world.sender.requests.length;
    expect(await world.company.api.deliverDue()).toMatchObject({ delivered: 1 });
    const waitingSet = String(world.sender.requests[before]?.body);
    clock += 24 * HOUR + 1000;
    await company.initialLink.submitProof({ ...proof, stage: 'final' });
    const final = await warifu.pushInitialLink({
      action: 'initial_link.finalize',
      initialLinkId,
      sub: signedIn.sub,
    });
    const finalLogin = await warifu.finish(await approveAt(user, final.url), final.pending);
    expect(await warifu.readInitialLink(finalLogin, final.pending)).toMatchObject({
      stage: 'finalize',
      initialLinkId,
    });
    await company.initialLink.report({ initialLinkId, result: 'linked' });

    // 仮申請と最初の証跡のまま、承認しない申請。
    const otherRef = randomBytes(18).toString('base64url');
    const otherRequest = randomBytes(18).toString('base64url');
    const otherId = await company.initialLink.prepare({
      requestId: otherRequest,
      memberRef: otherRef,
    });
    await company.initialLink.submitProof({
      ...proof,
      initialLinkId: otherId,
      memberRef: otherRef,
      stage: 'initial',
    });

    const needles = [
      ...exchanged,
      waitingSet,
      initialLinkId,
      otherId,
      requestId,
      otherRequest,
      memberRef,
      otherRef,
      first.pending.verifier,
      final.pending.verifier,
    ];
    // 集めた値が、実際に行き来した値を含んでいることを先に確かめる（包んだ通信の関数の空振りを防ぐ）。
    // 移行証跡の JWT は、仮申請ごとに最初と最終で3件。最終の承認の JWT と、company-api のトークンも入る。
    expect(exchanged).toContain(initialLinkId);
    expect(
      exchanged.filter((v) => v.split('.').length === 3 && v.length > 100).length,
    ).toBeGreaterThanOrEqual(8);
    expect(waitingSet.split('.')).toHaveLength(3);

    const dump = await dumpWorkerDatabase();
    const logs = {
      idp: world.t.logLines().join('\n'),
      company: world.company.logs.join('\n'),
      sender: world.sender.logs.join('\n'),
    };
    // 取り出したものとログが、この流れを実際に含んでいることを先に確かめる（利用者 ID は秘密ではなく、平文で残る）。
    expect(leaksIn({ dump }, [userIdOf(user.browser.authenticator)])).toEqual(['0:dump']);
    expect(dump).toMatch(/COPY company_api\.initial_link_records \([^)]*\) FROM stdin;\n[^\\]/);
    expect(leaksIn({ dump, ...logs }, needles)).toEqual([]);
  });
});
