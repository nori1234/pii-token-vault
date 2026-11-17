// テスト7（plan 11章）：高リスクの操作の承認（出金先の変更）と、企業と割符の間の OIDC の値を、割符の DB（pg_dump。
// 全サービスのスキーマ）とログに残さない（不変条件4、ADR 0025、ADR 0030）。
// 企業の側は rp-kit の SDK で書き、SDK に渡す通信の関数を包んで、企業と割符の間を行き来した値（PAR の request_uri、
// client assertion、認可コード、PKCE の code_verifier、ID トークン、アクセストークン、承認の JWT）を集める。申請ID と
// 変更ID も足す。承認、同じ承認の使い回し、承認しなかった申請、使い終わった認可コードの再送の後で、DB を丸ごと
// 取り出し、ログと合わせて、値の形を変えて探す。

import { randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createWarifuClient,
  type PayoutDestinationContent,
  RpKitError,
} from '../../packages/rp-kit/src/index.ts';
import type { HttpRequest, HttpResponse, Send } from '../../packages/rp-kit/src/transport.ts';
import { userIdOf } from '../setup/approvals.ts';
import { connectedUser, type DeskWorld, startDeskWorld } from '../setup/desk.ts';
import { dumpWorkerDatabase, leaksIn } from '../setup/dump.ts';
import type { Browser } from '../setup/idp.ts';
import { idpSend, jwkOf } from '../setup/rp-kit.ts';

const CONTENT: PayoutDestinationContent = {
  bankCode: '9991',
  branchCode: '101',
  accountLast4: '4567',
};
/** 企業と割符の間で行き来した値のうち、探すもの（不変条件4 のトークン。申請の中身の項目は除く）。 */
const FORM_KEYS = ['client_assertion', 'code', 'code_verifier', 'refresh_token'] as const;
const JSON_KEYS = ['request_uri', 'id_token', 'access_token', 'refresh_token'] as const;

let world: DeskWorld;
const exchanged: string[] = [];

/** SDK の通信の関数を包み、送った本文と受け取った本文から、探す値を集める。 */
const recordingSend: Send = async (request: HttpRequest): Promise<HttpResponse> => {
  const response = await idpSend(request);
  if (typeof request.body === 'string' && request.body.includes('=')) {
    const form = new URLSearchParams(request.body);
    for (const key of FORM_KEYS) {
      const value = form.get(key);
      if (value !== null) exchanged.push(value);
    }
  }
  if (response.headers['content-type']?.includes('json') === true) {
    const body = JSON.parse(response.body) as Record<string, unknown>;
    for (const key of JSON_KEYS) {
      const value = body[key];
      if (typeof value === 'string') exchanged.push(value);
    }
    for (const detail of Array.isArray(body.authorization_details)
      ? (body.authorization_details as Record<string, unknown>[])
      : []) {
      if (typeof detail.approval === 'string') exchanged.push(detail.approval);
    }
  }
  return response;
};

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 1,
    clients: [{ tenant: 0, operationActions: ['payout_destination.change'] }],
  });
});

afterAll(async () => {
  await world?.stop();
});

/** 利用者：承認用のオリジンで画面を読み、パスキーで承認して、企業への戻りの URL を返す。 */
async function approveOperation(user: { browser: Browser; approval: Browser }, url: string) {
  const arrived = await user.browser.follow(url);
  if (arrived.external?.pathname !== '/operation') throw new Error('承認用のオリジンに来ない');
  const uid = arrived.external.hash.slice(1);
  await user.approval.post('/api/operation/view', { uid });
  const started = await user.approval.post('/api/operation/approve/options', { uid });
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approved = await user.approval.post('/api/operation/approve/verify', {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  expect(approved.status).toBe(200);
  const finished = await user.browser.follow(String(approved.json.redirectTo));
  return String(finished.external?.href);
}

describe('テスト7：高リスクの操作の承認と OIDC の値を、DB とログに残さない', () => {
  it('承認、使い回し、承認しなかった申請、認可コードの再送の後に、DB を丸ごと取り出しても、ログにも、値がない', async () => {
    // 攻撃者が持っている情報：割符の DB を丸ごと読める立場（pg_dump、ATK-06）と、idp・company-api・sender のログを
    //                         読める立場
    // 試す経路：企業が SDK で出金先の変更の承認を求め（PAR）、利用者が承認し、企業が認可コードをトークンに換えて承認を
    //           確かめる。同じ承認をもう一度確かめる（使い回し）。別の申請を出して、承認しないまま残す。使い終わった
    //           認可コードを、もう一度トークンに換えようとする。その後で、DB を丸ごと取り出し、ログと合わせて探す
    // 期待する結果：client assertion、request_uri、認可コード、code_verifier、ID トークン、アクセストークン、承認の
    //               JWT、申請ID、変更ID が、DB にもログにも出ない
    // plan 11章：テスト7
    const client = world.t.clients[0];
    if (client === undefined) throw new Error('準備に失敗した');
    const warifu = await createWarifuClient({
      idpOrigin: world.t.origin,
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      privateKey: await jwkOf(client.privateKey),
      kid: client.kid,
      send: recordingSend,
    });
    const user = await connectedUser(world, client);
    const needles: string[] = [];

    // 承認して確かめ、同じ承認をもう一度確かめる。
    const requestId = randomBytes(18).toString('base64url');
    needles.push(requestId);
    const pushed = await warifu.pushOperation({
      action: 'payout_destination.change',
      requestId,
      sub: user.sub,
      content: CONTENT,
    });
    const back = await approveOperation(user, pushed.url);
    const code = new URL(back).searchParams.get('code');
    if (code === null) throw new Error('認可コードがない');
    needles.push(code, pushed.pending.verifier);
    const login = await warifu.finish(back, pushed.pending);
    expect(
      await warifu.verifyOperationApproval(login, pushed.pending, { requestId, content: CONTENT }),
    ).toMatchObject({ action: 'payout_destination.change', requestId });
    const approval = String(login.authorizationDetails?.[0]?.approval);
    const changeId = decodeJwt(approval).change_id;
    if (typeof changeId === 'string') needles.push(changeId);
    await expect(
      warifu.verifyOperationApproval(login, pushed.pending, { requestId, content: CONTENT }),
    ).rejects.toMatchObject({ code: 'replayed' });

    // 承認しないまま残す申請（PAR の request_uri だけが割符に残る）。
    const unused = randomBytes(18).toString('base64url');
    needles.push(unused);
    const left = await warifu.pushOperation({
      action: 'payout_destination.change',
      requestId: unused,
      sub: user.sub,
      content: { ...CONTENT, accountLast4: '0001' },
    });
    needles.push(left.pending.verifier);

    // 使い終わった認可コードの再送（割符は断る）。
    await expect(warifu.finish(back, pushed.pending)).rejects.toBeInstanceOf(RpKitError);

    needles.push(...exchanged);
    // 集めた値が、実際に行き来した値を含んでいることを先に確かめる（包んだ通信の関数の空振りを防ぐ）。
    expect(exchanged).toContain(approval);
    expect(exchanged).toContain(code);
    expect(exchanged).toContain(pushed.pending.verifier);
    // PAR の request_uri（2件）と、client assertion（PAR とトークンの要求で4件以上）と ID トークン（JWT の形）。
    expect(
      exchanged.filter((v) => v.startsWith('urn:ietf:params:oauth:request_uri:')),
    ).toHaveLength(2);
    expect(exchanged.filter((v) => v.split('.').length === 3).length).toBeGreaterThanOrEqual(6);

    const dump = await dumpWorkerDatabase();
    const logs = {
      idp: world.t.logLines().join('\n'),
      company: world.company.logs.join('\n'),
      sender: world.sender.logs.join('\n'),
    };
    // 取り出したものとログが、この流れを実際に含んでいることを先に確かめる（利用者 ID は秘密ではなく、平文で残る）。
    expect(leaksIn({ dump }, [userIdOf(user.browser.authenticator)])).toEqual(['0:dump']);
    expect(logs.idp).toContain('idp.operation_approved');
    expect(leaksIn({ dump, ...logs }, needles)).toEqual([]);
  });
});
