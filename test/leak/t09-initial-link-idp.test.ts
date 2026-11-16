// テスト9：既存会員の初回紐付けを、企業のサーバー役 → company-api → idp（PAR、承認用のオリジン、受信箱）→ 企業への
// 待機の SET → 最終の承認 → 紐付けの承認の JWT まで、端から端まで通す（plan 11章 テスト9、ADR 0028 の O-86〜O-91・O-103）。
// 企業のサーバーの役（仮申請、証跡、PAR、トークン、JWT の検証、結果の報告）は、テストの中で行う（rp-kit の手前）。

import { readFileSync } from 'node:fs';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { parseWarifuUserId, type WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { userIdOf } from '../setup/approvals.ts';
import type { TestTenant as CompanyTenant } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import {
  connectedUser,
  type DeskWorld,
  type ParResult,
  pushRequest,
  startDeskWorld,
} from '../setup/desk.ts';
import { type Browser, redeemCode, type TestClient } from '../setup/idp.ts';
import { initialLinkProof, newMemberRef, newRequestId } from '../setup/initial-link.ts';

const HOUR = 3600 * 1000;
const APPROVAL_TYP = 'warifu-initial-link-approval+jwt';
let clock = Date.now();
let world: DeskWorld;

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [
      { tenant: 0, initialLink: true },
      // 初回紐付けを許していないクライアント。
      { tenant: 1, initialLink: false },
    ],
    now: () => new Date(clock),
    initialLink: true,
  });
});

afterAll(async () => {
  await world?.stop();
});

function client(index: number): TestClient {
  const found = world.t.clients[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

function companyTenant(index: number): CompanyTenant {
  const found = world.company.tenants[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

/** 企業のサーバー役：company-api の初回紐付けのルートを呼ぶ。 */
async function companyCall(path: string, json: unknown) {
  const token = await world.company.accessToken(companyTenant(0), 'initial_link');
  return world.company.request({ path: `/v1/initial-link/${path}`, token, json });
}

/** 企業のサーバー役：仮申請と初回の証跡まで。 */
async function preparedWithProof(): Promise<{ id: string; memberRef: string }> {
  const memberRef = newMemberRef();
  const prepared = await companyCall('prepare', {
    request_id: newRequestId(),
    member_ref: memberRef,
  });
  expect(prepared.status).toBe(200);
  const id = (prepared.json() as { initial_link_id: string }).initial_link_id;
  const proof = await companyCall('proofs', {
    proof: await initialLinkProof(
      companyTenant(0),
      { initial_link_id: id, member_ref: memberRef },
      { nowMs: clock },
    ),
  });
  expect(proof.status).toBe(204);
  return { id, memberRef };
}

function detailOf(action: string, id: string, sub: string) {
  return { type: 'warifu_initial_link', actions: [action], identifier: id, subject: sub };
}

interface Outcome {
  readonly uid?: string;
  readonly approve?: { status: number; json: Record<string, unknown> };
  readonly authorizationDetails?: Record<string, unknown>[];
}

/** 利用者：PAR の request_uri で入口に来て、承認用のオリジンの /initial-link で、パスキーで承認する。 */
async function approveFlow(
  user: { readonly browser: Browser; readonly approval: Browser },
  c: TestClient,
  detail: Record<string, unknown>,
): Promise<Outcome & { readonly par: ParResult }> {
  const par = await pushRequest(world.t, c, [detail]);
  if (par.requestUri === undefined) return { par };
  const params = new URLSearchParams({ client_id: c.clientId, request_uri: par.requestUri });
  const arrived = await user.browser.follow(`/oidc/auth?${params}`);
  const uid =
    arrived.external?.pathname === '/initial-link' ? arrived.external.hash.slice(1) : undefined;
  if (uid === undefined) return { par };
  const started = await user.approval.post('/api/initial-link/approve/options', { uid });
  if (started.status !== 200) return { par, uid, approve: started };
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approve = await user.approval.post('/api/initial-link/approve/verify', {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  if (approve.status !== 200) return { par, uid, approve };
  const finished = await user.browser.follow(String(approve.json.redirectTo));
  if (finished.external?.searchParams.get('code') == null) return { par, uid, approve };
  const redeemed = await redeemCode(world.t, c, finished.external, par.verifier, par.state);
  return {
    par,
    uid,
    approve,
    authorizationDetails: redeemed.tokenResponse.authorization_details as Record<string, unknown>[],
  };
}

async function items(approval: Browser): Promise<Record<string, unknown>[]> {
  const result = await approval.get('/api/initial-link-items');
  expect(result.status).toBe(200);
  return result.json.items as Record<string, unknown>[];
}

async function idpItemCount(userId: WarifuUserId): Promise<number> {
  const db = await serviceDb('idp');
  try {
    const rows = await db.withWarifuUser(userId, (tx) =>
      tx.query(sql`SELECT item_id FROM idp.initial_link_items`),
    );
    return rows.length;
  } finally {
    await db.close();
  }
}

describe('テスト9：初回紐付け（idp。ADR 0028）', () => {
  it('最初の承認は状態だけを返し、待機の SET の 202 の後24時間で、最終の承認が紐付けの承認の JWT を返す', async () => {
    // 攻撃者が持っている情報：なし（正規の流れ。後のテストの土台）
    // 試す経路：仮申請と初回の証跡 → PAR（initial_link.approve）→ 承認 → 待機の SET → 24時間 → 最終の証跡 →
    //           PAR（initial_link.finalize）→ 承認 → JWT の検証 → linked の報告
    // 期待する結果：最初のトークンの応答は state=pending_notice だけで JWT を持たない。待機が満ちる前の最終の承認は
    //               409（not_ready）。満ちた後は、typ・aud・sub・initial_link_id の合った ES256 の JWT が出る。
    //               受信箱の項目は、承認済み → 待機中 → 紐付けの完了と進み、取消の操作は待機の間だけ出る
    // plan 11章：テスト9
    const user = await connectedUser(world, client(0));
    const { id, memberRef } = await preparedWithProof();
    const first = await approveFlow(
      user,
      client(0),
      detailOf('initial_link.approve', id, user.sub),
    );
    expect(first.approve?.status).toBe(200);
    expect(first.authorizationDetails).toEqual([
      { ...detailOf('initial_link.approve', id, user.sub), state: 'pending_notice' },
    ]);

    await user.approval.approvalLogin();
    expect((await items(user.approval)).map((i) => [i.state, i.cancellable])).toEqual([
      ['awaiting_notice', true],
    ]);

    // 待機の知らせの SET（最初の送信は0〜60秒の乱数だけ遅れる）。202 の時刻から待機が始まる。
    clock += 61_000;
    expect(await world.company.api.deliverDue()).toMatchObject({ delivered: 1 });
    const [waiting] = await items(user.approval);
    expect(waiting?.state).toBe('waiting');
    expect(waiting?.waitUntil).toBe(new Date(clock + 24 * HOUR).toISOString());

    // 待機が満ちる前の最終の承認は出ない（最終の証跡があっても）。
    const early = await approveFlow(
      user,
      client(0),
      detailOf('initial_link.finalize', id, user.sub),
    );
    expect([early.approve?.status, early.approve?.json]).toEqual([409, { error: 'not_ready' }]);

    clock += 24 * HOUR + 1000;
    const finalProof = await companyCall('proofs', {
      proof: await initialLinkProof(
        companyTenant(0),
        { initial_link_id: id, member_ref: memberRef, stage: 'final' },
        { nowMs: clock },
      ),
    });
    expect(finalProof.status).toBe(204);
    // 承認用のセッションは、24時間の間に切れている。もう一度パスキーで入る。
    await user.approval.approvalLogin();
    expect((await items(user.approval))[0]?.state).toBe('ready');
    const final = await approveFlow(
      user,
      client(0),
      detailOf('initial_link.finalize', id, user.sub),
    );
    expect(final.approve?.status).toBe(200);
    const [granted] = final.authorizationDetails ?? [];
    expect(Object.keys(granted ?? {}).sort()).toEqual([
      'actions',
      'approval',
      'identifier',
      'subject',
      'type',
    ]);
    const jwt = String(granted?.approval);
    expect(decodeProtectedHeader(jwt).typ).toBe(APPROVAL_TYP);
    const jwks = (await (
      await fetch(`${world.t.origin}/initial-link/jwks`)
    ).json()) as JSONWebKeySet;
    const { payload } = await jwtVerify(jwt, createLocalJWKSet(jwks), {
      issuer: world.t.issuer,
      audience: client(0).clientId,
      algorithms: ['ES256'],
      typ: APPROVAL_TYP,
      currentDate: new Date(clock),
    });
    expect(Object.keys(payload).sort()).toEqual([
      'acr',
      'aud',
      'auth_time',
      'exp',
      'iat',
      'initial_link_id',
      'iss',
      'jti',
      'purpose',
      'sub',
    ]);
    expect(payload).toMatchObject({ sub: user.sub, purpose: 'initial_link', initial_link_id: id });
    expect(Number(payload.exp) - Number(payload.iat)).toBe(300);
    // 操作ごとの承認（窓口）の鍵とは別の鍵。
    const opJwks = (await (
      await fetch(`${world.t.origin}/op-approval/jwks`)
    ).json()) as JSONWebKeySet;
    await expect(
      jwtVerify(jwt, createLocalJWKSet(opJwks), { currentDate: new Date(clock) }),
    ).rejects.toThrow();

    expect((await companyCall('results', { initial_link_id: id, result: 'linked' })).status).toBe(
      204,
    );
    expect((await items(user.approval)).map((i) => [i.state, i.cancellable])).toEqual([
      ['linked', false],
    ]);
  });

  it('許していないクライアント、2件の申請、型を混ぜた申請、形の違う申請は、PAR の受け口で断る', async () => {
    // 攻撃者が持っている情報：初回紐付けを許されていない企業の正規の資格情報、または正規の企業の資格情報
    // 試す経路：B社のクライアントで warifu_initial_link を送る。A社で2件、窓口の型と混ぜて、余計な項目付きで送る
    // 期待する結果：どれも 400（invalid_authorization_details などの、区別しない拒否）。request_uri は出ない
    // plan 11章：テスト9、テスト6
    const sub = 'A'.repeat(43);
    const id = 'B'.repeat(43);
    const cases: [TestClient, unknown][] = [
      [client(1), [detailOf('initial_link.approve', id, sub)]],
      [
        client(0),
        [detailOf('initial_link.approve', id, sub), detailOf('initial_link.finalize', id, sub)],
      ],
      [
        client(0),
        [
          detailOf('initial_link.approve', id, sub),
          { type: 'warifu_desk', actions: ['desk.case.status.read'], identifier: id, subject: sub },
        ],
      ],
      [client(0), [{ ...detailOf('initial_link.approve', id, sub), email: 'member@example.com' }]],
      [client(0), [detailOf('initial_link.link', id, sub)]],
    ];
    for (const [c, details] of cases) {
      const par = await pushRequest(world.t, c, details);
      expect(par.status).toBe(400);
      expect(par.requestUri).toBeUndefined();
    }
  });

  it('別の利用者、初回の証跡のない申請、紐付け済みの利用者には、承認を出さず、受信箱に項目を残さない', async () => {
    // 攻撃者が持っている情報：他人の旧会員の移行専用ID（企業のサーバーから漏れた）と、自分の割符のアカウント
    // 試す経路：被害者の sub を入れた申請を、攻撃者のパスキーで承認する。初回の証跡を出していない申請を承認する
    // 期待する結果：sub の不一致は 401、証跡のない申請は 409。どちらも受信箱の項目を作らない
    // plan 11章：テスト9（紐付けの攻撃）
    const victim = await connectedUser(world, client(0));
    const attacker = await connectedUser(world, client(0));
    const { id } = await preparedWithProof();
    const stolen = await approveFlow(
      attacker,
      client(0),
      detailOf('initial_link.approve', id, victim.sub),
    );
    expect(stolen.approve?.status).toBe(401);
    expect(await idpItemCount(parseWarifuUserId(userIdOf(attacker.browser.authenticator)))).toBe(0);

    const prepared = await companyCall('prepare', {
      request_id: newRequestId(),
      member_ref: newMemberRef(),
    });
    const noProofId = (prepared.json() as { initial_link_id: string }).initial_link_id;
    const noProof = await approveFlow(
      attacker,
      client(0),
      detailOf('initial_link.approve', noProofId, attacker.sub),
    );
    expect(noProof.approve?.status).toBe(409);
    expect(await idpItemCount(parseWarifuUserId(userIdOf(attacker.browser.authenticator)))).toBe(0);
  });

  it('利用者は待機中に受信箱から取り消せ、取消の後は企業の linked を 409 にし、最終の承認を出さない', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー（旧会員の側の証跡を出せる）。本人は待機中に気付いた
    // 試す経路：待機中に、本人が承認用のオリジンでパスキーで取り消す。その後、企業が linked を報告し、最終の承認を求める
    // 期待する結果：取消は cancel_requested。linked は 409。最終の承認は 409。項目は取り消しできない状態になる
    // plan 11章：テスト9、ADR 0028 の O-90・O-91
    const user = await connectedUser(world, client(0));
    const { id } = await preparedWithProof();
    const first = await approveFlow(
      user,
      client(0),
      detailOf('initial_link.approve', id, user.sub),
    );
    expect(first.approve?.status).toBe(200);
    await user.approval.approvalLogin();
    const [item] = await items(user.approval);
    const started = await user.approval.post('/api/initial-link-items/cancel/options', {
      id: item?.id,
    });
    expect(started.status).toBe(200);
    const response = user.approval.authenticator.get(started.json.options as never, undefined, {
      origin: user.approval.origin,
    });
    const cancelled = await user.approval.post('/api/initial-link-items/cancel/verify', {
      ceremonyId: started.json.ceremonyId,
      response,
    });
    expect(cancelled.json).toEqual({ ok: true, state: 'cancel_requested' });
    expect((await items(user.approval)).map((i) => [i.state, i.cancellable])).toEqual([
      ['cancel_requested', false],
    ]);
    expect((await companyCall('results', { initial_link_id: id, result: 'linked' })).status).toBe(
      409,
    );
    const final = await approveFlow(
      user,
      client(0),
      detailOf('initial_link.finalize', id, user.sub),
    );
    expect(final.approve?.status).toBe(409);
  });

  it('ほかの利用者の項目は、一覧に出ず、取り消せない', async () => {
    // 攻撃者が持っている情報：被害者の受信箱の項目 ID（画面の共有などで見た）と、自分の割符のアカウント
    // 試す経路：攻撃者の承認用のセッションで、被害者の項目 ID の取消の選択肢を求める
    // 期待する結果：400（区別しない）。攻撃者の一覧に被害者の項目は出ない
    // plan 11章：テスト6（利用者どうしの BOLA）
    const victim = await connectedUser(world, client(0));
    const attacker = await connectedUser(world, client(0));
    const { id } = await preparedWithProof();
    expect(
      (await approveFlow(victim, client(0), detailOf('initial_link.approve', id, victim.sub)))
        .approve?.status,
    ).toBe(200);
    await victim.approval.approvalLogin();
    const [item] = await items(victim.approval);
    await attacker.approval.approvalLogin();
    expect(await items(attacker.approval)).toEqual([]);
    const started = await attacker.approval.post('/api/initial-link-items/cancel/options', {
      id: item?.id,
    });
    expect([started.status, started.json]).toEqual([400, { error: 'failed' }]);
  });

  it('警告文 I は、DESIGN.md 3章の1文と同じで、ログインと初回紐付けの承認の画面の両方で使う', () => {
    // 攻撃者が持っている情報：なし（固定の文言が、文書と画面で食い違わないことを確かめる）
    // 試す経路：DESIGN.md 3章の警告文 I の文と、public/app.js の文を比べる
    // 期待する結果：同じ文が1か所にだけあり、企業へのログインと初回紐付けの承認の画面で出す
    // plan 11章：番号なし（DESIGN.md 原則5、ADR 0028 の O-105）
    const design = readFileSync(new URL('../../DESIGN.md', import.meta.url), 'utf8');
    const section = design.slice(design.indexOf('**I（割符と企業の受け持ち）**'));
    const sentence = /「(割符は、[^」]+)」/.exec(section)?.[1];
    expect(sentence).toBeDefined();
    const appJs = readFileSync(
      new URL('../../packages/idp/public/app.js', import.meta.url),
      'utf8',
    );
    expect(appJs.split(String(sentence)).length - 1).toBe(1);
    expect(appJs.match(/responsibilityNote\(\)/g)?.length).toBe(3);
  });
});
