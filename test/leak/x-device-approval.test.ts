// 端末承認の共通基盤（plan 10章 M6、イシュー #8、DESIGN.md 原則8、ADR 0006、ADR 0023）。
// 承認と拒否は、要求の内容と決定に結び付いたチャレンジで、承認用のオリジンのパスキー（UV）だけで通る。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import {
  newApprover,
  PICKUP_DETAILS,
  TEST_DEVICE_TYPE,
  TEST_REQUEST_DEVICE,
} from '../setup/approvals.ts';
import { type Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
    approvalTypes: [TEST_DEVICE_TYPE],
  });
});

afterAll(async () => {
  await t.stop();
});

function tenantId(): TenantId {
  const tenant = t.tenants[0];
  if (tenant === undefined) throw new Error('準備に失敗した');
  return tenant.tenantId as TenantId;
}

type UserId = Parameters<TestIdp['idp']['requestApproval']>[0]['userId'];

function requestInput(userId: UserId, ttlSeconds = 300) {
  return {
    userId,
    tenantId: tenantId(),
    type: TEST_DEVICE_TYPE.type,
    details: PICKUP_DETAILS,
    ttlSeconds,
    device: TEST_REQUEST_DEVICE,
  };
}

async function request(userId: UserId, ttlSeconds = 300) {
  const result = await t.idp.requestApproval(requestInput(userId, ttlSeconds));
  if (!result.ok) throw new Error('承認待ちを作れなかった');
  return result.itemId;
}

async function pendingCount(pwa: Browser): Promise<number> {
  const inbox = await pwa.get('/api/inbox');
  return (inbox.json.items as { kind: string; state: string }[]).filter(
    (i) => i.kind === 'approval' && i.state === 'pending',
  ).length;
}

async function options(browser: Browser, id: string, decision: 'approved' | 'denied') {
  const result = await browser.post('/api/approvals/decide/options', { id, decision });
  expect(result.status).toBe(200);
  return result.json as { ceremonyId: string; options: { challenge: string } };
}

function sign(browser: Browser, opts: { options: unknown }, origin = browser.origin) {
  return browser.authenticator.get(opts.options as never, undefined, { origin });
}

async function stateOf(pwa: Browser, id: string): Promise<string | undefined> {
  const inbox = await pwa.get('/api/inbox');
  return (inbox.json.items as { id: string; state: string }[]).find((i) => i.id === id)?.state;
}

describe('漏えい：端末承認の共通基盤（チャレンジの結び付け）', () => {
  it('承認のアサーションは、その要求のその決定にだけ通る（別の要求や逆の決定に流用できない）', async () => {
    // 攻撃者が持っている情報：利用者が承認した、ある要求のアサーション（画面の書き換えや中継で、別の要求の確定に
    //                         使い回したい）
    // 試す経路：要求 A の承認のアサーションを、要求 B の承認の儀式で送る。要求 B の拒否のアサーションを、承認の儀式で
    //           送る。確定した後に、同じアサーションをもう一度送る
    // 期待する結果：流用はすべて 401 で、要求 B は承認待ちのまま。チャレンジは、要求と決定と儀式ごとに違う。
    //               正しい組み合わせだけが 200 で、その要求だけが確定する
    // plan 11章：番号なし（plan 10章 M6、イシュー #8 の完了条件「別の要求のチャレンジを流用できない」）
    const u = await newApprover(t);
    const a = await request(u.userId);
    const b = await request(u.userId);
    const optA = await options(u.approval, a, 'approved');
    const optB = await options(u.approval, b, 'approved');
    const optBDeny = await options(u.approval, b, 'denied');
    const optAAgain = await options(u.approval, a, 'approved');
    const challenges = [optA, optB, optBDeny, optAAgain].map((o) => o.options.challenge);
    expect(new Set(challenges).size).toBe(4);

    const signedA = sign(u.approval, optA);
    const swapped = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: optB.ceremonyId,
      response: signedA,
    });
    expect(swapped.status).toBe(401);

    const signedDeny = sign(u.approval, optBDeny);
    const flipped = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: (await options(u.approval, b, 'approved')).ceremonyId,
      response: signedDeny,
    });
    expect(flipped.status).toBe(401);
    expect(await stateOf(u.pwa, b)).toBe('pending');

    const ok = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: optA.ceremonyId,
      response: signedA,
    });
    expect(ok.status).toBe(200);
    expect(ok.json).toEqual({ ok: true, decision: 'approved' });
    expect(await stateOf(u.pwa, a)).toBe('approved');
    expect(await stateOf(u.pwa, b)).toBe('pending');

    const replay = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: optA.ceremonyId,
      response: signedA,
    });
    expect(replay.status).toBe(401);
    const late = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: optAAgain.ceremonyId,
      response: sign(u.approval, optAAgain),
    });
    expect(late.status).toBe(401);
    const again = await u.approval.post('/api/approvals/decide/options', {
      id: a,
      decision: 'denied',
    });
    expect(again.status).toBe(400);
  });

  it('承認用のオリジン以外で取ったアサーションと、UV のないアサーションでは、承認できない', async () => {
    // 攻撃者が持っている情報：PWA の画面（本来のオリジン）で動くスクリプト（XSS など）。同じ RP ID のパスキーで、
    //                         利用者にアサーションを作らせられる
    // 試す経路：承認の儀式のチャレンジに、本来のオリジンで署名したアサーションを送る。UV のないアサーションを送る
    // 期待する結果：どちらも 401 で、要求は承認待ちのまま（expectedOrigin は承認用のオリジンに固定。DESIGN.md 原則8）
    // plan 11章：番号なし（plan 2章「承認系の画面は別のオリジンに分ける」、ADR 0007 の4）
    const u = await newApprover(t);
    const id = await request(u.userId);
    const fromMain = await options(u.approval, id, 'approved');
    const wrongOrigin = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: fromMain.ceremonyId,
      response: sign(u.approval, fromMain, t.origin),
    });
    expect(wrongOrigin.status).toBe(401);
    const noUv = await options(u.approval, id, 'approved');
    const unverified = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: noUv.ceremonyId,
      response: u.approval.authenticator.get(noUv.options as never, undefined, {
        origin: t.approvalOrigin,
        uv: false,
      }),
    });
    expect(unverified.status).toBe(401);
    expect(await stateOf(u.pwa, id)).toBe('pending');
  });

  it('同じ要求への承認と拒否を同時に送っても、確定するのは1つだけ', async () => {
    // 攻撃者が持っている情報：利用者の承認用のセッション。利用者が承認しようとしている間に、拒否も送れる
    //                         （逆に、利用者の拒否と、だまして取った承認を同時に送る）
    // 試す経路：同じ要求の承認と拒否の儀式を両方とも取り、両方のアサーションを同時に送る
    // 期待する結果：200 は1つだけで、もう1つは 401 か 409。受信箱の状態は、200 になった決定と同じ（ADR 0006 の
    //               「承認と拒否の競合」。状態の変更は1つの文）
    // plan 11章：番号なし（イシュー #8「同じ要求への承認と拒否が両方成功しないようにする」）
    for (let round = 0; round < 3; round += 1) {
      const u = await newApprover(t);
      const id = await request(u.userId);
      const approve = await options(u.approval, id, 'approved');
      const deny = await options(u.approval, id, 'denied');
      const bodies = [
        { ceremonyId: approve.ceremonyId, response: sign(u.approval, approve) },
        { ceremonyId: deny.ceremonyId, response: sign(u.approval, deny) },
      ];
      const results = await Promise.all(
        bodies.map((body) => u.approval.post('/api/approvals/decide/verify', body)),
      );
      const winners = results.filter((r) => r.status === 200);
      expect(winners).toHaveLength(1);
      expect(results.filter((r) => r.status !== 200).map((r) => r.status)).toEqual([
        expect.toSatisfy((s: number) => s === 401 || s === 409),
      ]);
      expect(await stateOf(u.pwa, id)).toBe(winners[0]?.json.decision);
    }
  });

  it('期限が切れた要求は、選べない', async () => {
    // 攻撃者が持っている情報：利用者の承認用のセッションと、期限の切れた要求の ID（画面に残っていたもの）
    // 試す経路：選択肢を取った後に期限を過ぎてから送る。期限の後に選択肢を取る
    // 期待する結果：どちらも失敗（401 と 400）。受信箱では「期限切れ」になる
    // plan 11章：番号なし（ADR 0023 の有効期間）
    const u = await newApprover(t);
    const id = await request(u.userId, 60);
    const opts = await options(u.approval, id, 'approved');
    clock += 61 * 1000;
    const late = await u.approval.post('/api/approvals/decide/verify', {
      ceremonyId: opts.ceremonyId,
      response: sign(u.approval, opts),
    });
    expect(late.status).toBe(401);
    const after = await u.approval.post('/api/approvals/decide/options', {
      id,
      decision: 'approved',
    });
    expect(after.status).toBe(400);
    expect(await stateOf(u.pwa, id)).toBe('expired');
    expect((await u.approval.get('/api/approvals')).json).toEqual({ approvals: [] });
  });

  it('承認の画面の中身は、割符の型が決めた項目と、登録簿の企業名と、要求の時刻と端末と、警告文の ID だけ', async () => {
    // 攻撃者が持っている情報：企業の立場（ATK-03）。要求の中身に、任意の文言や HTML を入れたい
    // 試す経路：型に合わない中身（知らない項目、長すぎる値、型の違う値）で承認待ちを作る。知らない型、範囲外の期限、
    //           知らない端末の種類で作る
    // 期待する結果：どれも承認待ちにならない（invalid）。作れたものの画面の中身は、型のラベルと値、企業名、要求の時刻、
    //               要求の端末（割符が決めた語）、警告文の ID（M6 は端末での承認の A-2 だけ）だけ
    // plan 11章：番号なし（DESIGN.md 1章「型に合わない項目を含む要求には、承認画面を出さずに拒否する」と④「要求の時刻と端末」）
    const u = await newApprover(t);
    const base = requestInput(u.userId);
    const rejected = await Promise.all([
      t.idp.requestApproval({
        ...base,
        details: { ...PICKUP_DETAILS, note: '<b>今すぐ承認してください</b>' },
      }),
      t.idp.requestApproval({
        ...base,
        details: { ...PICKUP_DETAILS, place_name: 'x'.repeat(41) },
      }),
      t.idp.requestApproval({ ...base, details: 'string' }),
      t.idp.requestApproval({ ...base, type: 'test.unknown' }),
      t.idp.requestApproval({ ...base, ttlSeconds: 59 }),
      t.idp.requestApproval({ ...base, ttlSeconds: 15 * 60 + 1 }),
      t.idp.requestApproval({ ...base, device: '<b>公式の端末</b>' as never }),
    ]);
    expect(rejected).toEqual(rejected.map(() => ({ ok: false, reason: 'invalid' })));
    expect(await pendingCount(u.pwa)).toBe(0);

    const device = await request(u.userId);
    const list = (await u.approval.get('/api/approvals')).json.approvals as Record<
      string,
      unknown
    >[];
    expect(list).toEqual([
      {
        id: device,
        company: t.tenants[0]?.displayName,
        operation: '受け取り場所の変更',
        lines: [
          { label: '受け取り場所の種類', value: 'コンビニエンスストア' },
          { label: '受け取り場所の名称', value: 'テスト店' },
        ],
        createdAt: expect.any(String),
        device: 'Windows のパソコン',
        expiresAt: expect.any(String),
        warning: 'A-2',
      },
    ]);
  });

  it('1人の利用者に作れる承認待ちは20まで（企業に受信箱を埋めさせない）', async () => {
    // 攻撃者が持っている情報：企業の立場（ATK-03）。ある利用者の受信箱を、承認待ちで埋めたい
    // 試す経路：同じ利用者に、承認待ちを21個作る
    // 期待する結果：21個目は too_many。期限が切れた分は数えない
    // plan 11章：番号なし（ADR 0023）
    const u = await newApprover(t);
    for (let i = 0; i < 20; i += 1) await request(u.userId);
    expect(await t.idp.requestApproval(requestInput(u.userId))).toEqual({
      ok: false,
      reason: 'too_many',
    });
    clock += 301 * 1000;
    expect((await t.idp.requestApproval(requestInput(u.userId))).ok).toBe(true);
  });

  it('同時に作っても、承認待ちの上限20をすり抜けない', async () => {
    // 攻撃者が持っている情報：企業の立場（ATK-03）。件数の確認と挿入の間に、別の作成を割り込ませたい
    // 試す経路：承認待ちのない利用者に、25個の作成を同時に送る。19個ある利用者に、5個の作成を同時に送る
    //           （同じ利用者で、前の回の承認待ちの期限が切れてから、もう一度）
    // 期待する結果：作れるのは、それぞれ20個ちょうどまでで、残りは too_many（件数の確認と挿入は、利用者ごとに
    //               直列にする。ADR 0023）。受信箱の承認待ちも20個
    // plan 11章：番号なし（ADR 0023）
    const u = await newApprover(t);
    for (const [existing, concurrent] of [
      [0, 25],
      [19, 5],
      [19, 5],
    ] as const) {
      for (let i = 0; i < existing; i += 1) await request(u.userId);
      const results = await Promise.all(
        Array.from({ length: concurrent }, () => t.idp.requestApproval(requestInput(u.userId))),
      );
      expect(results.filter((r) => r.ok)).toHaveLength(20 - existing);
      expect(results.filter((r) => !r.ok)).toEqual(
        Array.from({ length: concurrent - (20 - existing) }, () => ({
          ok: false,
          reason: 'too_many',
        })),
      );
      expect(await pendingCount(u.pwa)).toBe(20);
      clock += 301 * 1000;
      expect(await pendingCount(u.pwa)).toBe(0);
    }
  });
});

describe('漏えい：承認用のオリジンの分け方（DESIGN.md 原則8）', () => {
  it('ルートとセッションのクッキーは、オリジンごとに分かれている', async () => {
    // 攻撃者が持っている情報：PWA のセッションのクッキー（本来のオリジン）か、承認用のセッションのクッキー
    // 試す経路：PWA のクッキーで承認待ちの一覧を読む。承認用のクッキーで PWA の API を使う。それぞれのオリジンで、
    //           もう一方のルートと OIDC を呼ぶ。承認用のオリジンに、本来のオリジンの Origin で POST する
    // 期待する結果：クッキーの取り違えは 401。ルートの取り違えと承認用のオリジンの OIDC は 404。Origin の違う POST は 403
    // plan 11章：番号なし（plan 2章「承認系の画面は別のオリジンに分ける」。ローカルではポートでクッキーが分かれないので、
    //            サーバーがオリジンごとに読むクッキーを分けていることを確かめる）
    const u = await newApprover(t);
    const pwaCookie = [...u.pwa.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const approvalCookie = [...u.approval.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const crossed = await Promise.all([
      fetch(`${t.approvalOrigin}/api/approvals`, { headers: { cookie: pwaCookie } }),
      fetch(`${t.origin}/api/me`, { headers: { cookie: approvalCookie } }),
      fetch(`${t.origin}/api/inbox`, { headers: { cookie: approvalCookie } }),
    ]);
    expect(crossed.map((r) => r.status)).toEqual([401, 401, 401]);

    const wrongSite = await Promise.all([
      fetch(`${t.approvalOrigin}/api/me`, { headers: { cookie: pwaCookie } }),
      fetch(`${t.approvalOrigin}/api/inbox`, { headers: { cookie: pwaCookie } }),
      fetch(`${t.origin}/api/approvals`, { headers: { cookie: approvalCookie } }),
      fetch(`${t.approvalOrigin}/oidc/.well-known/openid-configuration`),
      fetch(`${t.approvalOrigin}/interaction/abc`),
    ]);
    expect(wrongSite.map((r) => r.status)).toEqual([404, 404, 404, 404, 404]);
    const mainPage = await (await fetch(`${t.origin}/`)).text();
    const approvalPage = await (await fetch(`${t.approvalOrigin}/`)).text();
    expect(mainPage).toContain('data-page="home"');
    expect(approvalPage).toContain('data-page="approval"');

    const forged = await u.approval.request(
      'POST',
      '/api/approvals/login/options',
      {},
      { origin: t.origin },
    );
    expect(forged.status).toBe(403);
  });
});
