// テスト1：高リスクの操作（出金先の変更）は、その企業のその内容に結び付いた承認だけを根拠にする（plan 11章 テスト1、
// plan 3-1、spec 02 の RP-09〜RP-12、ADR 0030）。企業の側は rp-kit の SDK で書く（ADR 0029）。
// 割符が検出できるのは、申請ID と表示の項目の不一致だけ。表示が同じ別の口座への差し替えは、企業の RP-09 で防ぐ
// （ここでは確かめない。demo-rp で示す）。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createWarifuClient,
  type PayoutDestinationContent,
  RpKitError,
  type WarifuClient,
} from '../../packages/rp-kit/src/index.ts';
import { connectedUser, type DeskWorld, pushRequest, startDeskWorld } from '../setup/desk.ts';
import type { Browser, TestClient } from '../setup/idp.ts';
import { idpSend, jwkOf } from '../setup/rp-kit.ts';

const clock = Date.now();
let world: DeskWorld;
let warifu: WarifuClient;
const CONTENT: PayoutDestinationContent = {
  bankCode: '9991',
  branchCode: '101',
  accountLast4: '4567',
};

beforeAll(async () => {
  world = await startDeskWorld({
    tenants: 2,
    clients: [
      { tenant: 0, operationActions: ['payout_destination.change'] },
      // 高リスクの操作を許していないクライアント。
      { tenant: 1 },
    ],
    now: () => new Date(clock),
  });
  warifu = await sdkFor(client(0));
});

afterAll(async () => {
  await world?.stop();
});

function client(index: number): TestClient {
  const found = world.t.clients[index];
  if (found === undefined) throw new Error('準備に失敗した');
  return found;
}

async function sdkFor(c: TestClient): Promise<WarifuClient> {
  return createWarifuClient({
    idpOrigin: world.t.origin,
    clientId: c.clientId,
    redirectUri: c.redirectUri,
    privateKey: await jwkOf(c.privateKey),
    kid: c.kid,
    send: idpSend,
  });
}

const newRequestId = () => randomBytes(18).toString('base64url');

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    if (!(error instanceof RpKitError)) throw error;
    return error.code;
  }
}

/** 利用者：/operation で画面を読み、パスキーで承認して、企業に戻る。画面の中身も返す。 */
async function approveOperation(user: { browser: Browser; approval: Browser }, url: string) {
  const arrived = await user.browser.follow(url);
  if (arrived.external?.pathname !== '/operation')
    throw new Error('承認用のオリジンに引き継がれない');
  const uid = arrived.external.hash.slice(1);
  const card = await user.approval.post('/api/operation/view', { uid });
  const started = await user.approval.post('/api/operation/approve/options', { uid });
  const response = user.approval.authenticator.get(started.json.options as never, undefined, {
    origin: user.approval.origin,
  });
  const approved = await user.approval.post('/api/operation/approve/verify', {
    uid,
    ceremonyId: started.json.ceremonyId,
    response,
  });
  if (approved.status !== 200) return { card, approved, back: undefined };
  const finished = await user.browser.follow(String(approved.json.redirectTo));
  return { card, approved, back: finished.external?.href };
}

describe('テスト1：高リスクの操作の step-up（ADR 0030）', () => {
  it('承認の画面は、対応表の名前とコード、末尾4桁、架空の注記、A-2 を出し、SDK はその内容の承認だけを通す', async () => {
    // 攻撃者が持っている情報：なし（正規の流れ）
    // 試す経路：SDK で出金先の変更を PAR で申請し、承認用のオリジンで承認し、SDK で承認の JWT を確かめる
    // 期待する結果：画面に、割符の対応表の金融機関名・支店名とコード、末尾4桁、デモ用の注記、警告文 A-2。
    //               企業が固定した申請ID と内容でだけ通り、同じ結果の2回目は replayed
    // plan 11章：テスト1（RP-10・RP-12）
    const user = await connectedUser(world, client(0));
    const requestId = newRequestId();
    const pushed = await warifu.pushOperation({
      action: 'payout_destination.change',
      requestId,
      sub: user.sub,
      content: CONTENT,
    });
    const { card, back } = await approveOperation(user, pushed.url);
    expect(card.json).toMatchObject({
      operation: '出金先の変更',
      lines: [
        { label: '金融機関', value: 'わりふデモ銀行（9991）' },
        { label: '支店', value: '中央支店（101）' },
        { label: '口座番号の末尾', value: '4567' },
      ],
      demoNote: 'デモ用の架空の金融機関・支店です。',
      warning: 'A-2',
    });
    const login = await warifu.finish(String(back), pushed.pending);
    // 企業が固定した内容と違う内容（末尾4桁や申請ID）で照らすと通らない。
    expect(
      await codeOf(
        warifu.verifyOperationApproval(login, pushed.pending, {
          requestId,
          content: { ...CONTENT, accountLast4: '9999' },
        }),
      ),
    ).toBe('verification_failed');
    expect(
      await codeOf(
        warifu.verifyOperationApproval(login, pushed.pending, {
          requestId: newRequestId(),
          content: CONTENT,
        }),
      ),
    ).toBe('verification_failed');
    expect(
      await warifu.verifyOperationApproval(login, pushed.pending, { requestId, content: CONTENT }),
    ).toMatchObject({ action: 'payout_destination.change', requestId });
    expect(
      await codeOf(
        warifu.verifyOperationApproval(login, pushed.pending, { requestId, content: CONTENT }),
      ),
    ).toBe('replayed');
  });

  it('対応表にない金融機関、形の違う内容、余計な項目、許していないクライアントは、PAR の受け口で断る', async () => {
    // 攻撃者が持っている情報：企業の資格情報（承認の画面に、自由な文言や実在らしい口座を出させようとする）
    // 試す経路：対応表にないコード、名前や名義を足した内容、全桁の口座番号、許していないクライアントで PAR を送る
    // 期待する結果：どれも 400。request_uri は出ない
    // plan 11章：テスト1、テスト6
    const sub = 'S'.repeat(43);
    const base = {
      type: 'warifu_operation',
      actions: ['payout_destination.change'],
      identifier: newRequestId(),
      subject: sub,
      content: { bank_code: '9991', branch_code: '101', account_last4: '4567' },
    };
    const cases: [TestClient, Record<string, unknown>][] = [
      [client(0), { ...base, content: { ...base.content, bank_code: '0001' } }],
      [client(0), { ...base, content: { ...base.content, branch_code: '999' } }],
      [client(0), { ...base, content: { ...base.content, bank_name: 'ほんもの銀行' } }],
      [client(0), { ...base, content: { ...base.content, holder: 'ヤマダ タロウ' } }],
      [client(0), { ...base, content: { ...base.content, account_last4: '12345678' } }],
      [client(0), { ...base, actions: ['refund_destination.change'] }],
      [client(0), { ...base, identifier: 'short' }],
      [client(1), base],
    ];
    for (const [c, detail] of cases) {
      const par = await pushRequest(world.t, c, [detail]);
      expect(par.status).toBe(400);
      expect(par.requestUri).toBeUndefined();
    }
  });

  it('別の利用者の承認、窓口の承認、期限の切れた承認は通らない', async () => {
    // 攻撃者が持っている情報：被害者の sub（企業の記録から漏れた）と自分の割符のアカウント。または窓口の承認
    // 試す経路：被害者の sub で申請して攻撃者のパスキーで承認する。窓口の照会の結果を高リスクの操作として確かめる。
    //           承認から5分を過ぎてから確かめる
    // 期待する結果：sub の不一致は 401。窓口の承認と期限切れは verification_failed
    // plan 11章：テスト1（RP-21）
    const victim = await connectedUser(world, client(0));
    const attacker = await connectedUser(world, client(0));
    const stolen = await warifu.pushOperation({
      action: 'payout_destination.change',
      requestId: newRequestId(),
      sub: victim.sub,
      content: CONTENT,
    });
    expect((await approveOperation(attacker, stolen.url)).approved.status).toBe(401);

    const deskClient = await createWarifuClient({
      idpOrigin: world.t.origin,
      clientId: client(0).clientId,
      redirectUri: client(0).redirectUri,
      privateKey: await jwkOf(client(0).privateKey),
      kid: client(0).kid,
      send: idpSend,
    });
    const requestId = newRequestId();
    const pushed = await deskClient.pushOperation({
      action: 'payout_destination.change',
      requestId,
      sub: victim.sub,
      content: CONTENT,
    });
    const { back } = await approveOperation(victim, pushed.url);
    const login = await deskClient.finish(String(back), pushed.pending);
    // 同じ結果を、窓口の承認として読ませても通らない（型と鍵が違う）。
    expect(await codeOf(deskClient.verifyDeskApproval(login, pushed.pending))).toBe(
      'verification_failed',
    );
    // 5分を過ぎた承認は通らない（SDK の時計を進める）。
    const later = await createWarifuClient({
      idpOrigin: world.t.origin,
      clientId: client(0).clientId,
      redirectUri: client(0).redirectUri,
      privateKey: await jwkOf(client(0).privateKey),
      kid: client(0).kid,
      send: idpSend,
      now: () => new Date(Date.now() + 6 * 60_000),
    });
    expect(
      await codeOf(
        later.verifyOperationApproval(login, pushed.pending, { requestId, content: CONTENT }),
      ),
    ).toBe('verification_failed');
  });
});
