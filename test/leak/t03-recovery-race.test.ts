// 協力者の承認と、同時に起きる協力者のパスキーの追加・協力者自身の回復の成立・協力者の解除（plan 11章 テスト3、
// PRN-87、ADR 0027 の O-76）。承認は、協力者の範囲での資格の判定と、持ち主の範囲での回復の記録の書き込みに分かれる
// （2つの利用者の境界を、1つのトランザクションにはまとめられない。境界は入れ子にしない。不変条件8）。そこで、テストが
// 持ち主の回復の記録の行をロックして、承認の書き込みを止めておき、その間に、協力者の資格を変える操作か、持ち主による
// 協力者の解除を流す。「その操作が承認より先に終わったのに、承認も通る」ことがないのを確かめる（#50 のレビュー）。
// テストの側のロックは、アプリのロール（idp）で、持ち主の境界の中で取る（DB の中身は書き換えない）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FAILED } from '../../packages/idp/src/http.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { Db } from '../../packages/warifu-core/src/db/types.ts';
import type { WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover } from '../setup/approvals.ts';
import { serviceDb } from '../setup/db.ts';
import { type Browser, type HttpResult, startTestIdp, type TestIdp } from '../setup/idp.ts';
import {
  bindingCodeOf,
  helperApprove,
  issueCode,
  makeHelper,
  resume,
  startOnNewDevice,
} from '../setup/recovery.ts';

/** 承認の要求が、テストのロックで止まるまで待つ時間（ミリ秒）。 */
const REACH_LOCK_MS = 300;
/** 追加や解除が、承認より先に終わるかを見る時間（ミリ秒）。 */
const RACE_MS = 700;
/** 回復の待機（秒）。http のオリジンなので短くできる（協力者自身の回復を成立させるため）。 */
const WAIT_SECONDS = 60;

let t: TestIdp;
let db: Db;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
    recoveryWaitSeconds: WAIT_SECONDS,
  });
  db = await serviceDb('idp');
});

afterAll(async () => {
  await db?.close();
  await t?.stop();
});

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 内容に結び付いた儀式の options と署名だけを先に済ませ、verify を送る関数を返す（verify だけを競わせる）。 */
async function prepareBound(
  browser: Browser,
  path: string,
  body: Record<string, unknown> = {},
): Promise<() => Promise<HttpResult>> {
  const options = await browser.post(`${path}/options`, body);
  expect(options.status).toBe(200);
  const response = browser.authenticator.get(options.json.options as never, undefined, {
    origin: browser.origin,
  });
  return () => browser.post(`${path}/verify`, { ceremonyId: options.json.ceremonyId, response });
}

/** パスキーの追加の options と作成だけを先に済ませ、verify を送る関数を返す。 */
async function prepareAddPasskey(pwa: Browser): Promise<() => Promise<HttpResult>> {
  const options = await pwa.post('/api/passkeys/options');
  expect(options.status).toBe(200);
  const response = pwa.authenticator.create(options.json.options as never);
  return () => pwa.post('/api/passkeys/verify', { ceremonyId: options.json.ceremonyId, response });
}

/** 新しい端末での読み直し（待機の後は成立）の options と署名だけを先に済ませ、verify を送る関数を返す。 */
async function prepareResume(device: Browser): Promise<() => Promise<HttpResult>> {
  const options = await device.post('/api/recovery/resume/options');
  expect(options.status).toBe(200);
  const response = device.authenticator.get(options.json.options as never, undefined, {
    origin: device.origin,
  });
  return () =>
    device.post('/api/recovery/resume/verify', { ceremonyId: options.json.ceremonyId, response });
}

/** 回復コードと協力者を持つ持ち主と、その持ち主の回復を始めた新しい端末（結び付けのコード）。 */
async function attemptAwaitingHelper() {
  const owner = await newApprover(t);
  const helper = await newApprover(t);
  const code = await issueCode(owner.approval);
  await makeHelper(owner.approval, helper.approval);
  const device = await startOnNewDevice(t, code);
  expect(device.register?.status).toBe(200);
  return { owner, helper, device: device.browser, binding: bindingCodeOf(device.register) };
}

/**
 * 持ち主の進行中の回復の記録の行をロックしたまま、承認の verify を送り、承認が止まった後に other を送る。
 * other が承認より先に終わったか（ロックを外す前に終わったか）と、両方の応答を返す。
 */
async function raceWhileHeld(
  ownerUserId: WarifuUserId,
  approve: () => Promise<HttpResult>,
  other: () => Promise<HttpResult>,
): Promise<{ approval: HttpResult; other: HttpResult; otherFirst: boolean }> {
  let release: () => void = () => undefined;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let locked: () => void = () => undefined;
  const isLocked = new Promise<void>((resolve) => {
    locked = resolve;
  });
  const holder = db.withWarifuUser(ownerUserId, async (tx) => {
    const rows = await tx.query(
      sql`SELECT attempt_id FROM idp.recovery_attempts WHERE state = 'awaiting_helper' FOR UPDATE`,
    );
    expect(rows).toHaveLength(1);
    locked();
    await released;
  });
  await isLocked;
  // 要求は、境界の外（テストの文脈）から送る。
  const approving = approve();
  await delay(REACH_LOCK_MS);
  let otherDone = false;
  const doing = other().then((result) => {
    otherDone = true;
    return result;
  });
  await Promise.race([doing, delay(RACE_MS)]);
  const otherFirst = otherDone;
  release();
  await holder;
  const [approval, result] = await Promise.all([approving, doing]);
  return { approval, other: result, otherFirst };
}

/**
 * もう一方の操作が承認より先に終わったなら、承認は 409 で、持ち主の回復は協力者の承認待ちのまま。承認が 200 なら、
 * もう一方の操作は承認の後に終わっている。
 */
async function expectSerialized(
  raced: { approval: HttpResult; otherFirst: boolean },
  device: Browser,
): Promise<void> {
  if (raced.otherFirst) {
    expect(raced.approval.status).toBe(409);
    expect(raced.approval.json).toEqual(FAILED);
    expect((await resume(device)).json.state).toBe('awaiting_helper');
  } else {
    expect(raced.approval.status).toBe(200);
    expect((await resume(device)).json.state).toBe('waiting');
  }
}

describe('漏えい：協力者の承認と、同時の追加・成立・解除（plan 11章 テスト3）', () => {
  it('承認の途中で協力者にパスキーが足されても、足した後に承認が通ることはない', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウントに足すパスキー（協力者のなりすまし）
    // 試す経路：協力者の承認の verify が、資格の判定を終えてから回復の記録を書くまでの間に、協力者のアカウントに
    //           パスキーを足す
    // 期待する結果：パスキーの追加が先に終わったなら、承認は 409（回復は協力者の承認待ちのまま）。承認が 200 なら、
    //               パスキーの追加は承認の後に終わる（足してから14日の判定をすり抜けない。PRN-87）
    // plan 11章：テスト3（PRN-87）
    const { owner, helper, device, binding } = await attemptAwaitingHelper();
    const approve = await prepareBound(helper.approval, '/api/recovery/helper', { code: binding });
    const add = await prepareAddPasskey(helper.pwa);

    const raced = await raceWhileHeld(owner.userId, approve, add);
    expect(raced.other.status).toBe(200);
    await expectSerialized(raced, device);
  });

  it('承認の途中で協力者自身の回復が成立しても、成立した後に承認が通ることはない', async () => {
    // 攻撃者が持っている情報：盗んだ回復コード（持ち主のものと、協力者のもの）と、協力者の回復で作った新しい端末
    //                         （協力者のなりすまし）
    // 試す経路：協力者の承認の verify が、資格の判定を終えてから回復の記録を書くまでの間に、協力者自身の回復を
    //           成立させる
    // 期待する結果：協力者の回復の成立が先に終わったなら、承認は 409（回復は協力者の承認待ちのまま）。承認が 200
    //               なら、協力者の回復の成立は承認の後に終わる（回復してから14日の判定をすり抜けない。PRN-87）
    // plan 11章：テスト3（PRN-87）
    const helper = await newApprover(t);
    const helpersHelper = await newApprover(t);
    const helperCode = await issueCode(helper.approval);
    await makeHelper(helper.approval, helpersHelper.approval);
    const helperDevice = await startOnNewDevice(t, helperCode);
    expect(helperDevice.register?.status).toBe(200);
    const approved = await helperApprove(
      helpersHelper.approval,
      bindingCodeOf(helperDevice.register),
    );
    expect(approved.status).toBe(200);
    clock = Date.parse(String(approved.json.readyAt)) + 1000;

    const owner = await newApprover(t);
    const code = await issueCode(owner.approval);
    await makeHelper(owner.approval, helper.approval);
    const device = await startOnNewDevice(t, code);
    expect(device.register?.status).toBe(200);
    const approve = await prepareBound(helper.approval, '/api/recovery/helper', {
      code: bindingCodeOf(device.register),
    });
    const complete = await prepareResume(helperDevice.browser);

    const raced = await raceWhileHeld(owner.userId, approve, complete);
    expect(raced.other.status).toBe(200);
    expect(raced.other.json.state).toBe('completed');
    await expectSerialized(raced, device.browser);
  });

  it('承認の途中で持ち主が協力者を外しても、外した後に承認が通ることはない', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウント（協力者のなりすまし）
    // 試す経路：協力者の承認の verify が、協力関係を確かめてから回復の記録を書くまでの間に、持ち主が自分の登録済みの
    //           端末で協力者を外す
    // 期待する結果：解除が先に終わったなら、承認は 409（回復は協力者の承認待ちのまま）。承認が 200 なら、解除は
    //               承認の後に終わる（外した協力者の承認は通らない。ADR 0027 の O-76）
    // plan 11章：テスト3（PRN-87）
    const { owner, helper, device, binding } = await attemptAwaitingHelper();
    const approve = await prepareBound(helper.approval, '/api/recovery/helper', { code: binding });
    const remove = await prepareBound(owner.approval, '/api/helpers/remove');

    const raced = await raceWhileHeld(owner.userId, approve, remove);
    expect(raced.other.status).toBe(200);
    await expectSerialized(raced, device);
  });
});
