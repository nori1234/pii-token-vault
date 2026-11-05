// 回復の開始の応答を、登録済みかどうかで変えない（plan 11章 テスト10、不変条件10、ADR 0027 の O-75）。
// 形の違うコード、いない利用者、秘密の違うコード、協力者のいない利用者、進行中の回復がある利用者、取消の後の14日の中の
// 利用者は、どれも同じ 400 の固定の本文になり、所要時間にも大きな差がない。

import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FAILED } from '../../packages/idp/src/http.ts';
import { formatRecoveryCode, parseRecoveryCode } from '../../packages/idp/src/recovery.ts';
import type { WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover } from '../setup/approvals.ts';
import { Browser, type HttpResult, startTestIdp, type TestIdp } from '../setup/idp.ts';
import {
  bindingCodeOf,
  cancelRecovery,
  issueCode,
  makeHelper,
  startOnNewDevice,
} from '../setup/recovery.ts';

const HOUR = 3600_000;

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock));
});

afterAll(async () => {
  await t?.stop();
});

/** 回復の開始を1回送る。レート制限（IP と利用者で1時間）を持ち越さないよう、送る前に時計を進める。 */
async function start(code: unknown): Promise<HttpResult & { ms: number }> {
  clock += 2 * HOUR;
  const browser = new Browser(t.approvalOrigin);
  const started = performance.now();
  const result = await browser.post('/api/recovery/start', { code });
  return { ...result, ms: performance.now() - started };
}

function wrongSecret(code: string): string {
  const parsed = parseRecoveryCode(code);
  if (parsed === undefined) throw new Error('コードの形が違う');
  return formatRecoveryCode(parsed.userId, randomBytes(10));
}

describe('漏えい：回復の開始の応答（plan 11章 テスト10）', () => {
  it('形の違うコード、いない利用者、秘密の違うコード、使えない状態の利用者は、どれも同じ 400 になる', async () => {
    // 攻撃者が持っている情報：利用者 ID らしい値（企業別ID や別名からは導けないが、総当たりや推測で作った値）と、
    //                         登録済みかもしれない利用者のコードの形
    // 試す経路：回復の開始に、形の違うコード、いない利用者のコード、登録済みの利用者の秘密の違うコード、協力者のいない
    //           利用者の正しいコード、回復が進行中の利用者の正しいコード、取消の後の14日の中の利用者のコードを送る
    // 期待する結果：どれも 400 で、本文は { error: 'failed' }、クッキーを置かない。正しいコードだけが 200 になる
    // plan 11章：テスト10
    const withHelper = await newApprover(t);
    const helper = await newApprover(t);
    const code = await issueCode(withHelper.approval);
    await makeHelper(withHelper.approval, helper.approval);

    const noHelper = await newApprover(t);
    const noHelperCode = await issueCode(noHelper.approval);

    const busy = await newApprover(t);
    const busyHelper = await newApprover(t);
    const busyCode = await issueCode(busy.approval);
    await makeHelper(busy.approval, busyHelper.approval);
    bindingCodeOf((await startOnNewDevice(t, busyCode)).register);

    const locked = await newApprover(t);
    const lockedHelper = await newApprover(t);
    const lockedCode = await issueCode(locked.approval);
    await makeHelper(locked.approval, lockedHelper.approval);
    bindingCodeOf((await startOnNewDevice(t, lockedCode)).register);
    await locked.approval.approvalLogin();
    expect((await cancelRecovery(locked.approval)).status).toBe(200);
    await locked.approval.approvalLogin();
    const relockedCode = await issueCode(locked.approval);

    const refused = [
      'not-a-recovery-code',
      code.replace(/-/g, '').slice(0, 30),
      `${code}0`,
      formatRecoveryCode(randomUUID() as WarifuUserId, randomBytes(10)),
      wrongSecret(code),
      noHelperCode,
      busyCode,
      relockedCode,
    ];
    for (const value of refused) {
      const result = await start(value);
      expect(result.status).toBe(400);
      expect(result.json).toEqual(FAILED);
      expect(result.headers.getSetCookie()).toEqual([]);
    }
    const accepted = await start(code.toLowerCase());
    expect(accepted.status).toBe(200);
    expect(accepted.headers.getSetCookie()).toEqual([]);
  });

  it('いない利用者と、登録済みの利用者の秘密の違うコードで、所要時間の中央値に大きな差がない', async () => {
    // 攻撃者が持っている情報：利用者 ID らしい値（総当たりで作った値）
    // 試す経路：いない利用者のコードと、登録済みの利用者の秘密の違うコードを、交互に20回ずつ送り、所要時間を比べる
    // 期待する結果：どちらも 400 で、所要時間の中央値の差は小さい（100ミリ秒未満）
    // plan 11章：テスト10
    const owner = await newApprover(t);
    const helper = await newApprover(t);
    const code = await issueCode(owner.approval);
    await makeHelper(owner.approval, helper.approval);
    const timings: Record<'known' | 'unknown', number[]> = { known: [], unknown: [] };
    for (let i = 0; i < 20; i += 1) {
      for (const kind of ['known', 'unknown'] as const) {
        const value =
          kind === 'known'
            ? wrongSecret(code)
            : formatRecoveryCode(randomUUID() as WarifuUserId, randomBytes(10));
        const result = await start(value);
        expect(result.status).toBe(400);
        timings[kind].push(result.ms);
      }
    }
    const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;
    expect(Math.abs(median(timings.known) - median(timings.unknown))).toBeLessThan(100);
  });
});
