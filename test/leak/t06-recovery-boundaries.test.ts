// 回復と協力者の境界とレート制限（plan 11章 テスト6、ADR 0027 の O-74〜O-78、O-84）。
// 利用者 U1 は、U2 の回復コード、招待、結び付けのコード、回復の記録に触れない（存在しない値と同じ応答）。
// 協力者の承認は、始めた時点の協力者が、承認用のオリジンで、UV 付きのパスキーで、1回だけ行える。

import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { FAILED, RATE_LIMITED } from '../../packages/idp/src/http.ts';
import { formatRecoveryCode, newShortCode } from '../../packages/idp/src/recovery.ts';
import { newApprover } from '../setup/approvals.ts';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import {
  bindingCodeOf,
  bound,
  helperApprove,
  issueCode,
  makeHelper,
  resume,
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

beforeEach(() => {
  clock += 2 * HOUR;
});

async function ownerWithHelper() {
  const owner = await newApprover(t);
  const helper = await newApprover(t);
  const code = await issueCode(owner.approval);
  await makeHelper(owner.approval, helper.approval);
  return { owner, helper, code };
}

describe('漏えい：回復と協力者の境界（plan 11章 テスト6）', () => {
  it('ほかの利用者の結び付けのコード、回復の記録、招待には、存在しない値と同じ応答になる', async () => {
    // 攻撃者が持っている情報：別の利用者の、新しい端末に出た結び付けのコード（画面をのぞいた）、回復の記録の ID、
    //                         招待コード（協力者でない者として）
    // 試す経路：協力者でない利用者 U1 が、U2 の結び付けのコードで協力者の画面と儀式を開く。U2 の回復の記録の ID で
    //           取消を始める。U2 の招待の状態を読み、確定を始める
    // 期待する結果：どれも 400 { error: 'failed' } で、乱数の値と同じ。U2 の回復は協力者の承認待ちのまま
    // plan 11章：テスト6
    const { owner, code } = await ownerWithHelper();
    const attacker = await newApprover(t);
    const device = await startOnNewDevice(t, code);
    const binding = bindingCodeOf(device.register);
    const attempt = (await owner.approval.get('/api/recovery/settings')).json.attempt as {
      id: string;
    };
    for (const value of [binding, newShortCode(), 'not-a-code']) {
      for (const path of ['/api/recovery/helper/view', '/api/recovery/helper/options']) {
        const result = await attacker.approval.post(path, { code: value });
        expect(result.status).toBe(400);
        expect(result.json).toEqual(FAILED);
      }
    }
    for (const id of [attempt.id, randomUUID()]) {
      const result = await attacker.approval.post('/api/recovery/cancel/options', { id });
      expect(result.status).toBe(400);
      expect(result.json).toEqual(FAILED);
    }
    const invite = await owner.approval.post('/api/helpers/invite');
    for (const value of [invite.json.code, newShortCode()]) {
      for (const path of ['/api/helpers/invite/status', '/api/helpers/confirm/options']) {
        const result = await attacker.approval.post(path, { code: value });
        expect(result.status).toBe(400);
        expect(result.json).toEqual(FAILED);
      }
    }
    expect((await resume(device.browser)).json.state).toBe('awaiting_helper');
  });

  it('招待は1回だけ受け入れられ、持ち主は自分の招待を受け入れられない。確定は持ち主だけ', async () => {
    // 攻撃者が持っている情報：持ち主の招待コード（QR を盗み見た）
    // 試す経路：持ち主が自分の招待を受け入れる。協力者が受け入れた後に、攻撃者がもう一度受け入れる。協力者が自分で
    //           確定しようとする
    // 期待する結果：どれも 400 { error: 'failed' }。協力者は、持ち主が確定するまで協力者にならない
    // plan 11章：テスト6
    const owner = await newApprover(t);
    const helper = await newApprover(t);
    const attacker = await newApprover(t);
    const invite = await owner.approval.post('/api/helpers/invite');
    const code = invite.json.code;
    expect((await owner.approval.post('/api/helpers/accept', { code })).json).toEqual(FAILED);
    expect((await helper.approval.post('/api/helpers/accept', { code })).status).toBe(200);
    expect((await attacker.approval.post('/api/helpers/accept', { code })).json).toEqual(FAILED);
    expect((await helper.approval.post('/api/helpers/confirm/options', { code })).json).toEqual(
      FAILED,
    );
    expect((await owner.approval.get('/api/recovery/settings')).json.helper).toBeNull();
    expect((await helper.approval.get('/api/recovery/settings')).json.helping).toEqual([]);
    expect((await bound(owner.approval, '/api/helpers/confirm', { code })).status).toBe(200);
    expect((await helper.approval.get('/api/recovery/settings')).json.helping).toHaveLength(1);
    // 確定した招待は消える（同じコードで、もう一度確定できない）。
    expect((await owner.approval.post('/api/helpers/confirm/options', { code })).json).toEqual(
      FAILED,
    );
  });

  it('協力者の承認は、承認用のオリジンで、UV 付きのパスキーで、1回だけ。期限を過ぎた結び付けのコードは使えない', async () => {
    // 攻撃者が持っている情報：結び付けのコードと、協力者の画面を偽のオリジンに中継する手段、UV なしで鍵を使える手段
    // 試す経路：協力者のアサーションを PWA のオリジンで作る。UV なしで作る。承認の後に、同じコードでもう一度承認する。
    //           10分を過ぎた結び付けのコードで承認する
    // 期待する結果：オリジン違いと UV なしは 401。2回目と期限切れは 400 { error: 'failed' }
    // plan 11章：テスト6
    const { helper, code } = await ownerWithHelper();
    const device = await startOnNewDevice(t, code);
    const binding = bindingCodeOf(device.register);
    expect(
      (
        await bound(
          helper.approval,
          '/api/recovery/helper',
          { code: binding },
          { origin: t.origin },
        )
      ).status,
    ).toBe(401);
    expect(
      (await bound(helper.approval, '/api/recovery/helper', { code: binding }, { uv: false }))
        .status,
    ).toBe(401);
    expect((await helperApprove(helper.approval, binding)).status).toBe(200);
    const again = await helperApprove(helper.approval, binding);
    expect(again.status).toBe(400);
    expect(again.json).toEqual(FAILED);

    const second = await ownerWithHelper();
    const other = await startOnNewDevice(t, second.code);
    const stale = bindingCodeOf(other.register);
    clock += 10 * 60_000 + 1000;
    expect((await second.helper.approval.approvalLogin()).status).toBe(200);
    expect((await helperApprove(second.helper.approval, stale)).json).toEqual(FAILED);
    // 新しい端末で読み直すと、新しい結び付けのコードが出る（前のコードは使えない）。
    const fresh = bindingCodeOf(await resume(other.browser));
    expect(fresh).not.toBe(stale);
    expect((await helperApprove(second.helper.approval, fresh)).status).toBe(200);
  });

  it('承認用のセッションのない要求は、新しい端末のルートを除いて、どれも 401', async () => {
    // 攻撃者が持っている情報：何もない（ログインしていないブラウザ）
    // 試す経路：持ち主と協力者のルートを、セッションなしで呼ぶ
    // 期待する結果：どれも 401
    // plan 11章：テスト6
    const anonymous = new Browser(t.approvalOrigin);
    expect((await anonymous.get('/api/recovery/settings')).status).toBe(401);
    for (const path of [
      '/api/recovery-code/options',
      '/api/recovery-code/verify',
      '/api/helpers/invite',
      '/api/helpers/invite/status',
      '/api/helpers/confirm/options',
      '/api/helpers/confirm/verify',
      '/api/helpers/remove/options',
      '/api/helpers/remove/verify',
      '/api/helpers/accept',
      '/api/recovery/helper/view',
      '/api/recovery/helper/options',
      '/api/recovery/helper/verify',
      '/api/recovery/cancel/options',
      '/api/recovery/cancel/verify',
    ]) {
      expect((await anonymous.post(path, { code: newShortCode() })).status).toBe(401);
    }
  });
});

describe('漏えい：回復と協力者のレート制限（plan 11章 テスト6、ADR 0027 の O-84）', () => {
  it('回復の開始は、IP ごとに1時間に10回、コードの利用者ごとに1時間に5回まで', async () => {
    // 攻撃者が持っている情報：利用者 ID（を含むコードの形）と、秘密を総当たりする手段
    // 試す経路：同じ IP から、形の違うコードを続けて送る。時計を進めてから、同じ利用者の秘密の違うコードを続けて送る
    // 期待する結果：IP では11回目、利用者では6回目から 429 { error: 'rate_limited' }
    // plan 11章：テスト6
    const browser = new Browser(t.approvalOrigin);
    for (let i = 0; i < 10; i += 1) {
      expect((await browser.post('/api/recovery/start', { code: `x${i}` })).status).toBe(400);
    }
    const limited = await browser.post('/api/recovery/start', { code: 'x' });
    expect(limited.status).toBe(429);
    expect(limited.json).toEqual(RATE_LIMITED);

    clock += 2 * HOUR;
    const owner = await newApprover(t);
    for (let i = 0; i < 5; i += 1) {
      const code = formatRecoveryCode(owner.userId, randomBytes(10));
      expect((await browser.post('/api/recovery/start', { code })).status).toBe(400);
    }
    const byUser = await browser.post('/api/recovery/start', {
      code: formatRecoveryCode(owner.userId, randomBytes(10)),
    });
    expect(byUser.status).toBe(429);
  });

  it('招待の受け入れと結び付けのコードの入力は、利用者ごとに10分に10回まで。招待と回復コードの作成は1時間に5回まで', async () => {
    // 攻撃者が持っている情報：自分のアカウント（招待コードと結び付けのコードを総当たりしたい）
    // 試す経路：招待の受け入れと協力者の画面に、乱数のコードを続けて送る。招待と回復コードを続けて作る
    // 期待する結果：コードの入力は11回目から、作成は6回目から 429
    // plan 11章：テスト6
    const user = await newApprover(t);
    for (let i = 0; i < 10; i += 1) {
      const path = i % 2 === 0 ? '/api/helpers/accept' : '/api/recovery/helper/view';
      expect((await user.approval.post(path, { code: newShortCode() })).status).toBe(400);
    }
    expect((await user.approval.post('/api/helpers/accept', { code: newShortCode() })).status).toBe(
      429,
    );

    for (let i = 0; i < 5; i += 1) {
      expect((await user.approval.post('/api/helpers/invite')).status).toBe(200);
    }
    expect((await user.approval.post('/api/helpers/invite')).status).toBe(429);
    for (let i = 0; i < 5; i += 1) {
      expect((await user.approval.post('/api/recovery-code/options')).status).toBe(200);
    }
    expect((await user.approval.post('/api/recovery-code/options')).status).toBe(429);
  });
});
