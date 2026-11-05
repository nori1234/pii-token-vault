// 回復（plan 11章 テスト3、plan 4章、ADR 0003、ADR 0027）。回復は、回復コード、協力者の承認、待機の満了の
// 3つがそろったときだけ成立する（不変条件1(b)）。時間は、idp に渡した時計（clock）を進めて確かめる
// （plan 11章の「ハーネスが時間を進める」。DB の時刻を書き換えずに、idp の時刻だけを進める）。
// 企業への知らせ（recovered_at と回復の SET）は t03-recovery-companies で確かめる。

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { FAILED, RESTRICTED } from '../../packages/idp/src/http.ts';
import { type ApprovalType, NOTICE_TYPES } from '../../packages/idp/src/inbox.ts';
import { collectHelperNotices } from '../../packages/idp/src/recovery.ts';
import type { RepoDeps } from '../../packages/idp/src/repo.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { TenantId, WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import {
  newApprover,
  PICKUP_DETAILS,
  TEST_DEVICE_TYPE,
  TEST_REQUEST_DEVICE,
} from '../setup/approvals.ts';
import { serviceDb } from '../setup/db.ts';
import { pwaLogin } from '../setup/desk.ts';
import {
  actOnInteraction,
  Browser,
  startAuthorization,
  startTestIdp,
  type TestIdp,
} from '../setup/idp.ts';
import {
  bindingCodeOf,
  bound,
  cancelRecovery,
  helperApprove,
  issueCode,
  makeHelper,
  resume,
  startOnNewDevice,
} from '../setup/recovery.ts';

const HOUR = 3600_000;
const DAY = 24 * HOUR;

/** 高リスクの操作の型（テストの型。P0 の製品には、まだ高リスクの型はない。ADR 0027 の O-80）。 */
const HIGH_RISK_TYPE: ApprovalType = {
  ...TEST_DEVICE_TYPE,
  type: 'test.refund_change',
  operation: '返金先の変更',
  highRisk: true,
};

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
    approvalTypes: [TEST_DEVICE_TYPE, HIGH_RISK_TYPE],
  });
});

afterAll(async () => {
  await t?.stop();
});

// 回復の開始のレート制限（IP ごとに1時間に10）を、テストごとに持ち越さない。
beforeEach(() => {
  clock += 2 * HOUR;
});

function title(type: keyof typeof NOTICE_TYPES): string {
  return NOTICE_TYPES[type].title;
}

/** PWA の受信箱の知らせの見出し（セッションが切れていれば、パスキーでログインし直す）。 */
async function titles(pwa: Browser): Promise<string[]> {
  let inbox = await pwa.get('/api/inbox');
  if (inbox.status === 401) {
    expect((await pwaLogin(pwa)).status).toBe(200);
    inbox = await pwa.get('/api/inbox');
  }
  expect(inbox.status).toBe(200);
  return (inbox.json.items as { kind: string; title: string }[])
    .filter((item) => item.kind === 'notice')
    .map((item) => item.title);
}

/** 承認用のオリジンのセッションが切れていれば、パスキーでログインし直す。 */
async function ensureApproval(approval: Browser): Promise<void> {
  if ((await approval.get('/api/recovery/settings')).status === 401) {
    expect((await approval.approvalLogin()).status).toBe(200);
  }
}

/** 回復コードと協力者を持つ持ち主と、その協力者。 */
async function ownerWithHelper() {
  const owner = await newApprover(t);
  const helper = await newApprover(t);
  const code = await issueCode(owner.approval);
  const relationshipId = await makeHelper(owner.approval, helper.approval);
  return { owner, helper, code, relationshipId };
}

/** 回復を最後まで進める（開始、協力者の承認、72時間の待機、成立）。 */
async function recoverAll(code: string, helper: Browser) {
  const device = await startOnNewDevice(t, code);
  expect(device.register?.status).toBe(200);
  await ensureApproval(helper);
  const approved = await helperApprove(helper, bindingCodeOf(device.register));
  expect(approved.status).toBe(200);
  clock = Date.parse(String(approved.json.readyAt));
  const done = await resume(device.browser);
  expect(done.status).toBe(200);
  expect(done.json.state).toBe('completed');
  return { device: device.browser, completedAt: clock, newCode: String(done.json.recoveryCode) };
}

async function addPasskey(pwa: Browser): Promise<void> {
  const options = await pwa.post('/api/passkeys/options');
  expect(options.status).toBe(200);
  const response = pwa.authenticator.create(options.json.options as never);
  const added = await pwa.post('/api/passkeys/verify', {
    ceremonyId: options.json.ceremonyId,
    response,
  });
  expect(added.status).toBe(200);
}

function tenantId(): TenantId {
  const tenant = t.tenants[0];
  if (tenant === undefined) throw new Error('準備に失敗した');
  return tenant.tenantId as TenantId;
}

async function requestApproval(userId: WarifuUserId, type: ApprovalType): Promise<string> {
  const result = await t.idp.requestApproval({
    userId,
    tenantId: tenantId(),
    type: type.type,
    details: PICKUP_DETAILS,
    ttlSeconds: 300,
    device: TEST_REQUEST_DEVICE,
  });
  if (!result.ok) throw new Error('承認待ちを作れなかった');
  return result.itemId;
}

describe('漏えい：回復（plan 11章 テスト3）', () => {
  it('回復の画面と開始の API には、メール・電話・氏名の入力がない（回復コードだけで始める）', async () => {
    // 攻撃者が持っている情報：利用者の本物のメールアドレス、電話番号、氏名（漏えいした名簿）
    // 試す経路：回復の画面（新しい端末、回復の設定、協力者）を開き、入力欄を探す。開始の API に、メール、電話、氏名を
    //           送る。回復コードの欄に、メールアドレスを入れる
    // 期待する結果：画面に連絡先や氏名の入力欄がない。開始の API は、どれも 400 の固定の本文（FAILED）
    // plan 11章：テスト3
    const browser = new Browser(t.approvalOrigin);
    for (const path of ['/recover', '/recovery', '/helper']) {
      const page = await browser.get(path);
      expect(page.status).toBe(200);
      // カメラを許すのは、QR を読み取る協力者の画面だけ（同じオリジンだけ。ADR 0027 の O-82）。
      expect(page.headers.get('permissions-policy')).toBe(
        path === '/helper'
          ? 'camera=(self), microphone=(), geolocation=()'
          : 'camera=(), microphone=(), geolocation=()',
      );
      expect(page.text).not.toMatch(/type="(email|tel)"/i);
      expect(page.text).not.toMatch(/autocomplete="[^"]*(email|tel|name)[^"]*"/i);
      expect(page.text).not.toMatch(/name="(email|phone|tel|name)"/i);
    }
    for (const body of [
      { email: 'leaked@example.com' },
      { phone: '09012345678' },
      { name: '割符 太郎', birthdate: '1990-01-01' },
      { code: 'leaked@example.com' },
      { code: '09012345678' },
      {},
    ]) {
      const result = await browser.post('/api/recovery/start', body);
      expect(result.status).toBe(400);
      expect(result.json).toEqual(FAILED);
    }
  });

  it('回復コードだけでは回復できない（協力者が承認しなければ、待っても成立せず、24時間で期限が切れる）', async () => {
    // 攻撃者が持っている情報：盗んだ回復コード（協力者の承認は得られない）
    // 試す経路：新しい端末で回復を始め、回復待ちのパスキーで状態を読み直す。そのパスキーで、PWA と承認用のオリジンに
    //           ログインする。待機の長さ（72時間）を過ぎてから、もう一度読み直す
    // 期待する結果：始めることはできるが、状態は協力者の承認待ちのまま。回復待ちのパスキーではログインできない（401）。
    //               24時間で期限が切れ、回復待ちのパスキーは消える（読み直しは 401）。持ち主の端末と協力者に知らせが
    //               届き、持ち主のパスキーはそのまま使える
    // plan 11章：テスト3
    const { owner, helper, code } = await ownerWithHelper();
    const device = await startOnNewDevice(t, code);
    expect(device.start.status).toBe(200);
    expect(device.register?.status).toBe(200);
    expect(device.register?.json.state).toBe('awaiting_helper');
    bindingCodeOf(device.register);

    const again = await resume(device.browser);
    expect(again.status).toBe(200);
    expect(again.json.state).toBe('awaiting_helper');
    expect((await device.browser.approvalLogin()).status).toBe(401);
    expect((await pwaLogin(new Browser(t.origin, device.browser.authenticator))).status).toBe(401);

    const inbox = await owner.pwa.get('/api/inbox');
    expect((inbox.json.recovery as { state: string }).state).toBe('awaiting_helper');
    expect(await titles(owner.pwa)).toContain(title('recovery.started'));
    expect(await titles(helper.pwa)).toContain(title('helper.recovery_started'));

    clock += 72 * HOUR + 1000;
    expect((await resume(device.browser)).status).toBe(401);
    expect((await resume(device.browser)).status).toBe(401);
    expect(await titles(owner.pwa)).toContain(title('recovery.expired'));
    expect((await owner.pwa.get('/api/inbox')).json.recovery).toBeNull();
    expect((await owner.approval.approvalLogin()).status).toBe(200);
  });

  it('回復コードと協力者の承認がそろうと待機に入り、待機を終えてから成立する。成立すると前のコードと前の端末は使えない', async () => {
    // 攻撃者が持っている情報：回復の前の回復コードと、回復の前の端末（PWA と承認用のオリジンのセッション、パスキー）
    // 試す経路：持ち主が新しい端末で回復する（協力者が承認し、72時間待つ）。待機の途中で成立させようとする。成立の後に、
    //           前のコードで回復を始め、前の端末のセッションとパスキーで、PWA と承認用のオリジンを使う
    // 期待する結果：待機の途中は waiting（成立しない）。待機を終えると成立し、新しい回復コードが1回だけ返る。前のコードは
    //               400、前の端末のセッションは 401、前のパスキーは一時停止でログインできない（401）。新しい端末は
    //               承認用のオリジンにログインした状態で、PWA にもログインできる。持ち主と協力者の受信箱に知らせが届く
    // plan 11章：テスト3
    const { owner, helper, code } = await ownerWithHelper();
    const device = await startOnNewDevice(t, code);
    const approved = await helperApprove(helper.approval, bindingCodeOf(device.register));
    expect(approved.status).toBe(200);
    const readyAt = Date.parse(String(approved.json.readyAt));
    expect(readyAt - clock).toBe(72 * HOUR);
    expect((await resume(device.browser)).json).toEqual({
      state: 'waiting',
      readyAt: new Date(readyAt).toISOString(),
    });
    expect(await titles(owner.pwa)).toContain(title('recovery.approved'));

    clock = readyAt - 1000;
    expect((await resume(device.browser)).json.state).toBe('waiting');
    clock = readyAt;
    const done = await resume(device.browser);
    expect(done.status).toBe(200);
    expect(done.json.state).toBe('completed');
    const newCode = String(done.json.recoveryCode);
    expect(newCode).not.toBe(code);
    expect(newCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{1,6}){6}$/);
    // 回復待ちだったパスキーは有効になったので、もう回復の読み直しには使えない。
    expect((await resume(device.browser)).status).toBe(401);

    expect((await startOnNewDevice(t, code)).start.status).toBe(400);
    expect((await owner.pwa.get('/api/inbox')).status).toBe(401);
    expect((await owner.approval.get('/api/recovery/settings')).status).toBe(401);
    expect((await owner.approval.approvalLogin()).status).toBe(401);
    expect((await pwaLogin(owner.pwa)).status).toBe(401);

    const settings = await device.browser.get('/api/recovery/settings');
    expect(settings.status).toBe(200);
    expect(settings.json.restrictedUntil).toBe(new Date(readyAt + 7 * DAY).toISOString());
    expect((settings.json.code as { createdAt: string }).createdAt).toBe(
      new Date(readyAt).toISOString(),
    );
    const pwa = new Browser(t.origin, device.browser.authenticator);
    expect((await pwaLogin(pwa)).status).toBe(200);
    const ownerTitles = await titles(pwa);
    expect(ownerTitles).toContain(title('recovery.completed'));
    expect(ownerTitles).toContain(title('recovery.code_reissued'));
    const helperTitles = await titles(helper.pwa);
    expect(helperTitles).toContain(title('helper.recovery_completed'));
    expect(helperTitles).toContain(title('helper.code_reissued'));

    // 新しい回復コードは使える（協力者は変わらない）。
    const next = await startOnNewDevice(t, newCode);
    expect(next.register?.status).toBe(200);
  });

  it('直近14日以内にパスキーを足した協力者の承認は受け付けない（409）。14日を過ぎれば受け付ける', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウントに足した攻撃者のパスキー（協力者のなりすまし）
    // 試す経路：協力者のアカウントにパスキーを足してから、新しい端末に出た結び付けのコードで承認を試みる
    // 期待する結果：協力者の画面と儀式は 409 { error: 'helper_not_eligible' } で、回復は協力者の承認待ちのまま。
    //               14日を過ぎてから始め直した回復は承認できる
    // plan 11章：テスト3（PRN-87）
    const { helper, code } = await ownerWithHelper();
    await addPasskey(helper.pwa);
    const device = await startOnNewDevice(t, code);
    const binding = bindingCodeOf(device.register);
    const view = await helper.approval.post('/api/recovery/helper/view', { code: binding });
    expect(view.status).toBe(409);
    expect(view.json).toEqual({ error: 'helper_not_eligible' });
    const approve = await helperApprove(helper.approval, binding);
    expect(approve.status).toBe(409);
    expect(approve.json).toEqual({ error: 'helper_not_eligible' });
    expect((await resume(device.browser)).json.state).toBe('awaiting_helper');

    clock += 15 * DAY;
    await ensureApproval(helper.approval);
    const later = await startOnNewDevice(t, code);
    expect(later.register?.status).toBe(200);
    expect((await helperApprove(helper.approval, bindingCodeOf(later.register))).status).toBe(200);
  });

  it('パスキーを足してから消した協力者も、足してから14日は承認できない（409）', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウントに足した攻撃者のパスキー（協力者のなりすまし）
    // 試す経路：協力者のアカウントにパスキーを足し、足したパスキーを消してから（追加の行が残らない）、新しい端末に
    //           出た結び付けのコードで承認を試みる
    // 期待する結果：協力者の画面と儀式は 409 { error: 'helper_not_eligible' } で、回復は協力者の承認待ちのまま。
    //               足してから14日を過ぎれば承認できる（オーナーの5回目のレビュー）
    // plan 11章：テスト3（PRN-87）
    const { helper, code } = await ownerWithHelper();
    const addedAt = clock;
    await addPasskey(helper.pwa);
    const added = helper.pwa.authenticator.credentials[1];
    if (added === undefined) throw new Error('準備に失敗した');
    const deleted = await helper.pwa.post('/api/passkeys/delete', {
      id: Buffer.from(added.id).toString('base64url'),
    });
    expect(deleted.status).toBe(200);
    // 消したパスキーは、認証器からも外す（残った元のパスキーで、承認用のオリジンにログインし直す）。
    helper.pwa.authenticator.credentials.pop();
    const left = await serviceDb('idp');
    try {
      const rows = await left.withWarifuUser(helper.userId, (tx) =>
        tx.query(sql`SELECT credential_id FROM idp.credentials`),
      );
      expect(rows).toHaveLength(1);
    } finally {
      await left.close();
    }

    clock += 13 * DAY;
    await ensureApproval(helper.approval);
    const device = await startOnNewDevice(t, code);
    const binding = bindingCodeOf(device.register);
    const view = await helper.approval.post('/api/recovery/helper/view', { code: binding });
    expect(view.status).toBe(409);
    expect(view.json).toEqual({ error: 'helper_not_eligible' });
    const approve = await helperApprove(helper.approval, binding);
    expect(approve.status).toBe(409);
    expect(approve.json).toEqual({ error: 'helper_not_eligible' });
    expect((await resume(device.browser)).json.state).toBe('awaiting_helper');

    clock = addedAt + 15 * DAY;
    await ensureApproval(helper.approval);
    const later = await startOnNewDevice(t, code);
    expect(later.register?.status).toBe(200);
    expect((await helperApprove(helper.approval, bindingCodeOf(later.register))).status).toBe(200);
  });

  it('直近14日以内に回復した協力者の承認は受け付けない（409）', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウント（攻撃者が先に協力者のアカウントを回復で奪った）
    // 試す経路：協力者が自分の回復を成立させた直後に、持ち主の回復を承認する
    // 期待する結果：409 { error: 'helper_not_eligible' }
    // plan 11章：テスト3（PRN-87）
    const { helper, code } = await ownerWithHelper();
    const helperOfHelper = await newApprover(t);
    const helperCode = await issueCode(helper.approval);
    await makeHelper(helper.approval, helperOfHelper.approval);
    const recovered = await recoverAll(helperCode, helperOfHelper.approval);

    const device = await startOnNewDevice(t, code);
    const approve = await helperApprove(recovered.device, bindingCodeOf(device.register));
    expect(approve.status).toBe(409);
    expect(approve.json).toEqual({ error: 'helper_not_eligible' });
  });

  it('登録済みの端末で取り消すと、回復コードは失効し、14日間は回復を始められない', async () => {
    // 攻撃者が持っている情報：盗んだ回復コード（協力者もだまして承認させ、待機に入れた）
    // 試す経路：持ち主が登録済みの端末で取り消した後に、回復待ちのパスキーで読み直す。同じコードと、持ち主が作り直した
    //           コードで、回復を始め直す。回復待ちのパスキーで取り消しを試みる
    // 期待する結果：回復待ちのパスキーには承認用のセッションがなく、取消は 401。取消の後は、読み直しが 401、同じコードでの
    //               開始が 400、作り直したコードでも14日間は 400。14日を過ぎると始められる。持ち主の端末と協力者に
    //               知らせが届く
    // plan 11章：テスト3（PRN-89）
    const { owner, helper, code } = await ownerWithHelper();
    const device = await startOnNewDevice(t, code);
    expect((await helperApprove(helper.approval, bindingCodeOf(device.register))).status).toBe(200);
    const attempt = (await owner.approval.get('/api/recovery/settings')).json.attempt as {
      id: string;
      state: string;
    };
    expect(attempt.state).toBe('waiting');
    expect(
      (await device.browser.post('/api/recovery/cancel/options', { id: attempt.id })).status,
    ).toBe(401);

    expect((await cancelRecovery(owner.approval)).status).toBe(200);
    const cancelledAt = clock;
    expect((await resume(device.browser)).status).toBe(401);
    expect((await startOnNewDevice(t, code)).start.status).toBe(400);
    expect((await owner.approval.get('/api/recovery/settings')).json.code).toBeNull();
    const reissued = await issueCode(owner.approval);
    expect((await startOnNewDevice(t, reissued)).start.status).toBe(400);
    expect(await titles(owner.pwa)).toContain(title('recovery.cancelled'));
    expect(await titles(helper.pwa)).toContain(title('helper.recovery_cancelled'));

    clock = cancelledAt + 14 * DAY - 1000;
    expect((await startOnNewDevice(t, reissued)).start.status).toBe(400);
    clock = cancelledAt + 14 * DAY + 1000;
    expect((await startOnNewDevice(t, reissued)).register?.status).toBe(200);
  });

  it('回復の後7日間は、協力者の変更、パスキーの削除、メールの登録、高リスクの承認を受け付けない（409）', async () => {
    // 攻撃者が持っている情報：回復を成立させたアカウント（回復コードを盗み、協力者をだまし、持ち主が72時間気づかなかった）
    // 試す経路：回復の直後に、協力者の招待と削除、前のパスキーの削除、本物のメールの登録、高リスクの操作の承認を行う
    // 期待する結果：どれも 409 { error: 'restricted' }。高リスクの操作の拒否と、高リスクでない承認は受け付ける。
    //               7日を過ぎると受け付ける
    // plan 11章：テスト3（PRN-90）
    const { owner, helper, code } = await ownerWithHelper();
    const userId = owner.userId;
    const { device, completedAt } = await recoverAll(code, helper.approval);
    const pwa = new Browser(t.origin, device.authenticator);
    expect((await pwaLogin(pwa)).status).toBe(200);
    const oldPasskey = Buffer.from(owner.pwa.authenticator.credentials[0]?.id ?? []).toString(
      'base64url',
    );

    const invite = await device.post('/api/helpers/invite');
    expect(invite.status).toBe(409);
    expect(invite.json).toEqual(RESTRICTED);
    const removed = await bound(device, '/api/helpers/remove');
    expect(removed.status).toBe(409);
    expect(removed.json).toEqual(RESTRICTED);
    const deleted = await pwa.post('/api/passkeys/delete', { id: oldPasskey });
    expect(deleted.status).toBe(409);
    expect(deleted.json).toEqual(RESTRICTED);
    const email = await pwa.post('/api/email/start', { email: 'after-recovery@example.com' });
    expect(email.status).toBe(409);
    expect(email.json).toEqual(RESTRICTED);

    const risky = await requestApproval(userId, HIGH_RISK_TYPE);
    const riskyOptions = await device.post('/api/approvals/decide/options', {
      id: risky,
      decision: 'approved',
    });
    expect(riskyOptions.status).toBe(409);
    expect(riskyOptions.json).toEqual(RESTRICTED);
    expect((await device.decide(risky, 'denied')).status).toBe(200);
    expect(
      (await device.decide(await requestApproval(userId, TEST_DEVICE_TYPE), 'approved')).status,
    ).toBe(200);

    clock = completedAt + 7 * DAY + 1000;
    expect((await device.approvalLogin()).status).toBe(200);
    expect((await pwaLogin(pwa)).status).toBe(200);
    expect((await device.post('/api/helpers/invite')).status).toBe(200);
    expect(
      (await pwa.post('/api/email/start', { email: 'after-recovery@example.com' })).status,
    ).toBe(202);
    expect(
      (await device.decide(await requestApproval(userId, HIGH_RISK_TYPE), 'approved')).status,
    ).toBe(200);
    expect((await pwa.post('/api/passkeys/delete', { id: oldPasskey })).status).toBe(200);
  });

  it('回復が成立すると、前の端末の OIDC のセッション（SSO）も消え、企業へのログインにパスキーが要る', async () => {
    // 攻撃者が持っている情報：回復の前に、持ち主の端末で企業へのログインを済ませたブラウザ（OIDC の SSO のセッション）
    // 試す経路：回復が成立した後に、そのブラウザで企業の認可の要求を始める
    // 期待する結果：インタラクションで、パスキーのログインを求められる（SSO のセッションで同意の画面へ進まない）。
    //               回復の前は、同じブラウザで同意の画面へ進む（SSO のセッションが生きていた）
    // plan 11章：テスト3（ADR 0027 の O-79。オーナーのレビュー）
    const short = await startTestIdp(
      { tenants: 1, clients: [{ tenant: 0 }] },
      () => new Date(clock),
      {
        recoveryWaitSeconds: 60,
      },
    );
    try {
      const client = short.clients[0];
      if (client === undefined) throw new Error('準備に失敗した');
      // 企業へのログインでアカウントを作り、接続は断る（OIDC のセッションだけが残る。接続がないので企業への知らせは要らない）。
      const old = new Browser(short.origin);
      const first = await startAuthorization(old, client);
      const registered = await actOnInteraction(old, first.followed.path, 'register');
      const consentPath = registered.followed?.path ?? '';
      expect(registered.followed?.last.text).toContain('data-prompt="consent"');
      await actOnInteraction(old, consentPath, 'decline');
      const before = await startAuthorization(old, client);
      expect(before.followed.last.text).toContain('data-prompt="consent"');

      const approval = new Browser(short.approvalOrigin, old.authenticator);
      expect((await approval.approvalLogin()).status).toBe(200);
      const helper = await newApprover(short);
      const code = await issueCode(approval);
      await makeHelper(approval, helper.approval);
      const device = await startOnNewDevice(short, code);
      expect((await helperApprove(helper.approval, bindingCodeOf(device.register))).status).toBe(
        200,
      );
      clock += 61_000;
      expect((await resume(device.browser)).json.state).toBe('completed');

      const after = await startAuthorization(old, client);
      expect(after.followed.external).toBeUndefined();
      expect(after.followed.path).toMatch(/^\/interaction\//);
      expect(after.followed.last.text).toContain('data-prompt="login"');
      expect(after.followed.last.text).not.toContain('data-prompt="consent"');
    } finally {
      await short.stop();
    }
  });

  it('協力者への知らせは、持ち主が何もしなくても、協力者が受信箱を読むと届く。移せなくても残り、1回だけ届く', async () => {
    // 攻撃者が持っている情報：盗んだ回復コード（持ち主は端末を使っていない。協力者に知らせが届かないことを期待する）
    // 試す経路：回復を始めた後、持ち主は何もしない。協力者の範囲の書き込みを失敗させてから、協力者が受信箱を読む。
    //           もう一度読む
    // 期待する結果：失敗しても、知らせは送信待ちに残る。協力者が受信箱を読むと、持ち主の操作なしに届く。同じ知らせは
    //               1つだけ。送信待ちは、持ち主の範囲からは読めない（協力者あての行は、協力者だけが読んで消す）
    // plan 11章：テスト3（ADR 0027 の O-79。オーナーの再レビュー）
    const { owner, helper, code } = await ownerWithHelper();
    const startedTitle = title('helper.recovery_started');
    const startedCount = async () =>
      (await titles(helper.pwa)).filter((t) => t === startedTitle).length;
    const before = await startedCount();
    const db = await serviceDb('idp');
    try {
      const pendingFor = (userId: WarifuUserId) =>
        db.withWarifuUser(userId, (tx) =>
          tx.query(sql`SELECT notice_id FROM idp.helper_notice_outbox`),
        );
      // 持ち主は、この後なにもしない（受信箱も回復の設定も読まない）。
      expect((await startOnNewDevice(t, code)).register?.status).toBe(200);
      expect(await pendingFor(helper.userId)).toHaveLength(1);
      expect(await pendingFor(owner.userId)).toHaveLength(0);

      const failing: RepoDeps = {
        db: {
          ...db,
          withWarifuUser: (() =>
            Promise.reject(
              new Error('書き込みの失敗（テスト）'),
            )) as RepoDeps['db']['withWarifuUser'],
        } as RepoDeps['db'],
        keys: undefined as never,
        now: () => new Date(clock),
      };
      await expect(collectHelperNotices(failing, helper.userId)).rejects.toThrow();
      expect(await pendingFor(helper.userId)).toHaveLength(1);

      expect(await startedCount()).toBe(before + 1);
      expect(await pendingFor(helper.userId)).toHaveLength(0);
      expect(await startedCount()).toBe(before + 1);
    } finally {
      await db.close();
    }
  });
});
