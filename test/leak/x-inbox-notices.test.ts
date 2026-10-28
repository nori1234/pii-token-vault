// 全端末への知らせと、受信箱の保存期間（plan 4章「予防」「通知」、spec 03 の TH-26・TH-27、ADR 0018、ADR 0023）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TenantId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover, PICKUP_DETAILS, TEST_DEVICE_TYPE, userIdOf } from '../setup/approvals.ts';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { SoftAuthenticator } from '../setup/soft-authenticator.ts';

let t: TestIdp;
let clock = Date.now();
const DAY = 24 * 60 * 60 * 1000;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock), {
    approvalTypes: [TEST_DEVICE_TYPE],
  });
});

afterAll(async () => {
  await t.stop();
});

interface Entry {
  id: string;
  kind: string;
  title: string;
  state: string;
  lines?: { label: string; value: string }[];
}

async function inbox(browser: Browser): Promise<Entry[]> {
  const result = await browser.get('/api/inbox');
  expect(result.status).toBe(200);
  return result.json.items as Entry[];
}

describe('漏えい：全端末への知らせ（受信箱）', () => {
  it('パスキーの追加と削除、メールの登録と変更は、ほかの端末の受信箱にも届く', async () => {
    // 攻撃者が持っている情報：一度だけ得た利用者のセッション（認証から5分以内。盗んだクッキー）。パスキーを足して
    //                         居座る（TH-26）か、割符に登録したメールを書き換えて知らせを奪う（TH-27）
    // 試す経路：盗んだセッションで、攻撃者の認証器のパスキーを足し、メールアドレスを登録して変える
    // 期待する結果：利用者の別の端末（別のセッション）の受信箱に、それぞれの知らせが未読で届く。利用者がそのパスキーを
    //               消すと、その知らせも届く。中身は型が決めた文言（と、同期パスキーか端末固定か）だけで、
    //               メールアドレスは入らない
    // plan 11章：番号なし（plan 4章「パスキーの追加と削除には step-up を求め、全端末に知らせる」。ADR 0018 の
    //            「全端末への知らせは M6 で足す」）
    const owner = new Browser(t.origin);
    expect((await owner.registerAccount()).status).toBe(200);
    const userId = userIdOf(owner.authenticator);
    const stolen = new Browser(t.origin, new SoftAuthenticator(t.origin));
    for (const [name, value] of owner.cookies) stolen.cookies.set(name, value);
    const options = await stolen.post('/api/passkeys/options');
    const added = await stolen.post('/api/passkeys/verify', {
      ceremonyId: options.json.ceremonyId,
      response: stolen.authenticator.create(options.json.options as never),
    });
    expect(added.status).toBe(200);
    const address = `n${Date.now()}@example.test`;
    for (const email of [address, `x${address}`]) {
      // 一覧の順（作った時刻の新しい順）を決めるため、操作ごとに時計を1秒進める。
      clock += 1000;
      expect((await stolen.post('/api/email/start', { email })).status).toBe(202);
      const message = t.outbox.lastFor(userId, 'email_verification');
      const code = message?.kind === 'email_verification' ? message.code : undefined;
      expect((await stolen.post('/api/email/confirm', { code })).status).toBe(200);
    }

    const login = async () => {
      const device = new Browser(t.origin, owner.authenticator);
      const o = await device.post('/api/login/options');
      const verified = await device.post('/api/login/verify', {
        ceremonyId: o.json.ceremonyId,
        response: owner.authenticator.get(o.json.options as never),
      });
      expect(verified.status).toBe(200);
      return device;
    };
    const otherDevice = await login();
    expect((await inbox(otherDevice)).map((item) => [item.title, item.state]).reverse()).toEqual([
      ['パスキーが追加されました', 'unread'],
      ['メールアドレスが登録されました', 'unread'],
      ['メールアドレスが変更されました', 'unread'],
    ]);
    const passkeys = (await otherDevice.get('/api/me')).json.passkeys as { id: string }[];
    const stolenCredential = stolen.authenticator.credentials.at(-1);
    const attackerKey = Buffer.from(stolenCredential?.id ?? []).toString('base64url');
    expect(passkeys.map((p) => p.id)).toContain(attackerKey);
    clock += 1000;
    expect((await otherDevice.post('/api/passkeys/delete', { id: attackerKey })).status).toBe(200);
    const items = await inbox(await login());
    expect(items.map((item) => [item.kind, item.title, item.state]).reverse()).toEqual([
      ['notice', 'パスキーが追加されました', 'unread'],
      ['notice', 'メールアドレスが登録されました', 'unread'],
      ['notice', 'メールアドレスが変更されました', 'unread'],
      ['notice', 'パスキーが削除されました', 'unread'],
    ]);
    expect(items.at(-1)?.lines).toEqual([{ label: '種類', value: '同期パスキー' }]);
    expect(JSON.stringify(items)).not.toContain('example.test');
  });

  it('知らせは既読にでき、保存期間を過ぎた項目は、次に受信箱を読むときに消える', async () => {
    // 攻撃者が持っている情報：DB の写し（ATK-07）。古い受信箱の項目から、利用者の行動の記録を集めたい
    // 試す経路：知らせを既読にする。時計を進めて、承認待ちは期限の30日後、知らせは90日後を過ぎてから受信箱を読む
    // 期待する結果：既読は1回だけ通る。保存期間を過ぎた項目は、一覧からも DB からも消える（ADR 0023 の保存期間）
    // plan 11章：番号なし（plan 8章「保存するものごとに保存期間を決め、過ぎたら消す」）
    const u = await newApprover(t);
    const options = await u.pwa.post('/api/passkeys/options');
    const second = new SoftAuthenticator(t.origin);
    await u.pwa.post('/api/passkeys/verify', {
      ceremonyId: options.json.ceremonyId,
      response: second.create(options.json.options as never),
    });
    const requested = await t.idp.requestApproval({
      userId: u.userId,
      tenantId: t.tenants[0]?.tenantId as TenantId,
      type: TEST_DEVICE_TYPE.type,
      details: PICKUP_DETAILS,
      ttlSeconds: 60,
    });
    expect(requested.ok).toBe(true);
    const notice = (await inbox(u.pwa)).find((item) => item.kind === 'notice');
    expect((await u.pwa.post('/api/inbox/read', { id: notice?.id })).status).toBe(200);
    expect((await u.pwa.post('/api/inbox/read', { id: notice?.id })).status).toBe(400);
    expect((await inbox(u.pwa)).find((item) => item.id === notice?.id)?.state).toBe('read');

    // セッションの期限を避けるため、時計を進めるたびにログインし直す。
    const fresh = async () => {
      const b = new Browser(t.origin, u.pwa.authenticator);
      const o = await b.post('/api/login/options');
      await b.post('/api/login/verify', {
        ceremonyId: o.json.ceremonyId,
        response: u.pwa.authenticator.get(o.json.options as never),
      });
      return b;
    };
    clock += 31 * DAY;
    expect((await inbox(await fresh())).map((item) => item.kind)).toEqual(['notice']);
    clock += 60 * DAY;
    expect(await inbox(await fresh())).toEqual([]);
  });
});
