// テスト10（登録時の応答。plan 11章、不変条件10）と、本物のメールの登録・変更（plan 4章、不変条件3・4）。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { MailRequest } from '../../packages/idp/src/mailer.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { createRelayKeyClient } from '../../packages/warifu-core/src/keys/relay.ts';
import { rawRoleClient, relayDb } from '../setup/db.ts';
import { Browser, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { keysvcConnection } from '../setup/keys.ts';

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock));
});

afterAll(async () => {
  await t.stop();
});

const address = () => `${randomBytes(6).toString('hex')}@example.com`;

/** 送信の上限（利用者ごとに15分に3回）と step-up（5分）を越えるため、時計を進めてから step-up する。 */
async function freshWindow(browser: Browser): Promise<void> {
  clock += 16 * 60 * 1000;
  expect((await browser.stepUp()).status).toBe(200);
}

async function userIdOf(browser: Browser): Promise<string> {
  const handle = browser.authenticator.credentials[0]?.userHandle ?? '';
  const hex = Buffer.from(handle, 'base64url').toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function codeFrom(message: MailRequest | undefined): string {
  if (message?.kind !== 'email_verification') throw new Error('確認コードのメールがない');
  return message.code;
}

describe('漏えい：メールの登録で、登録済みかどうかが分からない（plan 11章 テスト10）', () => {
  it('ほかのアカウントで使われているアドレスでも、新しいアドレスでも、応答の本文とステータスが同じ', async () => {
    // 攻撃者が持っている情報：漏れたメールアドレスの一覧。割符のアカウントを自分で作れる
    // 試す経路：自分のアカウントで、ほかの人が登録済みのアドレスと、だれも使っていないアドレスの登録を始める
    // 期待する結果：どちらも 202 { status: 'sent' }。所要時間の中央値の差は小さい（100ミリ秒未満）
    // plan 11章：テスト10
    const victim = new Browser(t.origin);
    expect((await victim.registerAccount()).status).toBe(200);
    const taken = address();
    expect((await victim.post('/api/email/start', { email: taken })).status).toBe(202);
    const victimId = await userIdOf(victim);
    const code = codeFrom(t.outbox.lastFor(victimId as never, 'email_verification'));
    expect((await victim.post('/api/email/confirm', { code })).status).toBe(200);

    const attacker = new Browser(t.origin);
    expect((await attacker.registerAccount()).status).toBe(200);
    const timings: Record<'taken' | 'fresh', number[]> = { taken: [], fresh: [] };
    const bodies = new Set<string>();
    for (let round = 0; round < 4; round += 1) {
      await freshWindow(attacker);
      for (const kind of ['taken', 'fresh', 'taken'] as const) {
        const started = performance.now();
        const result = await attacker.post('/api/email/start', {
          email: kind === 'taken' ? taken : address(),
        });
        timings[kind].push(performance.now() - started);
        expect(result.status).toBe(202);
        bodies.add(result.text);
      }
    }
    expect([...bodies]).toEqual([JSON.stringify({ status: 'sent' })]);
    const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;
    expect(Math.abs(median(timings.taken) - median(timings.fresh))).toBeLessThan(100);
  });
});

describe('本物のメールの登録と変更（plan 4章）', () => {
  it('宛先確認の後だけ登録され、DB には暗号文だけが残り、復号できるのは relay だけ', async () => {
    // 攻撃者が持っている情報：DB の中身（アプリのロールで読める範囲）
    // 試す経路：登録を始め、コードを入れる前と後に、contacts の表を読む。relay の鍵で暗号文を復号する
    // 期待する結果：確認前は contacts.email が空。確認後は暗号文だけがあり、平文のアドレスもコードも含まない。
    //               relay の鍵で、その利用者の文脈で復号すると元のアドレスになる
    // plan 11章：テスト7 の一部（平文を残さない）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const userId = await userIdOf(browser);
    const email = address();
    expect((await browser.post('/api/email/start', { email })).status).toBe(202);
    const code = codeFrom(t.outbox.lastFor(userId as never, 'email_verification'));
    expect(code).toMatch(/^[0-9]{8}$/);

    const relay = await relayDb();
    try {
      const read = (table: 'email' | 'email_pending') =>
        relay.withWarifuUser(userId as never, (tx) =>
          tx.query<{ ciphertext: Uint8Array }>(
            table === 'email'
              ? sql`SELECT ciphertext FROM contacts.email`
              : sql`SELECT ciphertext FROM contacts.email_pending`,
          ),
        );
      expect(await read('email')).toHaveLength(0);
      expect(await read('email_pending')).toHaveLength(1);
      expect((await browser.post('/api/email/confirm', { code })).status).toBe(200);
      const [stored] = await read('email');
      if (stored === undefined) throw new Error('登録されていない');
      const raw = Buffer.from(stored.ciphertext);
      expect(raw.includes(Buffer.from(email))).toBe(false);
      const keys = createRelayKeyClient(keysvcConnection('relay'));
      const plain = await keys.decryptContact({
        userId: userId as never,
        ciphertext: new Uint8Array(raw),
      });
      expect(Buffer.from(plain).toString('utf8')).toBe(email);
      expect(await read('email_pending')).toHaveLength(0);
    } finally {
      await relay.close();
    }

    // アプリのロールの生の接続で、平文のアドレスとコードを探す（境界を自分で設定して読める範囲）。
    const client = await rawRoleClient('warifu_idp');
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_catalog.set_config('warifu.user_id', $1, true)", [userId]);
      const dump = JSON.stringify(
        (await client.query('SELECT * FROM contacts.email')).rows.concat(
          (await client.query('SELECT * FROM idp.credentials')).rows,
          (await client.query('SELECT * FROM audit.events WHERE user_id = $1', [userId])).rows,
        ),
      );
      expect(dump).not.toContain(email);
      expect(dump).not.toContain(code);
      await client.query('ROLLBACK');
    } finally {
      await client.end();
    }
  });

  it('コードの照合は5回まで。違うコードでは登録されず、変更したら旧アドレスに知らせる（リンクもコードも無い）', async () => {
    // 攻撃者が持っている情報：利用者のセッション（盗んだ端末など）。確認コードは知らない
    // 試す経路：違うコードを5回入れてから、正しいコードを入れる。別の機会に、正しい手順でアドレスを変える
    // 期待する結果：違うコードは 400 { error: 'failed' }。5回の後は、正しいコードでも登録されない。
    //               変更の後、旧アドレスあての知らせ（email_changed_notice）が1件。知らせにはコードが無い
    // plan 11章：番号なし（plan 4章「本物のメール」）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    const userId = await userIdOf(browser);
    expect((await browser.post('/api/email/start', { email: address() })).status).toBe(202);
    const code = codeFrom(t.outbox.lastFor(userId as never, 'email_verification'));
    const wrong = code === '00000000' ? '11111111' : '00000000';
    for (let i = 0; i < 5; i += 1) {
      const result = await browser.post('/api/email/confirm', { code: wrong });
      expect(result.status).toBe(400);
      expect(result.json).toEqual({ error: 'failed' });
    }
    expect((await browser.post('/api/email/confirm', { code })).status).toBe(400);
    expect((await browser.get('/api/me')).json.email).toMatchObject({ registered: false });

    await freshWindow(browser);
    expect((await browser.post('/api/email/start', { email: address() })).status).toBe(202);
    const first = codeFrom(t.outbox.lastFor(userId as never, 'email_verification'));
    expect((await browser.post('/api/email/confirm', { code: first })).status).toBe(200);
    expect(t.outbox.lastFor(userId as never, 'email_changed_notice')).toBeUndefined();
    expect((await browser.post('/api/email/start', { email: address() })).status).toBe(202);
    const second = codeFrom(t.outbox.lastFor(userId as never, 'email_verification'));
    expect((await browser.post('/api/email/confirm', { code: second })).status).toBe(200);
    const notice = t.outbox.lastFor(userId as never, 'email_changed_notice');
    expect(notice).toEqual({ kind: 'email_changed_notice', userId });
  });

  it('メールの登録には step-up（5分以内の認証）が要る', async () => {
    // 攻撃者が持っている情報：利用者の PWA のセッション（認証から5分以上たったもの）
    // 試す経路：時計を進めてから、メールの登録を始める
    // 期待する結果：401 { error: 'reauth_required' }。パスキーで step-up した後は 202
    // plan 11章：番号なし（plan 4章「本物のメール」、DESIGN.md 2章）
    const browser = new Browser(t.origin);
    expect((await browser.registerAccount()).status).toBe(200);
    clock += 6 * 60 * 1000;
    const stale = await browser.post('/api/email/start', { email: address() });
    expect(stale.status).toBe(401);
    expect(stale.json).toEqual({ error: 'reauth_required' });
    expect((await browser.stepUp()).status).toBe(200);
    expect((await browser.post('/api/email/start', { email: address() })).status).toBe(202);
  });
});
