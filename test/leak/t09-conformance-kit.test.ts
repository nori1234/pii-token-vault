// テスト9：適合テストキット（plan 11章 テスト9、plan 3-3、spec 02 の 15-1、ADR 0010、ADR 0028 の O-104、ADR 0029）。
// 悪い振る舞いをする RP は作らない（ADR 0010）。キットが不合格にすることは、判定（judge）に作り物の観測を与えて示す。
// 観測を集める部分（collect）は、固定の値を返すフックを相手にして確かめる。作り物の観測とフックの値は、入力によらない
// 固定の値にし、メール、sub、別名を見て変えない（不変条件1 は、テストの補助にも適用する）。
// 確かめられるのは、キットの判定と、フックの応答から観測への写し方までで、悪い RP に端から端まで当てるところは示さない。

import { generateKeyPairSync } from 'node:crypto';
import { exportJWK, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import { createWarifuClient, RpKitError } from '../../packages/rp-kit/src/index.ts';
import {
  collect,
  createMockOp,
  judge,
  type KitParticipation,
  MOCK_OP_ORIGIN,
  type Observations,
  type RpTestHooks,
  runConformanceKit,
} from '../../packages/rp-kit/src/kit/index.ts';

const CLIENT_ID = 'kit-client';
const REDIRECT = 'https://company.example/callback';
const FULL: KitParticipation = { mode: 'full' };

/** 合格する観測（固定の値）。 */
const CLEAN: Observations = {
  sameAliasAccounts: ['account-1', 'account-2'],
  legacyLogin: 'refused',
  legacyReset: 'absent',
  linkAttack: 'refused',
  routes: [{ method: 'POST', path: '/orders/:id/cancel', tags: ['other'] }],
};

function statusOf(observations: Observations, participation: KitParticipation) {
  return Object.fromEntries(
    judge(observations, participation).results.map((r) => [r.check, r.status]),
  );
}

describe('テスト9：適合テストキット（ADR 0029）', () => {
  it('作り物の観測：別名でまとめた、旧経路が残る、紐付けの攻撃が通る、sub の書き換えやゲスト照会がある RP は不合格', () => {
    // 攻撃者が持っている情報：漏れたメール（別名を含む）と、自分の割符のアカウント
    // 試す経路：判定に、作り物の観測を与える（同じ内部のアカウント、旧ログインが通った、紐付けが通った、ルートの申告）
    // 期待する結果：完全な参加では、それぞれの検査が fail。合格の観測だけが pass
    // plan 11章：テスト9
    expect(judge(CLEAN, FULL).passed).toBe(true);
    const cases: [Partial<Observations>, string][] = [
      [{ sameAliasAccounts: ['account-1', 'account-1'] }, 'same_alias_two_subs'],
      [{ sameAliasAccounts: ['account-1', ''] }, 'same_alias_two_subs'],
      [{ legacyLogin: 'accepted' }, 'legacy_login'],
      [{ legacyReset: 'accepted' }, 'legacy_reset'],
      [{ linkAttack: 'linked' }, 'link_attack'],
      [
        { routes: [{ method: 'POST', path: '/admin/members/:id', tags: ['sub_rewrite'] }] },
        'sub_rewrite',
      ],
      [
        { routes: [{ method: 'POST', path: '/admin/accounts', tags: ['account_merge'] }] },
        'sub_rewrite',
      ],
      [
        { routes: [{ method: 'GET', path: '/orders/guest', tags: ['guest_lookup'] }] },
        'guest_lookup',
      ],
    ];
    for (const [change, check] of cases) {
      const report = judge({ ...CLEAN, ...change }, FULL);
      expect(report.passed).toBe(false);
      expect(report.results.find((r) => r.check === check)?.status).toBe('fail');
    }
  });

  it('移行中：閉じたと報告していない入り口の検査だけを緩め、閉じたと報告した入り口と、緩めない検査は不合格', () => {
    // 攻撃者が持っている情報：漏れたメールと、移行中の企業に残る旧経路
    // 試す経路：移行中の設定（閉じたと報告した入り口の組み合わせ）と、作り物の観測を判定に与える
    // 期待する結果：ENT-01・02・03 が開いていれば、対応する検査は relaxed。閉じたと報告していれば fail。
    //               同じ別名で sub の違う2人と、sub の書き換えは、どの設定でも fail（RP-15）
    // plan 11章：テスト9（ADR 0028 の O-104）
    const bad: Observations = {
      sameAliasAccounts: ['account-1', 'account-2'],
      legacyLogin: 'accepted',
      legacyReset: 'accepted',
      linkAttack: 'linked',
      routes: [{ method: 'GET', path: '/orders/guest', tags: ['guest_lookup'] }],
    };
    const open: KitParticipation = { mode: 'migrating', reportedClosed: [] };
    expect(statusOf(bad, open)).toEqual({
      same_alias_two_subs: 'pass',
      legacy_login: 'relaxed',
      legacy_reset: 'relaxed',
      link_attack: 'relaxed',
      sub_rewrite: 'pass',
      guest_lookup: 'relaxed',
    });
    expect(judge(bad, open).passed).toBe(true);
    const closed: KitParticipation = {
      mode: 'migrating',
      reportedClosed: ['ENT-01', 'ENT-02', 'ENT-03'],
    };
    expect(statusOf(bad, closed)).toEqual({
      same_alias_two_subs: 'pass',
      legacy_login: 'fail',
      legacy_reset: 'fail',
      link_attack: 'fail',
      sub_rewrite: 'pass',
      guest_lookup: 'fail',
    });
    const partly: KitParticipation = { mode: 'migrating', reportedClosed: ['ENT-02'] };
    expect(statusOf(bad, partly)).toMatchObject({ legacy_login: 'fail', legacy_reset: 'relaxed' });
    for (const participation of [open, closed]) {
      const merged = judge(
        { ...bad, sameAliasAccounts: ['account-1', 'account-1'] },
        participation,
      );
      expect(merged.results.find((r) => r.check === 'same_alias_two_subs')?.status).toBe('fail');
      const rewrite = judge(
        { ...bad, routes: [{ method: 'POST', path: '/admin/members/:id', tags: ['sub_rewrite'] }] },
        participation,
      );
      expect(rewrite.results.find((r) => r.check === 'sub_rewrite')?.status).toBe('fail');
    }
  });

  it('観測を集める部分：固定の値を返すフックの応答を、そのまま観測に写す。ログインの例外は検査できなかったことにする', async () => {
    // 攻撃者が持っている情報：なし（集める部分の写し方を、固定の応答で確かめる）
    // 試す経路：どの利用者にも同じ参照を返すフック、2人目で例外を投げるフックを collect に渡す
    // 期待する結果：観測は、フックの値と同じ。例外は undefined になり、判定で unverified（合格にしない）
    // plan 11章：テスト9
    const mockOp = await createMockOp({ clientId: CLIENT_ID, redirectUri: REDIRECT });
    const fixed = (signIn: RpTestHooks['signIn']): RpTestHooks => ({
      signIn,
      legacyLogin: async () => 'accepted',
      legacyReset: async () => 'refused',
      linkAttack: async () => 'refused',
      routes: async () => [{ method: 'GET', path: '/health', tags: ['other'] }],
    });
    const same = await collect(
      fixed(async () => 'fixed-account'),
      mockOp,
    );
    expect(same).toEqual({
      sameAliasAccounts: ['fixed-account', 'fixed-account'],
      legacyLogin: 'accepted',
      legacyReset: 'refused',
      linkAttack: 'refused',
      routes: [{ method: 'GET', path: '/health', tags: ['other'] }],
    });
    let calls = 0;
    const second = await collect(
      fixed(async () => {
        calls += 1;
        if (calls === 2) throw new Error('2人目は断る');
        return 'fixed-account';
      }),
      mockOp,
    );
    expect(second.sameAliasAccounts).toEqual(['fixed-account', undefined]);
    const report = judge(second, FULL);
    // このフックは旧ログインを accepted と返すので、全体は fail。2人目のログインの例外は unverified。
    expect(report.outcome).toBe('fail');
    expect(report.results.find((r) => r.check === 'same_alias_two_subs')?.status).toBe(
      'unverified',
    );
  });

  it('SDK と模擬 OP：(iss, sub) で内部のアカウントを決める RP は、同じ別名で sub の違う2人を別のアカウントにして合格', async () => {
    // 攻撃者が持っている情報：漏れた別名（2人の ID トークンの email クレームが同じ）
    // 試す経路：SDK のログインを模擬 OP に向け、alpha と beta でログインする。RP は (iss, sub) だけで内部のアカウントを決める
    // 期待する結果：2人は別のアカウント。email クレームは別名で、email_verified は false。キットの報告は合格
    // plan 11章：テスト9（RP-01・RP-03・RP-05）
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const mockOp = await createMockOp({ clientId: CLIENT_ID, redirectUri: REDIRECT });
    const sdk = await createWarifuClient({
      idpOrigin: MOCK_OP_ORIGIN,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      privateKey: (await exportJWK(privateKey)) as JWK,
      kid: 'kit',
      send: mockOp.send,
    });
    const accounts = new Map<string, string>();
    const aliases: (string | null)[] = [];
    const hooks: RpTestHooks = {
      async signIn(_persona, complete) {
        const { url, pending } = await sdk.authorize({ scope: 'openid email' });
        const login = await sdk.finish(complete(url), pending);
        aliases.push(login.contactAlias);
        const key = `${login.iss}|${login.sub}`;
        if (!accounts.has(key)) accounts.set(key, `account-${accounts.size + 1}`);
        return accounts.get(key) ?? '';
      },
      legacyLogin: async () => 'absent',
      legacyReset: async () => 'absent',
      linkAttack: async () => 'refused',
      routes: async () => [{ method: 'POST', path: '/orders/:id/cancel', tags: ['other'] }],
    };
    const report = await runConformanceKit({ hooks, mockOp, participation: FULL });
    expect(report.passed).toBe(true);
    expect(accounts.size).toBe(2);
    expect(aliases[0]).not.toBeNull();
    expect(aliases[0]).toBe(aliases[1]);
  });

  it('模擬 OP：認可コードは一度だけで、PKCE の verifier が違えば断り、外の宛先には答えない', async () => {
    // 攻撃者が持っている情報：横取りした認可コード
    // 試す経路：同じ戻りの URL で2回 finish する。別の pending（違う verifier）で finish する。模擬 OP の外の宛先に送らせる
    // 期待する結果：2回目と verifier の違いは rejected。外の宛先は forbidden_destination
    // plan 11章：テスト9、テスト11
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const mockOp = await createMockOp({ clientId: CLIENT_ID, redirectUri: REDIRECT });
    const sdk = await createWarifuClient({
      idpOrigin: MOCK_OP_ORIGIN,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
      privateKey: (await exportJWK(privateKey)) as JWK,
      kid: 'kit',
      send: mockOp.send,
    });
    const codeOf = async (promise: Promise<unknown>) => {
      try {
        await promise;
        return undefined;
      } catch (error) {
        return error instanceof RpKitError ? error.code : 'other';
      }
    };
    const first = await sdk.authorize();
    const back = mockOp.complete(first.url, 'alpha');
    expect((await sdk.finish(back, first.pending)).sub).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await codeOf(sdk.finish(back, first.pending))).toBe('rejected');
    const second = await sdk.authorize();
    const other = await sdk.authorize();
    const back2 = mockOp.complete(second.url, 'alpha');
    expect(await codeOf(sdk.finish(back2, { ...other.pending, state: second.pending.state }))).toBe(
      'rejected',
    );
    expect(
      await codeOf(
        mockOp.send({ method: 'GET', url: 'https://evil.example/oidc/jwks', headers: {} }),
      ),
    ).toBe('forbidden_destination');
  });

  it('名前だけが似たルートは要確認で、禁止した機能の申告は不合格。フックの想定外の応答は合格にしない', () => {
    // 攻撃者が持っている情報：なし（判定の分け方を、作り物の観測で確かめる）
    // 試す経路：印のない、名前だけが似たルートを申告する。フックが undefined、知らない値、形の違うルートを返す
    // 期待する結果：名前だけなら review（合否は変えない）。印付きの申告は fail。想定外の応答は unverified で、
    //               報告は incomplete（合格にしない）
    // plan 11章：テスト9
    for (const path of [
      '/admin/members/rebind',
      '/reservations/by-phone',
      '/api/subject/profile',
    ]) {
      const report = judge({ ...CLEAN, routes: [{ method: 'GET', path, tags: ['other'] }] }, FULL);
      expect(report.outcome).toBe('review');
      expect(report.passed).toBe(true);
      expect(report.results.some((r) => r.status === 'review')).toBe(true);
    }
    // 移行中で ENT-03 が開いているときの、名前だけのゲスト照会は relaxed。
    const migrating: KitParticipation = { mode: 'migrating', reportedClosed: [] };
    expect(
      statusOf(
        { ...CLEAN, routes: [{ method: 'GET', path: '/orders/guest', tags: ['other'] }] },
        migrating,
      ).guest_lookup,
    ).toBe('relaxed');
    const odd: [Record<string, unknown>, string][] = [
      [{ legacyLogin: undefined }, 'legacy_login'],
      [{ legacyReset: 'ok' }, 'legacy_reset'],
      [{ linkAttack: false }, 'link_attack'],
      [{ routes: undefined }, 'sub_rewrite'],
      [{ routes: [{ method: 'GET', path: 'no-slash', tags: ['other'] }] }, 'guest_lookup'],
      [{ routes: [{ method: 'GET', path: '/x', tags: [] }] }, 'sub_rewrite'],
      [{ routes: [{ method: 'GET', path: '/x', tags: ['unknown'] }] }, 'sub_rewrite'],
      [{ sameAliasAccounts: ['account-1'] }, 'same_alias_two_subs'],
      [{ sameAliasAccounts: [1, 2] }, 'same_alias_two_subs'],
    ];
    for (const [change, check] of odd) {
      for (const participation of [FULL, migrating]) {
        const report = judge({ ...CLEAN, ...change } as unknown as Observations, participation);
        expect(report.results.find((r) => r.check === check)?.status).toBe('unverified');
        expect(report.passed).toBe(false);
        expect(report.outcome).toBe('incomplete');
      }
    }
  });
});
