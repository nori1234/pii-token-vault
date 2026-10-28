// 別名の入れ替え（plan 3-2、ADR 0005、ADR 0022）。plan 11章 テスト4の後半。
// 企業が sub で別名の入れ替えを頼むと、次の世代の別名が返る。前の世代の別名あてのメールは、同じ 250 で受けて
// 届けない（不変条件10）。照合用の MAC の一意制約で、前の世代の別名は二度と割り当てられない（不変条件5）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { aliasLookupMessage } from '../../packages/warifu-core/src/aliases.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import { connectUser, startTestCompanyApi, type TestCompanyApi } from '../setup/company-api.ts';
import { serviceDb, sqlstateOf } from '../setup/db.ts';
import { Browser, codeFlow, startTestIdp } from '../setup/idp.ts';
import { keysvcConnection } from '../setup/keys.ts';
import {
  addUser,
  companyMail,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestRelay,
} from '../setup/relay.ts';

let relay: TestRelay;
let api: TestCompanyApi;

beforeAll(async () => {
  relay = await startTestRelay({ companies: 1 });
  const [company] = relay.companies;
  if (company === undefined) throw new Error('準備に失敗した');
  api = await startTestCompanyApi({
    tenants: [{ tenantId: company.tenantId, relayDomain: company.relayDomain }],
  });
});

afterAll(async () => {
  await api.stop();
  await relay.stop();
});

async function deliver(to: string): Promise<number> {
  const [company] = relay.companies;
  if (company === undefined) throw new Error('準備に失敗した');
  const before = relay.outbound.all().length;
  const raw = await signCompanyMail(company, companyMail(company, to));
  const { rcpt, data } = await sendMail(
    relay.relay.smtpPort,
    { from: `bounce@${company.senderDomain}`, to },
    raw,
  );
  expect([rcpt.code, data?.code]).toEqual([250, 250]);
  await relay.relay.idle();
  return relay.outbound.all().length - before;
}

describe('漏えい：別名の入れ替え（plan 11章 テスト4の後半）', () => {
  it('入れ替えた後、前の別名あてのメールは届かず、新しい別名あてだけが本物のアドレスに届く', async () => {
    // 攻撃者が持っている情報：漏れた前の別名（入れ替えの前に、企業から漏れたもの）
    // 試す経路：企業が sub で入れ替えを頼んだ後に、前の別名と新しい別名へ、企業の正規の署名でメールを送る
    // 期待する結果：入れ替えは 200 で、返るのは新しい別名だけ。前の別名あては 250 で受けて、どこにも届けない。
    //               新しい別名あては本物のアドレスに届く
    // plan 11章：テスト4の後半
    const [tenant] = api.tenants;
    if (tenant === undefined) throw new Error('準備に失敗した');
    const user = await addUser(relay.companies);
    const connected = await connectUser([tenant], user.userId);
    expect(connected.aliases).toEqual(user.aliases);
    const [oldAlias] = user.aliases;
    const [sub] = connected.subs;
    if (oldAlias === undefined || sub === undefined) throw new Error('準備に失敗した');
    expect(await deliver(oldAlias)).toBe(1);

    const token = await api.accessToken(tenant);
    const res = await api.request({ path: '/v1/aliases/rotate', token, json: { sub } });
    expect(res.status).toBe(200);
    const body = res.json() as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(['alias']);
    const newAlias = String(body.alias);
    expect(newAlias).not.toBe(oldAlias);
    expect(newAlias.endsWith(`@${tenant.relayDomain}`)).toBe(true);
    expect(res.text).not.toContain(user.email);

    expect(await deliver(oldAlias)).toBe(0);
    expect(await deliver(newAlias)).toBe(1);
    expect(relay.outbound.all().at(-1)?.rcptTo).toBe(user.email);
  });

  it('ID トークンの sub で入れ替えを頼むと、次の ID トークンの別名が新しい世代になる', async () => {
    // 攻撃者が持っている情報：なし（正規の経路の確認。idp が接続の同意のときに置いた sub の索引が、ID トークンの
    //                       sub と一致することを見る）
    // 試す経路：コードフローで ID トークンを受け取り、その sub で company-api に入れ替えを頼み、もう一度ログインする
    // 期待する結果：入れ替えは 200。次の ID トークンの sub は同じで、email の別名は入れ替えで返った新しい別名
    // plan 11章：テスト4の後半
    const idp = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
    const [tenant] = idp.tenants;
    const [client] = idp.clients;
    if (tenant === undefined || client === undefined) throw new Error('準備に失敗した');
    const companyApi = await startTestCompanyApi({
      tenants: [{ tenantId: tenant.tenantId as never, relayDomain: tenant.relayDomain }],
    });
    try {
      const browser = new Browser(idp.origin);
      const first = await codeFlow(idp, browser, client, { mode: 'register' });
      const [apiTenant] = companyApi.tenants;
      if (apiTenant === undefined) throw new Error('準備に失敗した');
      const token = await companyApi.accessToken(apiTenant);
      const res = await companyApi.request({
        path: '/v1/aliases/rotate',
        token,
        json: { sub: first.claims.sub },
      });
      expect(res.status).toBe(200);
      const { alias } = res.json() as { alias: string };
      expect(alias).not.toBe(first.claims.email);
      const second = await codeFlow(idp, browser, client, { mode: 'session' });
      expect(second.claims.sub).toBe(first.claims.sub);
      expect(second.claims.email).toBe(alias);
    } finally {
      await companyApi.stop();
      await idp.stop();
    }
  });

  it('割り当ては、照合用の MAC の一意制約で、前の世代の別名を返せない', async () => {
    // 攻撃者が持っている情報：侵害した company-api の DB の資格情報（ATK-07）と、前の世代の別名
    // 試す経路：company-api の境界で、前の世代の別名の照合用の MAC を、新しい世代として足そうとする。
    //           入れ替えを何度も頼んで、前の値が戻るかを見る
    // 期待する結果：一意制約（23505）で失敗する。何度入れ替えても、前のどの値とも違う別名が返る
    // plan 11章：テスト4の後半
    const [tenant] = api.tenants;
    if (tenant === undefined) throw new Error('準備に失敗した');
    const connected = await connectUser([tenant]);
    const [first] = connected.aliases;
    const [sub] = connected.subs;
    if (first === undefined || sub === undefined) throw new Error('準備に失敗した');
    const token = await api.accessToken(tenant);
    const seen = new Set([first]);
    for (let i = 0; i < 3; i += 1) {
      const res = await api.request({ path: '/v1/aliases/rotate', token, json: { sub } });
      const alias = String((res.json() as { alias: string }).alias);
      expect(seen.has(alias)).toBe(false);
      seen.add(alias);
    }
    const keys = createCompanyApiKeyClient(keysvcConnection('company-api'));
    const oldMac = await keys.mac('alias_lookup', aliasLookupMessage(first.split('@')[0] ?? ''));
    const db = await serviceDb('company-api');
    try {
      const state = await sqlstateOf(
        db.withTenant(tenant.tenantId, (tx) =>
          tx.execute(
            sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
                VALUES (${tenant.tenantId}, ${connected.userId}, 99, ${oldMac})`,
          ),
        ),
      );
      expect(state).toBe('23505');
      // 世代を消したり戻したりする権限もない（UPDATE と DELETE を与えていない）。
      for (const statement of [
        sql`UPDATE aliases.generation SET generation = 1 WHERE user_id = ${connected.userId}`,
        sql`DELETE FROM aliases.generation WHERE user_id = ${connected.userId}`,
      ]) {
        expect(
          await sqlstateOf(db.withTenant(tenant.tenantId, (tx) => tx.execute(statement))),
        ).toBe('42501');
      }
    } finally {
      await db.close();
    }
  });

  it('企業に渡る値は、トークン、新しい別名、SET の検証の鍵だけ', async () => {
    // 攻撃者が持っている情報：企業向け API の正規の資格情報（企業の中の者）
    // 試す経路：トークン、別名の入れ替え、知らない sub、公開鍵の応答の項目を数える
    // 期待する結果：トークンは access_token・token_type・expires_in・scope だけ。入れ替えは alias だけ。
    //               知らない sub は 404 で、本文は固定。公開鍵は ES256 の公開鍵だけ（d がない）
    // plan 11章：テスト4の後半（企業に渡る値の一覧）
    const [tenant] = api.tenants;
    if (tenant === undefined) throw new Error('準備に失敗した');
    const tokenRes = await api.token(tenant);
    expect(Object.keys(tokenRes.json() as object).sort()).toEqual([
      'access_token',
      'expires_in',
      'scope',
      'token_type',
    ]);
    const token = (tokenRes.json() as { access_token: string }).access_token;
    const unknown = await api.request({
      path: '/v1/aliases/rotate',
      token,
      json: { sub: 'A'.repeat(43) },
    });
    expect([unknown.status, unknown.text]).toEqual([404, '{"error":"not_found"}']);
    const jwks = await api.request({ method: 'GET', path: '/jwks' });
    const keys = (jwks.json() as { keys: Record<string, unknown>[] }).keys;
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(Object.keys(key).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']);
      expect([key.kty, key.crv, key.alg]).toEqual(['EC', 'P-256', 'ES256']);
    }
  });
});
