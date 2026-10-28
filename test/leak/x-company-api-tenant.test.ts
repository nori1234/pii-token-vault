// 企業向け API のテナントの境界（A2B 攻撃、BOLA。plan 2章、RP-70・73、CAP-10・30〜34、ADR 0022）。plan 11章 テスト6。

import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import {
  clientAssertion,
  connectUser,
  startTestCompanyApi,
  type TestCompanyApi,
  TOKEN_ENDPOINT,
} from '../setup/company-api.ts';
import { rawRoleClient, serviceDb } from '../setup/db.ts';

let api: TestCompanyApi;

beforeAll(async () => {
  api = await startTestCompanyApi({ tenants: [{}, {}] });
});

afterAll(async () => {
  await api.stop();
});

function tenants() {
  const [a, b] = api.tenants;
  if (a === undefined || b === undefined) throw new Error('準備に失敗した');
  return { a, b };
}

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

describe('漏えい：企業向け API のテナントの境界（plan 11章 テスト6）', () => {
  it('A社のトークンでは、B社の利用者の別名を入れ替えられない', async () => {
    // 攻撃者が持っている情報：A社の正規の資格情報（侵害されたテナント ATK-03）と、B社の利用者の sub
    //                         （B社から漏れたもの）
    // 試す経路：A社のトークンで、B社の sub を指定して入れ替えを頼む
    // 期待する結果：404（自分のテナントにない sub と同じ）。B社の別名は変わらない
    // plan 11章：テスト6
    const { a, b } = tenants();
    const user = await connectUser([a, b]);
    const [, subB] = user.subs;
    if (subB === undefined) throw new Error('準備に失敗した');
    const token = await api.accessToken(a);
    const res = await api.request({ path: '/v1/aliases/rotate', token, json: { sub: subB } });
    expect([res.status, res.text]).toEqual([404, '{"error":"not_found"}']);
    const db = await serviceDb('company-api');
    try {
      const rows = await db.withTenant(b.tenantId, (tx) =>
        tx.query<{ generation: number }>(
          sql`SELECT generation FROM aliases.generation WHERE user_id = ${user.userId}`,
        ),
      );
      expect(rows.map((r) => r.generation)).toEqual([1]);
    } finally {
      await db.close();
    }
  });

  it('テナントは要求の本文からは決まらない。トークンの中身を書き換えると、署名で落ちる', async () => {
    // 攻撃者が持っている情報：A社の正規のトークンと、B社のテナント ID とクライアント ID
    // 試す経路：本文に tenant_id を足す。トークンのペイロードの tenant_id と client_id を B社のものに書き換える。
    //           A社が自分の鍵で作った JWT、alg を none や HS256 にしたもの、期限の切れたものを送る
    // 期待する結果：本文の余計な項目は 400。書き換えたトークンは、すべて同じ 401
    // plan 11章：テスト6
    const { a, b } = tenants();
    const token = await api.accessToken(a);
    const extra = await api.request({
      path: '/v1/aliases/rotate',
      token,
      json: { sub: 'A'.repeat(43), tenant_id: b.tenantId },
    });
    expect(extra.status).toBe(400);
    const [header, payload, signature] = token.split('.');
    const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8'));
    const swapped = `${header}.${b64({ ...claims, tenant_id: b.tenantId, client_id: b.client.clientId, sub: b.client.clientId })}.${signature}`;
    const self = await new SignJWT({ ...claims, tenant_id: b.tenantId })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'at+jwt',
        kid: JSON.parse(Buffer.from(header ?? '', 'base64url').toString()).kid,
      })
      .sign(a.client.privateKey);
    const none = `${b64({ alg: 'none', typ: 'at+jwt' })}.${payload}.`;
    const hs = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
      .sign(new TextEncoder().encode('secret-secret-secret-secret-secret'));
    const expired = `${header}.${b64({ ...claims, exp: 1_000 })}.${signature}`;
    const results = await Promise.all(
      [swapped, self, none, hs, expired, `${token}x`, 'not-a-jwt'].map((t) =>
        api.request({ path: '/v1/aliases/rotate', token: t, json: { sub: 'A'.repeat(43) } }),
      ),
    );
    expect(results.map((r) => [r.status, r.text])).toEqual(
      results.map(() => [401, '{"error":"invalid_token"}']),
    );
  });

  it('client assertion は ES256 で、自分の鍵、自分の client_id、トークンのエンドポイント、1回だけ', async () => {
    // 攻撃者が持っている情報：A社の秘密鍵（侵害されたテナント ATK-03）、B社の client_id、盗み見た A社の assertion
    // 試す経路：A社の鍵で B社の client_id を名乗る。aud を違える。期限の切れたもの、iat の古いもの、
    //           ES384 や HS256 で署名したもの、同じ assertion の2回目、知らない client_id、
    //           client_secret を足したもの、client_assertion_type の違うもの
    // 期待する結果：client の認証の失敗は、すべて同じ 401 invalid_client。形の違いは 400 invalid_request
    // plan 11章：テスト6、テスト8（ES256 だけ）
    const { a, b } = tenants();
    const now = Math.floor(Date.now() / 1000);
    const es384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    const replayed = await clientAssertion(a.client);
    expect((await api.token(a, { client_assertion: replayed })).status).toBe(200);
    const forms: Record<string, string>[] = [
      {
        client_assertion: await clientAssertion(a.client, {
          iss: b.client.clientId,
          sub: b.client.clientId,
        }),
      },
      { client_assertion: await clientAssertion(a.client, { aud: 'http://localhost:4400' }) },
      {
        client_assertion: await clientAssertion(a.client, {
          aud: 'https://idp.warifu.test/oidc/token',
        }),
      },
      { client_assertion: await clientAssertion(a.client, { iat: now - 3600, exp: now - 3000 }) },
      { client_assertion: await clientAssertion(a.client, { iat: now - 600, exp: now + 60 }) },
      { client_assertion: await clientAssertion(a.client, { exp: now + 3600 }) },
      {
        client_assertion: await new SignJWT({ jti: randomUUID() })
          .setProtectedHeader({ alg: 'ES384' })
          .setIssuer(a.client.clientId)
          .setSubject(a.client.clientId)
          .setAudience(TOKEN_ENDPOINT)
          .setIssuedAt()
          .setExpirationTime('1m')
          .sign(es384),
      },
      {
        client_assertion: await new SignJWT({ jti: randomUUID() })
          .setProtectedHeader({ alg: 'HS256' })
          .setIssuer(a.client.clientId)
          .setSubject(a.client.clientId)
          .setAudience(TOKEN_ENDPOINT)
          .setIssuedAt()
          .setExpirationTime('1m')
          .sign(new TextEncoder().encode('x'.repeat(32))),
      },
      { client_assertion: replayed },
      {
        client_assertion: await clientAssertion(a.client, {
          iss: 'unknown-client',
          sub: 'unknown-client',
        }),
      },
      { client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer' },
      { client_id: b.client.clientId },
    ];
    const results = await Promise.all(forms.map((form) => api.token(a, form)));
    expect(results.map((r) => [r.status, r.text])).toEqual(
      results.map(() => [401, '{"error":"invalid_client"}']),
    );
    const invalid = await Promise.all([
      api.token(a, { client_secret: 'x' }),
      api.token(a, { grant_type: 'authorization_code' }),
      api.token(a, { scope: 'admin' }),
    ]);
    expect(invalid.map((r) => [r.status, r.json()])).toEqual([
      [400, { error: 'invalid_request' }],
      [400, { error: 'unsupported_grant_type' }],
      [400, { error: 'invalid_scope' }],
    ]);
  });

  it('緊急停止したテナントには、トークンを出さず、発行済みのトークンも断る', async () => {
    // 攻撃者が持っている情報：侵害されたテナントの資格情報と、停止の前に得たトークン（ATK-03）
    // 試す経路：設定で suspended にして配備し直した company-api に、同じ鍵の assertion と、前のトークンを送る
    // 期待する結果：トークンは 401 invalid_client。前のトークンは 401 invalid_token
    // plan 11章：テスト6（plan 2章「テナントが侵害されたときの封じ込め」）
    const { a } = tenants();
    const before = await api.accessToken(a);
    const stopped = await startTestCompanyApi({
      tenants: [
        { tenantId: a.tenantId, relayDomain: a.relayDomain, client: a.client, suspended: true },
      ],
    });
    try {
      const [s] = stopped.tenants;
      if (s === undefined) throw new Error('準備に失敗した');
      expect([(await stopped.token(s)).status]).toEqual([401]);
      const res = await stopped.request({
        path: '/v1/aliases/rotate',
        token: before,
        json: { sub: 'A'.repeat(43) },
      });
      expect([res.status, res.text]).toEqual([401, '{"error":"invalid_token"}']);
    } finally {
      await stopped.stop();
    }
  });

  it('トークンの要求と検証の SET の依頼には、レート制限がかかる', async () => {
    // 攻撃者が持っている情報：送信元の1つの IP（ATK-02）。侵害したテナントのトークン（ATK-03）
    // 試す経路：トークンの要求を61回送る。検証の SET の依頼を11回送る（受け口のないテナントは 409 で数えない）
    // 期待する結果：61回目のトークンの要求は 429。受け口のあるテナントで、11回目の依頼は 429
    // plan 11章：テスト6（レート制限が働く）
    const limitedApi = await startTestCompanyApi({
      tenants: [{ webhookUrl: 'https://hooks.company.example/set' }],
    });
    try {
      const [t] = limitedApi.tenants;
      if (t === undefined) throw new Error('準備に失敗した');
      const token = await limitedApi.accessToken(t);
      const codes: number[] = [];
      for (let i = 0; i < 11; i += 1) {
        codes.push(
          (await limitedApi.request({ path: '/v1/events/verification', token, json: {} })).status,
        );
      }
      expect(codes).toEqual([...Array(10).fill(202), 429]);
      // 上の accessToken で1回使っているので、あと59回までは通る。
      const tokenCodes: number[] = [];
      for (let i = 0; i < 59; i += 1) {
        tokenCodes.push((await limitedApi.token(t, { client_assertion: 'x' })).status);
      }
      expect(new Set(tokenCodes)).toEqual(new Set([401]));
      expect((await limitedApi.token(t)).status).toBe(429);
    } finally {
      await limitedApi.stop();
    }
  });

  it('company-api のロールは、境界の外ではテナントの行を読めず、参加の状態を書き換える列もない', async () => {
    // 攻撃者が持っている情報：SQL インジェクションか盗んだ資格情報で、company-api のロールとして任意の SQL を実行できる
    //                         （ATK-02、ATK-07）
    // 試す経路：境界を設定しない生の接続で、sub の索引、別名の世代、SET の送信待ちを読む。
    //           company_api のスキーマで、参加の状態の列を探す
    // 期待する結果：どれも0行。参加の状態、移行中の期限、確かめた入り口の列は、どの表にもない（ADR 0010）
    // plan 11章：テスト6
    const { a } = tenants();
    await connectUser([a]);
    const client = await rawRoleClient('warifu_company_api');
    try {
      for (const table of ['aliases.subject', 'aliases.generation', 'company_api.set_outbox']) {
        const { rows } = await client.query(`SELECT tenant_id FROM ${table}`);
        expect([table, rows.length]).toEqual([table, 0]);
      }
      const { rows } = await client.query(
        `SELECT table_schema, table_name, column_name FROM information_schema.columns
          WHERE table_schema IN ('company_api', 'aliases')
            AND column_name ~ '(participation|migrat|verified|deadline|suspend)'`,
      );
      expect(rows).toEqual([]);
    } finally {
      await client.end();
    }
  });
});
