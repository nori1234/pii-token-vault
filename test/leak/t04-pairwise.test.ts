// テスト4の前半（plan 11章、不変条件5）：企業ごとの sub と別名。
// 同じ人の sub と別名は、A社とB社で別々。同じテナントの2つのクライアントでは sub が同じ。
// 企業に渡る値は、sub、別名（email クレームか contact_alias）、acr、auth_time と、JWT の決まった項目だけ。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { aliasLookupMessage } from '../../packages/warifu-core/src/aliases.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { relayDb } from '../setup/db.ts';
import { Browser, codeFlow, startTestIdp, type TestIdp } from '../setup/idp.ts';
import { keysvcConnection } from '../setup/keys.ts';

let t: TestIdp;

beforeAll(async () => {
  // テナント A（クライアント2つ）、テナント B（クライアント1つ、contact_alias で受け取る）。
  t = await startTestIdp({
    tenants: 2,
    clients: [{ tenant: 0 }, { tenant: 0 }, { tenant: 1, aliasClaim: 'contact_alias' }],
  });
});

afterAll(async () => {
  await t.stop();
});

const ID_TOKEN_KEYS = ['acr', 'aud', 'auth_time', 'exp', 'iat', 'iss', 'nonce', 'sub'];

describe('漏えい：企業ごとに独立した sub と別名（plan 11章 テスト4）', () => {
  it('同じ人でも、A社とB社では sub と別名が違い、同じテナントの2つのクライアントでは sub が同じ', async () => {
    // 攻撃者が持っている情報：A社とB社の両方の会員データ（sub、別名）。2社が結託するか、両方から漏れた場面
    // 試す経路：同じ利用者が、A社の2つのクライアントとB社のクライアントにコードフローでログインし、ID トークンを比べる
    // 期待する結果：A社の2つのクライアントの sub は同じ。B社の sub は違う。別名もA社とB社で違い、ドメインも違う。
    //               email_verified は常に false。B社は email ではなく contact_alias で受け取る
    // plan 11章：テスト4
    const [a1, a2, b] = t.clients as [
      (typeof t.clients)[0],
      (typeof t.clients)[0],
      (typeof t.clients)[0],
    ];
    const browser = new Browser(t.origin);
    const first = await codeFlow(t, browser, a1, { mode: 'register' });
    // 初めての A社：登録と同意の2つのインタラクション。
    expect(first.interactionPaths).toHaveLength(2);
    const second = await codeFlow(t, browser, a2, { mode: 'session' });
    // A社の2つ目のクライアントは、同意済みのテナントなので同意の画面が出ない（セッションも有効）。
    expect(second.interactionPaths).toHaveLength(0);
    const third = await codeFlow(t, browser, b, { mode: 'session' });
    // B社は初めてなので、同意だけを求める。
    expect(third.interactionPaths).toHaveLength(1);

    expect(first.claims.sub).toBe(second.claims.sub);
    expect(third.claims.sub).not.toBe(first.claims.sub);
    expect(String(first.claims.sub)).toMatch(/^[A-Za-z0-9_-]{43}$/);

    expect(first.claims.email).toBe(second.claims.email);
    expect(first.claims.email_verified).toBe(false);
    expect(third.claims.email).toBeUndefined();
    expect(third.claims.email_verified).toBeUndefined();
    const aliasA = String(first.claims.email);
    const aliasB = String(third.claims.contact_alias);
    expect(aliasA).toMatch(
      new RegExp(`^[a-z2-7]{16}@${t.tenants[0]?.relayDomain.replaceAll('.', '\\.')}$`),
    );
    expect(aliasB).toMatch(
      new RegExp(`^[a-z2-7]{16}@${t.tenants[1]?.relayDomain.replaceAll('.', '\\.')}$`),
    );
    expect(aliasA.split('@')[0]).not.toBe(aliasB.split('@')[0]);

    // 企業に渡る値の一覧（ID トークンの項目）。
    expect(Object.keys(first.claims).sort()).toEqual(
      [...ID_TOKEN_KEYS, 'email', 'email_verified'].sort(),
    );
    expect(Object.keys(third.claims).sort()).toEqual([...ID_TOKEN_KEYS, 'contact_alias'].sort());
    expect(first.claims.acr).toBe('urn:warifu:acr:passkey');
    // トークンの応答に refresh token はない。
    expect(first.tokenResponse.refresh_token).toBeUndefined();
    expect(t.outboundAttempts()).toBe(0);
  });

  it('別名は relay の解決関数で、そのテナントと利用者に戻る（別名そのものは DB にない）', async () => {
    // 攻撃者が持っている情報：A社の別名
    // 試す経路：relay の解決関数に、A社の別名の照合用の MAC を渡す
    // 期待する結果：A社のテナント ID が返る。B社の別名からは B社のテナント ID が返る（同じ利用者 ID）
    // plan 11章：テスト4
    const browser = new Browser(t.origin);
    const [a1, , b] = t.clients as [(typeof t.clients)[0], unknown, (typeof t.clients)[0]];
    const fromA = await codeFlow(t, browser, a1, { mode: 'register' });
    const fromB = await codeFlow(t, browser, b, { mode: 'session' });
    const keys = createIdpKeyClient(keysvcConnection('idp'));
    const relay = await relayDb();
    try {
      const resolve = async (alias: string) => {
        const local = alias.split('@')[0] ?? '';
        return relay.resolveAlias(await keys.mac('alias_lookup', aliasLookupMessage(local)));
      };
      const a = await resolve(String(fromA.claims.email));
      const b2 = await resolve(String(fromB.claims.contact_alias));
      expect(a?.tenantId).toBe(t.tenants[0]?.tenantId);
      expect(b2?.tenantId).toBe(t.tenants[1]?.tenantId);
      expect(a?.userId).toBe(b2?.userId);
    } finally {
      await relay.close();
    }
  });
});
