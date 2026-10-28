// RLS とロールの固定テスト（不変条件8、plan 10章 M2「RLS の固定テスト」、2章「BOLA を防ぐ」。テスト6の土台）。
// アプリのロール（warifu_idp）でカタログを読み、境界が効く前提が崩れていないことを確かめる。
// 期待の一覧はテストの中に書く。表、ポリシー、GRANT を足したら、同じ PR でここも直す（principle-review の観点8）。

import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rawRoleClient } from '../setup/db.ts';

const APP_ROLES = ['warifu_company_api', 'warifu_idp', 'warifu_relay'];
const SYSTEM_SCHEMAS = "('pg_catalog', 'information_schema', 'pg_toast')";

// 表 → ロール → 権限 → 列。
const COLUMN_GRANTS: Record<string, Record<string, Record<string, string[]>>> = {
  'aliases.generation': {
    warifu_alias_resolver: { SELECT: ['generation', 'lookup_mac', 'tenant_id', 'user_id'] },
    warifu_company_api: {
      INSERT: ['generation', 'lookup_mac', 'tenant_id', 'user_id'],
      SELECT: ['created_at', 'generation', 'tenant_id', 'user_id'],
    },
    warifu_idp: {
      INSERT: ['generation', 'lookup_mac', 'tenant_id', 'user_id'],
      SELECT: ['created_at', 'generation', 'tenant_id', 'user_id'],
    },
  },
  // sub の索引（0006。ADR 0022）。idp は sub を置けるが読めない。company-api は sub から利用者を引くだけ。
  'aliases.subject': {
    warifu_company_api: { SELECT: ['sub', 'tenant_id', 'user_id'] },
    warifu_idp: {
      INSERT: ['sub', 'tenant_id', 'user_id'],
      SELECT: ['created_at', 'tenant_id', 'user_id'],
    },
  },
  // SET の送信待ち（0006。ADR 0022）。署名した SET の列はない。
  'company_api.set_outbox': {
    warifu_company_api: {
      INSERT: ['deliver_after', 'event_id', 'event_type', 'state', 'tenant_id'],
      SELECT: [
        'attempts',
        'created_at',
        'deliver_after',
        'event_id',
        'event_type',
        'issued_at',
        'jti',
        'state',
        'tenant_id',
      ],
      UPDATE: ['attempts', 'deliver_after', 'issued_at', 'jti'],
    },
  },
  'audit.chain': Object.fromEntries(
    APP_ROLES.map((role) => [
      role,
      {
        INSERT: ['content_mac', 'mac', 'prev_mac', 'seq'],
        SELECT: ['content_mac', 'mac', 'prev_mac', 'seq'],
      },
    ]),
  ),
  'contacts.email': {
    warifu_idp: {
      INSERT: ['ciphertext', 'updated_at', 'user_id'],
      SELECT: ['ciphertext', 'updated_at', 'user_id'],
      UPDATE: ['ciphertext', 'updated_at'],
    },
    warifu_relay: { SELECT: ['ciphertext', 'user_id'] },
  },
  'contacts.email_pending': {
    warifu_idp: {
      INSERT: ['ciphertext', 'code_mac', 'expires_at', 'user_id'],
      SELECT: ['attempts', 'ciphertext', 'code_mac', 'created_at', 'expires_at', 'user_id'],
      UPDATE: ['attempts'],
    },
    warifu_relay: { SELECT: ['ciphertext', 'user_id'] },
  },
  'contacts.email_previous': {
    warifu_idp: {
      INSERT: ['ciphertext', 'replaced_at', 'user_id'],
      SELECT: ['replaced_at', 'user_id'],
    },
    warifu_relay: { SELECT: ['ciphertext', 'user_id'] },
  },
  'idp.connections': {
    warifu_idp: {
      INSERT: ['tenant_id', 'user_id'],
      SELECT: ['consented_at', 'tenant_id', 'user_id'],
    },
  },
  'idp.credentials': {
    warifu_idp: {
      INSERT: [
        'alg',
        'backed_up',
        'backup_eligible',
        'credential_id',
        'public_key',
        'rsa_bits',
        'sign_count',
        'transports',
        'user_id',
      ],
      SELECT: [
        'alg',
        'backed_up',
        'backup_eligible',
        'created_at',
        'credential_id',
        'last_used_at',
        'public_key',
        'rsa_bits',
        'sign_count',
        'transports',
        'user_id',
      ],
      UPDATE: ['backed_up', 'last_used_at', 'sign_count'],
    },
  },
  // 端末の受信箱（0007。ADR 0023）。作った後に変えられるのは、状態とその時刻だけ。
  'idp.inbox': {
    warifu_idp: {
      INSERT: [
        'content',
        'created_at',
        'expires_at',
        'item_id',
        'kind',
        'purge_after',
        'state',
        'tenant_id',
        'type',
        'user_id',
      ],
      SELECT: [
        'content',
        'created_at',
        'decided_at',
        'expires_at',
        'item_id',
        'kind',
        'purge_after',
        'read_at',
        'state',
        'tenant_id',
        'type',
        'user_id',
      ],
      UPDATE: ['decided_at', 'read_at', 'state'],
    },
  },
  'idp.users': {
    warifu_idp: { INSERT: ['user_id'], SELECT: ['created_at', 'user_id'] },
  },
  // relay の表（0005。ADR 0021）。UPDATE はない。配送ログの Message-ID の MAC は、書けるが読めない。
  'relay.delivery_log': {
    warifu_relay: {
      INSERT: ['direction', 'expires_at', 'log_id', 'message_id_mac', 'outcome', 'tenant_id'],
      SELECT: ['created_at', 'direction', 'expires_at', 'log_id', 'outcome', 'tenant_id'],
    },
  },
  'relay.replay': {
    warifu_relay: {
      INSERT: ['expires_at', 'replay_mac', 'tenant_id'],
      SELECT: ['expires_at', 'replay_mac', 'tenant_id'],
    },
  },
  'relay.threads': {
    warifu_relay: {
      INSERT: ['expires_at', 'target_ciphertext', 'tenant_id', 'thread_id', 'token_mac', 'user_id'],
      SELECT: ['expires_at', 'target_ciphertext', 'tenant_id', 'thread_id', 'token_mac', 'user_id'],
    },
  },
  'audit.events': Object.fromEntries(
    APP_ROLES.map((role) => {
      const cols = [
        'attrs',
        'event_type',
        'occurred_at',
        'scope_seq',
        'seq',
        'service',
        'tenant_id',
        'user_id',
      ];
      return [role, { INSERT: cols, SELECT: cols }];
    }),
  ),
};

const APP = '{warifu_company_api,warifu_idp,warifu_relay}';
const OWN = '(user_id = warifu.current_user_id())';
const TENANT = '(tenant_id = warifu.current_tenant_id())';
const POLICIES = [
  'aliases.generation|company_api_insert|INSERT|{warifu_company_api}||((tenant_id = warifu.current_tenant_id()) AND (generation >= 2))',
  'aliases.generation|company_api_select|SELECT|{warifu_company_api}|(tenant_id = warifu.current_tenant_id())|',
  'aliases.generation|idp_insert|INSERT|{warifu_idp}||((tenant_id = warifu.current_tenant_id()) AND (generation = 1))',
  'aliases.generation|idp_select|SELECT|{warifu_idp}|((tenant_id = warifu.current_tenant_id()) OR (user_id = warifu.current_user_id()))|',
  'aliases.generation|resolver_select|SELECT|{warifu_alias_resolver}|true|',
  `aliases.subject|company_api_select|SELECT|{warifu_company_api}|${TENANT}|`,
  `aliases.subject|idp_insert|INSERT|{warifu_idp}||${TENANT}`,
  `aliases.subject|idp_select|SELECT|{warifu_idp}|${TENANT}|`,
  `audit.chain|chain_insert|INSERT|${APP}||warifu.has_boundary()`,
  `audit.chain|chain_select|SELECT|${APP}|warifu.has_boundary()|`,
  `audit.events|events_insert|INSERT|${APP}||((service = warifu.service_of(CURRENT_USER)) AND (((tenant_id = warifu.current_tenant_id()) AND (user_id IS NULL)) OR ((user_id = warifu.current_user_id()) AND (tenant_id IS NULL))))`,
  `audit.events|events_select|SELECT|${APP}|((tenant_id = warifu.current_tenant_id()) OR (user_id = warifu.current_user_id()))|`,
  `company_api.set_outbox|company_api_delete|DELETE|{warifu_company_api}|${TENANT}|`,
  `company_api.set_outbox|company_api_insert|INSERT|{warifu_company_api}||${TENANT}`,
  `company_api.set_outbox|company_api_select|SELECT|{warifu_company_api}|${TENANT}|`,
  `company_api.set_outbox|company_api_update|UPDATE|{warifu_company_api}|${TENANT}|${TENANT}`,
  ...['email', 'email_pending', 'email_previous'].flatMap((t) => [
    ...(t === 'email_previous' || t === 'email_pending'
      ? [`contacts.${t}|idp_delete|DELETE|{warifu_idp}|${OWN}|`]
      : []),
    `contacts.${t}|idp_insert|INSERT|{warifu_idp}||${OWN}`,
    `contacts.${t}|idp_select|SELECT|{warifu_idp}|${OWN}|`,
    ...(t === 'email' || t === 'email_pending'
      ? [`contacts.${t}|idp_update|UPDATE|{warifu_idp}|${OWN}|${OWN}`]
      : []),
    `contacts.${t}|relay_select|SELECT|{warifu_relay}|${OWN}|`,
  ]),
  `idp.connections|idp_insert|INSERT|{warifu_idp}||${OWN}`,
  `idp.connections|idp_select|SELECT|{warifu_idp}|${OWN}|`,
  `idp.credentials|idp_delete|DELETE|{warifu_idp}|${OWN}|`,
  `idp.credentials|idp_insert|INSERT|{warifu_idp}||${OWN}`,
  `idp.credentials|idp_select|SELECT|{warifu_idp}|${OWN}|`,
  `idp.credentials|idp_update|UPDATE|{warifu_idp}|${OWN}|${OWN}`,
  `idp.inbox|idp_delete|DELETE|{warifu_idp}|${OWN}|`,
  `idp.inbox|idp_insert|INSERT|{warifu_idp}||${OWN}`,
  `idp.inbox|idp_select|SELECT|{warifu_idp}|${OWN}|`,
  `idp.inbox|idp_update|UPDATE|{warifu_idp}|${OWN}|${OWN}`,
  `idp.users|idp_insert|INSERT|{warifu_idp}||${OWN}`,
  `idp.users|idp_select|SELECT|{warifu_idp}|${OWN}|`,
  ...['delivery_log', 'replay', 'threads'].flatMap((t) => [
    `relay.${t}|relay_delete|DELETE|{warifu_relay}|${TENANT}|`,
    `relay.${t}|relay_insert|INSERT|{warifu_relay}||${TENANT}`,
    `relay.${t}|relay_select|SELECT|{warifu_relay}|${TENANT}|`,
  ]),
];

// 表の単位の権限（DELETE は列の単位で与えられない）。これ以外は0件（UPDATE は列の単位だけ）。
const TABLE_GRANTS = [
  'company_api.set_outbox|warifu_company_api|DELETE',
  'contacts.email_pending|warifu_idp|DELETE',
  'contacts.email_previous|warifu_idp|DELETE',
  'idp.credentials|warifu_idp|DELETE',
  'idp.inbox|warifu_idp|DELETE',
  'relay.delivery_log|warifu_relay|DELETE',
  'relay.replay|warifu_relay|DELETE',
  'relay.threads|warifu_relay|DELETE',
];

let client: pg.Client;

beforeAll(async () => {
  client = await rawRoleClient('warifu_idp');
});

afterAll(async () => {
  await client.end();
});

async function rows<T extends object>(text: string, values: unknown[] = []): Promise<T[]> {
  return (await client.query<T>(text, values)).rows;
}

describe('漏えい：RLS とロールの固定（plan 10章 M2）', () => {
  it('全テーブルに RLS の ENABLE と FORCE がある', async () => {
    // 攻撃者が持っている情報：SQL インジェクションか盗んだ資格情報で、アプリのロールの1つとして任意の SQL を実行できる
    //                       （ATK-02、ATK-07）。この固定テストは、そのときに効く前提が崩れていないことを確かめる
    // 試す経路：pg_class を読み、FORCE の付け忘れを探す
    // 期待する結果：システムのスキーマ以外の、relkind が r と p の全テーブルで、relrowsecurity と relforcerowsecurity が true
    // plan 11章：番号なし（plan 10章 M2「RLS の固定テスト」、2章「BOLA を防ぐ」。テスト6の土台）
    const tables = await rows<{ t: string; rls: boolean; force: boolean }>(
      `SELECT n.nspname || '.' || c.relname AS t, c.relrowsecurity AS rls, c.relforcerowsecurity AS force
         FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ${SYSTEM_SCHEMAS}
        ORDER BY 1`,
    );
    expect(tables.map((t) => t.t)).toEqual(
      expect.arrayContaining([
        'aliases.generation',
        'aliases.subject',
        'audit.chain',
        'company_api.set_outbox',
        'audit.events',
        'contacts.email',
        'contacts.email_pending',
        'contacts.email_previous',
        'idp.connections',
        'idp.credentials',
        'idp.inbox',
        'idp.users',
        'warifu_meta.migrations',
      ]),
    );
    expect(tables.filter((t) => !t.rls || !t.force)).toEqual([]);
  });

  it('抜け道になる種類のオブジェクトがない', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：RLS を迂回しうるもの（マテリアライズドビュー、外部テーブル、所有者の権限で動くビュー）を探す
    // 期待する結果：マテリアライズドビューと外部テーブルが0件。ビューは security_invoker=true だけ（M2 では0件）
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const objects = await rows<{ t: string; kind: string; options: string[] | null }>(
      `SELECT n.nspname || '.' || c.relname AS t, c.relkind AS kind, c.reloptions AS options
         FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('m', 'f', 'v') AND n.nspname NOT IN ${SYSTEM_SCHEMAS}`,
    );
    expect(objects.filter((o) => o.kind !== 'v')).toEqual([]);
    expect(
      objects.filter((o) => o.kind === 'v' && !(o.options ?? []).includes('security_invoker=true')),
    ).toEqual([]);
  });

  it('ログインできるロールと、スーパーユーザー', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：pg_roles を読み、ログインできるロールとスーパーユーザーを数える
    // 期待する結果：LOGIN を持つのは warifu_bootstrap、warifu_idp、warifu_relay、warifu_company_api だけ。
    //               スーパーユーザーは warifu_bootstrap だけ（CAP-18。BI ツールなどのロールを作らない）
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const login = await rows<{ rolname: string }>(
      'SELECT rolname FROM pg_catalog.pg_roles WHERE rolcanlogin ORDER BY 1',
    );
    expect(login.map((r) => r.rolname)).toEqual([
      'warifu_bootstrap',
      'warifu_company_api',
      'warifu_idp',
      'warifu_relay',
    ]);
    const supers = await rows<{ rolname: string }>(
      'SELECT rolname FROM pg_catalog.pg_roles WHERE rolsuper ORDER BY 1',
    );
    expect(supers.map((r) => r.rolname)).toEqual(['warifu_bootstrap']);
  });

  it('アプリのロールの属性と設定', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：アプリのロール、所有者、解決関数の所有者の属性と設定を読む
    // 期待する結果：アプリのロールは rolsuper、rolbypassrls、rolcreaterole、rolcreatedb、rolreplication、rolinherit が
    //               false。rolconfig に search_path="" と3つの時間切れがあり、warifu. で始まる設定がない。
    //               warifu_owner と warifu_alias_resolver はログインできず、同じく権限の属性がない
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const roles = await rows<{
      rolname: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolcreaterole: boolean;
      rolcreatedb: boolean;
      rolreplication: boolean;
      rolinherit: boolean;
      rolcanlogin: boolean;
      rolconfig: string[] | null;
    }>(
      `SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolinherit,
              rolcanlogin, rolconfig
         FROM pg_catalog.pg_roles WHERE rolname LIKE 'warifu\\_%' AND rolname <> 'warifu_bootstrap'
        ORDER BY 1`,
    );
    expect(roles.map((r) => r.rolname)).toEqual([
      'warifu_alias_resolver',
      'warifu_company_api',
      'warifu_idp',
      'warifu_owner',
      'warifu_relay',
    ]);
    for (const role of roles) {
      expect(role).toMatchObject({
        rolsuper: false,
        rolbypassrls: false,
        rolcreaterole: false,
        rolcreatedb: false,
        rolreplication: false,
        rolinherit: false,
      });
      if (APP_ROLES.includes(role.rolname)) {
        expect(role.rolcanlogin).toBe(true);
        expect([...(role.rolconfig ?? [])].sort()).toEqual([
          'idle_in_transaction_session_timeout=10s',
          'lock_timeout=3s',
          'search_path=""',
          'statement_timeout=5s',
        ]);
      } else {
        expect(role.rolcanlogin).toBe(false);
      }
      expect((role.rolconfig ?? []).filter((c) => c.startsWith('warifu.'))).toEqual([]);
    }
  });

  it('ロールの所属がない', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：pg_auth_members を読み、アプリのロールが所有者などの権限を継げないかを確かめる
    // 期待する結果：アプリのロール、warifu_owner、warifu_alias_resolver は、どのロールにも所属せず、どのロールも
    //               それらに所属していない
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const members = await rows<{ role: string; member: string }>(
      `SELECT pg_catalog.pg_get_userbyid(roleid) AS role, pg_catalog.pg_get_userbyid(member) AS member
         FROM pg_catalog.pg_auth_members`,
    );
    const ours = [...APP_ROLES, 'warifu_owner', 'warifu_alias_resolver'];
    expect(members.filter((m) => ours.includes(m.role) || ours.includes(m.member))).toEqual([]);
  });

  it('アプリのロールは、スキーマ、表、関数を所有しない', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07。所有者はポリシーを変えられ、FORCE を外せる）
    // 試す経路：pg_namespace、pg_class、pg_proc の所有者を読む
    // 期待する結果：アプリのロールが所有するものはない
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const owned = await rows<{ kind: string; name: string }>(
      `SELECT 'schema' AS kind, nspname AS name FROM pg_catalog.pg_namespace
        WHERE pg_catalog.pg_get_userbyid(nspowner) = ANY($1)
       UNION ALL
       SELECT 'relation', relname FROM pg_catalog.pg_class WHERE pg_catalog.pg_get_userbyid(relowner) = ANY($1)
       UNION ALL
       SELECT 'function', proname FROM pg_catalog.pg_proc WHERE pg_catalog.pg_get_userbyid(proowner) = ANY($1)`,
      [APP_ROLES],
    );
    expect(owned).toEqual([]);
  });

  it('ポリシーの一覧が、期待の一覧と完全に一致する', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：pg_policies を読む（表、名前、コマンド、ロール、USING、WITH CHECK）
    // 期待する結果：テストの中の一覧と完全に一致する。PUBLIC 向けのポリシーがない。USING (true) は resolver_select だけ
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const policies = await rows<{ line: string }>(
      `SELECT schemaname || '.' || tablename || '|' || policyname || '|' || cmd || '|' || roles::text || '|' ||
              COALESCE(qual, '') || '|' || COALESCE(with_check, '') AS line
         FROM pg_catalog.pg_policies ORDER BY schemaname, tablename, policyname`,
    );
    expect(policies.map((p) => p.line)).toEqual(POLICIES);
    expect(policies.filter((p) => p.line.includes('public'))).toEqual([]);
    expect(
      policies.filter((p) => /\|true\|/.test(p.line)).map((p) => p.line.split('|')[1]),
    ).toEqual(['resolver_select']);
  });

  it('アプリのロールには、表の単位の権限がなく、列の単位の権限が期待の一覧と一致する', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：aclexplode(relacl) と aclexplode(attacl) を読む
    // 期待する結果：アプリのロール（と解決関数の所有者）に表の単位の権限がない。列の単位の権限が一覧と完全に一致する
    //               （表の単位は、利用者の範囲の DELETE の3つと、relay のテナントの範囲の DELETE の3つだけ。
    //               UPDATE は列の単位だけ。TRUNCATE、REFERENCES、
    //               TRIGGER はない。lookup_mac はアプリのロールが読めない。idp の暗号文は、復号できないが読める）
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const roles = [...APP_ROLES, 'warifu_alias_resolver'];
    const tableGrants = await rows<{ t: string; grantee: string; priv: string }>(
      `SELECT n.nspname || '.' || c.relname AS t, pg_catalog.pg_get_userbyid(a.grantee) AS grantee,
              a.privilege_type AS priv
         FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace,
              pg_catalog.aclexplode(c.relacl) AS a
        WHERE n.nspname NOT IN ${SYSTEM_SCHEMAS} AND (a.grantee = 0 OR pg_catalog.pg_get_userbyid(a.grantee) = ANY($1))`,
      [roles],
    );
    expect(tableGrants.map((g) => `${g.t}|${g.grantee}|${g.priv}`).sort()).toEqual(TABLE_GRANTS);
    const columnGrants = await rows<{ t: string; grantee: string; priv: string; col: string }>(
      `SELECT n.nspname || '.' || c.relname AS t, pg_catalog.pg_get_userbyid(x.grantee) AS grantee,
              x.privilege_type AS priv, a.attname AS col
         FROM pg_catalog.pg_attribute AS a
         JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
         JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace,
              pg_catalog.aclexplode(a.attacl) AS x
        WHERE n.nspname NOT IN ${SYSTEM_SCHEMAS} AND a.attacl IS NOT NULL`,
    );
    const actual: Record<string, Record<string, Record<string, string[]>>> = {};
    for (const g of columnGrants) {
      const byRole = actual[g.t] ?? {};
      const byPriv = byRole[g.grantee] ?? {};
      byPriv[g.priv] = [...(byPriv[g.priv] ?? []), g.col];
      byRole[g.grantee] = byPriv;
      actual[g.t] = byRole;
    }
    for (const byRole of Object.values(actual)) {
      for (const byPriv of Object.values(byRole)) {
        for (const cols of Object.values(byPriv)) cols.sort();
      }
    }
    expect(actual).toEqual(COLUMN_GRANTS);
  });

  it('SECURITY DEFINER の関数は、relay の解決関数の1つだけ', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07。SECURITY DEFINER は RLS を越える経路になる）
    // 試す経路：pg_proc から prosecdef の関数を探し、所有者、設定、実行権限、戻り値を読む
    // 期待する結果：relay.resolve_alias(bytea) だけ。所有者は warifu_alias_resolver、search_path は
    //               pg_catalog, pg_temp に固定、EXECUTE は warifu_relay（と所有者）だけ、戻り値は2つの ID だけ
    // plan 11章：番号なし（不変条件8の例外。plan 2章「逆引きをしない」）
    const definers = await rows<{
      name: string;
      owner: string;
      config: string[] | null;
      result: string;
      oid: number;
    }>(
      `SELECT n.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS name,
              pg_catalog.pg_get_userbyid(p.proowner) AS owner, p.proconfig AS config,
              pg_catalog.pg_get_function_result(p.oid) AS result, p.oid::int AS oid
         FROM pg_catalog.pg_proc AS p JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ${SYSTEM_SCHEMAS}`,
    );
    expect(definers.map((d) => d.name)).toEqual(['relay.resolve_alias(p_lookup_mac bytea)']);
    const [resolver] = definers;
    expect(resolver?.owner).toBe('warifu_alias_resolver');
    expect(resolver?.config).toEqual(['search_path=pg_catalog, pg_temp']);
    expect(resolver?.result).toBe('TABLE(user_id uuid, tenant_id uuid)');
    const execute = await rows<{ grantee: string }>(
      `SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee
         FROM pg_catalog.pg_proc AS p, pg_catalog.aclexplode(p.proacl) AS a
        WHERE p.oid = $1 AND a.privilege_type = 'EXECUTE' ORDER BY 1`,
      [resolver?.oid],
    );
    expect(execute.map((e) => e.grantee)).toEqual(['warifu_alias_resolver', 'warifu_relay']);
  });

  it('割符の関数に、PUBLIC の EXECUTE がない', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07）
    // 試す経路：warifu、audit、aliases、relay のスキーマの関数の実行権限（既定を含む）を読む
    // 期待する結果：PUBLIC の EXECUTE がない
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const publicExecute = await rows<{ name: string }>(
      `SELECT n.nspname || '.' || p.proname AS name
         FROM pg_catalog.pg_proc AS p JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace,
              pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) AS a
        WHERE n.nspname IN ('warifu', 'audit', 'aliases', 'relay', 'idp', 'company_api', 'contacts', 'warifu_meta')
          AND a.grantee = 0`,
    );
    expect(publicExecute).toEqual([]);
  });

  it('スキーマの権限', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07。CREATE があると、関数や表を置いて検索の順を乗っ取れる）
    // 試す経路：has_schema_privilege と aclexplode(nspacl) を読む
    // 期待する結果：アプリのロールは、どのスキーマにも CREATE を持たない。public には PUBLIC の USAGE もない。
    //               warifu_meta にはアプリのロールの USAGE がない
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const create = await rows<{ role: string; schema: string }>(
      `SELECT r AS role, n.nspname AS schema
         FROM pg_catalog.pg_namespace AS n, pg_catalog.unnest($1::text[]) AS r
        WHERE pg_catalog.has_schema_privilege(r, n.oid, 'CREATE')`,
      [APP_ROLES],
    );
    expect(create).toEqual([]);
    const publicSchema = await rows<{ grantee: number }>(
      `SELECT a.grantee FROM pg_catalog.pg_namespace AS n, pg_catalog.aclexplode(n.nspacl) AS a
        WHERE n.nspname = 'public' AND a.grantee = 0`,
    );
    expect(publicSchema).toEqual([]);
    const meta = await rows<{ role: string }>(
      `SELECT r AS role FROM pg_catalog.unnest($1::text[]) AS r
        WHERE pg_catalog.has_schema_privilege(r, 'warifu_meta', 'USAGE')`,
      [APP_ROLES],
    );
    expect(meta).toEqual([]);
  });

  it('DB の権限：PUBLIC に CONNECT と TEMP がなく、アプリのロールは CONNECT だけ', async () => {
    // 攻撃者が持っている情報：同上（ATK-02、ATK-07。TEMP があると、pg_temp に表や関数を置いて名前を乗っ取れる）
    // 試す経路：いまの DB の datacl を読む
    // 期待する結果：PUBLIC の権限がない。アプリのロールは CONNECT だけ
    // plan 11章：番号なし（plan 10章 M2、2章「BOLA を防ぐ」）
    const acl = await rows<{ grantee: string; priv: string }>(
      `SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
              a.privilege_type AS priv
         FROM pg_catalog.pg_database AS d, pg_catalog.aclexplode(d.datacl) AS a
        WHERE d.datname = pg_catalog.current_database()`,
    );
    expect(acl.filter((a) => a.grantee === 'PUBLIC')).toEqual([]);
    for (const role of APP_ROLES) {
      expect(acl.filter((a) => a.grantee === role).map((a) => a.priv)).toEqual(['CONNECT']);
    }
  });
});
