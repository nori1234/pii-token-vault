-- 0001：ロール、スキーマ、境界の関数（不変条件8、ADR 0015）。
-- マイグレーション（不変条件8の例外）として、ブートストラップのロールで流す（scripts/migrate.ts）。
-- ロールはクラスタ全体のもの。テンプレートとワーカーの DB で共有するので、すでにあれば属性をそろえ直す。
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('warifu_owner', false),
      ('warifu_alias_resolver', false),
      ('warifu_idp', true),
      ('warifu_relay', true),
      ('warifu_company_api', true)
    ) AS t(name, login)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r.name) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I', r.name);
    END IF;
    EXECUTE pg_catalog.format(
      'ALTER ROLE %I %s NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
      r.name, CASE WHEN r.login THEN 'LOGIN' ELSE 'NOLOGIN' END);
    IF r.login THEN
      -- 名前は必ずスキーマで修飾させる（検索の順を乗っ取らせない）。
      EXECUTE pg_catalog.format('ALTER ROLE %I SET search_path TO %L', r.name, '');
      EXECUTE pg_catalog.format('ALTER ROLE %I SET statement_timeout TO %L', r.name, '5s');
      EXECUTE pg_catalog.format('ALTER ROLE %I SET lock_timeout TO %L', r.name, '3s');
      EXECUTE pg_catalog.format('ALTER ROLE %I SET idle_in_transaction_session_timeout TO %L', r.name, '10s');
    END IF;
  END LOOP;
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA warifu AUTHORIZATION warifu_owner;       -- 境界の関数
CREATE SCHEMA warifu_meta AUTHORIZATION warifu_owner;  -- マイグレーションの記録（アプリのロールからは見えない）
CREATE SCHEMA audit AUTHORIZATION warifu_owner;        -- 監査ログ（0002）
CREATE SCHEMA aliases AUTHORIZATION warifu_owner;      -- 別名の世代（0003）
CREATE SCHEMA idp AUTHORIZATION warifu_owner;          -- idp の表（M3 から）
CREATE SCHEMA relay AUTHORIZATION warifu_owner;        -- relay の表（M4 から）と解決関数（0003）
CREATE SCHEMA company_api AUTHORIZATION warifu_owner;  -- company-api の表（M5 から）

-- warifu_owner が作る関数は、既定では誰も実行できない。要るロールにだけ明示して付与する。
ALTER DEFAULT PRIVILEGES FOR ROLE warifu_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

SET ROLE warifu_owner;

CREATE TABLE warifu_meta.migrations (
  version integer PRIMARY KEY CHECK (version >= 1),
  name text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT pg_catalog.now()
);
-- 全テーブルに ENABLE と FORCE。ポリシーも GRANT も付けない（アプリのロールからは見えない）。
ALTER TABLE warifu_meta.migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE warifu_meta.migrations FORCE ROW LEVEL SECURITY;

-- 境界の値。未設定と空文字は NULL になり、どのポリシーにも一致しない（閉じる側に倒す）。SECURITY INVOKER。
CREATE FUNCTION warifu.current_tenant_id() RETURNS pg_catalog.uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $f$ SELECT NULLIF(pg_catalog.current_setting('warifu.tenant_id', true), '')::pg_catalog.uuid $f$;
CREATE FUNCTION warifu.current_user_id() RETURNS pg_catalog.uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $f$ SELECT NULLIF(pg_catalog.current_setting('warifu.user_id', true), '')::pg_catalog.uuid $f$;
CREATE FUNCTION warifu.has_boundary() RETURNS boolean
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $f$ SELECT warifu.current_tenant_id() IS NOT NULL OR warifu.current_user_id() IS NOT NULL $f$;
-- 監査ログの service 列を、書き込んだロールに結び付ける。
CREATE FUNCTION warifu.service_of(role_name pg_catalog.name) RETURNS pg_catalog.text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  AS $f$
    SELECT CASE role_name
      WHEN 'warifu_idp' THEN 'idp'
      WHEN 'warifu_relay' THEN 'relay'
      WHEN 'warifu_company_api' THEN 'company-api'
    END
  $f$;

GRANT USAGE ON SCHEMA warifu TO warifu_idp, warifu_relay, warifu_company_api;
GRANT EXECUTE ON FUNCTION warifu.current_tenant_id(), warifu.current_user_id(), warifu.has_boundary(),
  warifu.service_of(pg_catalog.name) TO warifu_idp, warifu_relay, warifu_company_api;
GRANT USAGE ON SCHEMA idp TO warifu_idp;
GRANT USAGE ON SCHEMA relay TO warifu_relay;
GRANT USAGE ON SCHEMA company_api TO warifu_company_api;

RESET ROLE;
