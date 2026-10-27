-- 0002：監査ログ（CAP-17、ADR 0016）。全体のチェーン（範囲の情報を持たない）と、範囲を RLS で限った本文。
-- MAC は鍵サービスの mac(audit_chain)。追記だけ。
SET ROLE warifu_owner;

-- 全体のチェーン。テナントも利用者も持たない（通番と MAC だけ）。
CREATE TABLE audit.chain (
  seq bigint PRIMARY KEY CHECK (seq >= 1),
  content_mac bytea NOT NULL CHECK (octet_length(content_mac) = 32),
  prev_mac bytea NOT NULL CHECK (octet_length(prev_mac) = 32),
  mac bytea NOT NULL CHECK (octet_length(mac) = 32)
);

-- 本文。範囲はテナントか利用者のどちらか1つ。属性に値（連絡先、トークンなど）を入れない（ADR 0016）。
CREATE TABLE audit.events (
  seq bigint PRIMARY KEY REFERENCES audit.chain (seq),
  scope_seq bigint NOT NULL CHECK (scope_seq >= 1),
  occurred_at timestamptz NOT NULL,
  service text NOT NULL CHECK (service IN ('idp', 'relay', 'company-api')),
  event_type text NOT NULL
    CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND octet_length(event_type) <= 64),
  tenant_id uuid,
  user_id uuid,
  attrs jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(attrs) = 'object' AND octet_length(attrs::text) <= 2048),
  CONSTRAINT events_one_scope CHECK (num_nonnulls(tenant_id, user_id) = 1)
);
CREATE UNIQUE INDEX events_tenant_scope_seq ON audit.events (tenant_id, scope_seq) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX events_user_scope_seq ON audit.events (user_id, scope_seq) WHERE user_id IS NOT NULL;

ALTER TABLE audit.chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.chain FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.events FORCE ROW LEVEL SECURITY;

-- チェーンは、境界の中でだけ読み書きできる（境界の外からは0行）。
CREATE POLICY chain_select ON audit.chain FOR SELECT
  TO warifu_idp, warifu_relay, warifu_company_api USING (warifu.has_boundary());
CREATE POLICY chain_insert ON audit.chain FOR INSERT
  TO warifu_idp, warifu_relay, warifu_company_api WITH CHECK (warifu.has_boundary());
-- 本文は、いまの範囲だけ。書けるのは、いまの範囲と、自分のサービスの名前だけ。
CREATE POLICY events_select ON audit.events FOR SELECT
  TO warifu_idp, warifu_relay, warifu_company_api
  USING (tenant_id = warifu.current_tenant_id() OR user_id = warifu.current_user_id());
CREATE POLICY events_insert ON audit.events FOR INSERT
  TO warifu_idp, warifu_relay, warifu_company_api
  WITH CHECK (
    service = warifu.service_of(current_user)
    AND ((tenant_id = warifu.current_tenant_id() AND user_id IS NULL)
      OR (user_id = warifu.current_user_id() AND tenant_id IS NULL)));

GRANT USAGE ON SCHEMA audit TO warifu_idp, warifu_relay, warifu_company_api;
-- 列単位の SELECT と INSERT だけ。UPDATE、DELETE、TRUNCATE、REFERENCES、TRIGGER は付与しない。
GRANT SELECT (seq, content_mac, prev_mac, mac), INSERT (seq, content_mac, prev_mac, mac)
  ON audit.chain TO warifu_idp, warifu_relay, warifu_company_api;
GRANT SELECT (seq, scope_seq, occurred_at, service, event_type, tenant_id, user_id, attrs),
      INSERT (seq, scope_seq, occurred_at, service, event_type, tenant_id, user_id, attrs)
  ON audit.events TO warifu_idp, warifu_relay, warifu_company_api;

-- 所有者の権限でも書き換えさせない（マイグレーションの誤りへの備え）。スーパーユーザーはトリガーも外せるので、
-- 改ざんの検出は HMAC のチェーンに頼る。
CREATE FUNCTION audit.reject_mutation() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
  AS $f$ BEGIN RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit log is append-only'; END $f$;
CREATE TRIGGER chain_append_only BEFORE UPDATE OR DELETE ON audit.chain
  FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();
CREATE TRIGGER chain_no_truncate BEFORE TRUNCATE ON audit.chain
  FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON audit.events
  FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON audit.events
  FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

RESET ROLE;
