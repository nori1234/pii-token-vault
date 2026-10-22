-- 0003：別名の世代と、relay の解決関数（不変条件8の例外の SECURITY DEFINER 関数。ADR 0005、ADR 0014）。
-- 別名そのものは置かない。照合用の HMAC（鍵サービスの mac(alias_lookup)）だけを置き、一意にする（二度と割り当てない）。
-- 世代は足すだけ。最新でない世代が廃番。UPDATE と DELETE はどのロールにも与えない。
SET ROLE warifu_owner;

CREATE TABLE aliases.generation (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  generation integer NOT NULL CHECK (generation >= 1),
  lookup_mac bytea NOT NULL CHECK (octet_length(lookup_mac) = 32),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  PRIMARY KEY (tenant_id, user_id, generation),
  CONSTRAINT generation_lookup_mac_key UNIQUE (lookup_mac)
);
ALTER TABLE aliases.generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE aliases.generation FORCE ROW LEVEL SECURITY;

-- 解決関数の所有者だけが、テナントを横断して読める（USING (true) はこのポリシーだけ）。
CREATE POLICY resolver_select ON aliases.generation FOR SELECT TO warifu_alias_resolver USING (true);
-- idp：利用者のルート（withWarifuUser）と、OIDC の発行（withTenant）で読む。最初の世代だけを書く（M3 で見直す）。
CREATE POLICY idp_select ON aliases.generation FOR SELECT TO warifu_idp
  USING (tenant_id = warifu.current_tenant_id() OR user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON aliases.generation FOR INSERT TO warifu_idp
  WITH CHECK (tenant_id = warifu.current_tenant_id() AND generation = 1);
-- company-api：自分のテナントの中で、再発行（第2世代以降）だけを書く（M5）。
CREATE POLICY company_api_select ON aliases.generation FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON aliases.generation FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id() AND generation >= 2);

GRANT USAGE ON SCHEMA aliases TO warifu_idp, warifu_company_api, warifu_alias_resolver;
GRANT SELECT (tenant_id, user_id, generation, lookup_mac) ON aliases.generation TO warifu_alias_resolver;
-- アプリのロールは lookup_mac を書けるが読めない。
GRANT SELECT (tenant_id, user_id, generation, created_at), INSERT (tenant_id, user_id, generation, lookup_mac)
  ON aliases.generation TO warifu_idp, warifu_company_api;

-- relay の唯一の横断の手段。返すのは2つの ID だけ。最新の世代だけを返す。
-- 廃番、存在しない、長さの違う入力、NULL は、どれも同じ「0行」。
CREATE FUNCTION relay.resolve_alias(p_lookup_mac bytea)
  RETURNS TABLE (user_id uuid, tenant_id uuid)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
  AS $f$
    SELECT g.user_id, g.tenant_id
      FROM aliases.generation AS g
     WHERE pg_catalog.octet_length(p_lookup_mac) = 32
       AND g.lookup_mac = p_lookup_mac
       AND g.generation = (
             SELECT pg_catalog.max(h.generation) FROM aliases.generation AS h
              WHERE h.tenant_id = g.tenant_id AND h.user_id = g.user_id)
  $f$;

RESET ROLE;

ALTER FUNCTION relay.resolve_alias(bytea) OWNER TO warifu_alias_resolver;
REVOKE ALL ON FUNCTION relay.resolve_alias(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay.resolve_alias(bytea) TO warifu_relay;
