-- 0006：企業別ID（sub）の索引と、SET の送信待ち（ADR 0022）。どの表も、テナントの範囲（withTenant）でだけ読み書きする。
-- テナントの登録（参加の状態を含む）は DB に置かず、配備のときの静的な設定にする（ADR 0022）。企業向けのルートから
-- 書き換えられる参加の状態の列は、そもそも作らない（ADR 0010、テスト6）。
SET ROLE warifu_owner;

-- 企業別ID（sub）から利用者を引く索引。企業が sub で別名の入れ替えを頼むときに使う（plan 3-2）。
-- sub は秘密ではない（CLAUDE.md の用語）が、企業に渡す値なので、テナントの中でだけ引ける。
-- idp が接続の同意のときに置く（sub の導出は idp だけ。ADR 0018）。追記だけ。
CREATE TABLE aliases.subject (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  sub text NOT NULL CHECK (sub ~ '^[A-Za-z0-9_-]{43}$'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  PRIMARY KEY (tenant_id, user_id),
  CONSTRAINT subject_tenant_sub_key UNIQUE (tenant_id, sub)
);

-- SET の送信待ち（RFC 8417、RFC 8935）。署名した SET は置かない（不変条件4。送るときに署名する）。
-- 置くのは、イベントの種類と、送る中身の材料（検証のイベントの state）と、送る時刻と回数だけ。
-- jti と iat は初めて送るときに決めて置き、再送でも同じ値にする（RFC 8935 の再送）。送れたら、または諦めたら消す。
CREATE TABLE company_api.set_outbox (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('verification')),
  state text CHECK (state ~ '^[A-Za-z0-9._~-]{1,64}$'),
  jti text CHECK (jti ~ '^[A-Za-z0-9_-]{22}$'),
  issued_at timestamptz,
  deliver_after timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 16),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CHECK ((jti IS NULL) = (issued_at IS NULL))
);
CREATE INDEX set_outbox_due ON company_api.set_outbox (tenant_id, deliver_after);

ALTER TABLE aliases.subject ENABLE ROW LEVEL SECURITY;
ALTER TABLE aliases.subject FORCE ROW LEVEL SECURITY;
ALTER TABLE company_api.set_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_api.set_outbox FORCE ROW LEVEL SECURITY;

-- idp：接続の同意のときに、テナントの範囲で置く。読むのは、置いたかどうかの確かめだけ。
CREATE POLICY idp_select ON aliases.subject FOR SELECT TO warifu_idp
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY idp_insert ON aliases.subject FOR INSERT TO warifu_idp
  WITH CHECK (tenant_id = warifu.current_tenant_id());
-- company-api：自分のテナントの中で、sub から利用者を引く。
CREATE POLICY company_api_select ON aliases.subject FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());

CREATE POLICY company_api_select ON company_api.set_outbox FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON company_api.set_outbox FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_update ON company_api.set_outbox FOR UPDATE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id()) WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_delete ON company_api.set_outbox FOR DELETE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());

-- 列単位の権限。idp は sub を置けるが、ほかの利用者の行は読めない（テナントの範囲の中でも、置いた行の確かめだけ）。
GRANT SELECT (tenant_id, user_id, created_at), INSERT (tenant_id, user_id, sub)
  ON aliases.subject TO warifu_idp;
GRANT SELECT (tenant_id, user_id, sub) ON aliases.subject TO warifu_company_api;
GRANT SELECT (event_id, tenant_id, event_type, state, jti, issued_at, deliver_after, attempts, created_at),
      INSERT (event_id, tenant_id, event_type, state, deliver_after),
      UPDATE (jti, issued_at, deliver_after, attempts)
  ON company_api.set_outbox TO warifu_company_api;
GRANT DELETE ON company_api.set_outbox TO warifu_company_api;

RESET ROLE;
