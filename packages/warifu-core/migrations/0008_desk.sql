-- 0008：窓口の操作別承認の作成の正本と、利用者の索引と、取消の SET（ADR 0019、ADR 0026）。
-- 照会の承認は、割符に状態を残さない（ADR 0026 の O-63）。ここに置くのは、作成（desk.case.create）の承認だけ。
-- 申請ID、変更ID、取消要求ID の原値は置かない（不変条件4）。申請ID と変更ID は照合用の MAC（desk_lookup）だけ、
-- 変更ID と取消要求ID は内部のレコード ID から MAC（desk_id）でその都度導く（ADR 0026 の O-64）。
SET ROLE warifu_owner;

-- 作成の正本（company-api。テナントの範囲。withTenant でだけ読み書きする）。
CREATE TABLE company_api.desk_changes (
  -- 内部のレコード ID（乱数）。外に出す変更ID は、ここから導く。idp の desk_items と同じ値。
  change_ref uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  -- 承認した利用者（idp の内部 API が渡す）。内部 API で、頼んだ利用者と同じかを確かめるため。
  user_id uuid NOT NULL,
  -- mac(desk_lookup, テナント‖"request"‖申請ID) と mac(desk_lookup, テナント‖"change"‖変更ID)。
  request_mac text NOT NULL CHECK (request_mac ~ '^[A-Za-z0-9_-]{43}$'),
  change_mac text NOT NULL CHECK (change_mac ~ '^[A-Za-z0-9_-]{43}$'),
  action text NOT NULL CHECK (action IN ('desk.case.create')),
  state text NOT NULL
    CHECK (state IN ('awaiting_notice', 'created', 'cancel_requested', 'cancelled', 'not_created', 'closed')),
  approved_at timestamptz NOT NULL,
  -- 作成の知らせを記録した時刻と、そこから決めた取消期限（割符の時計）。
  notice_at timestamptz,
  cancel_closes_at timestamptz,
  -- 取消要求の内部のレコード ID と、受理した時刻（割符の時計）。外に出す取消要求ID は cancel_ref から導く。
  cancel_ref uuid,
  cancel_accepted_at timestamptz,
  -- 終端になった時刻と、消す予定の時刻（終端から7日。ADR 0026 の O-69）。終端でない行は消さない。
  terminal_at timestamptz,
  purge_after timestamptz,
  CONSTRAINT desk_changes_request_key UNIQUE (tenant_id, request_mac),
  CONSTRAINT desk_changes_change_key UNIQUE (tenant_id, change_mac),
  CHECK ((notice_at IS NULL) = (cancel_closes_at IS NULL)),
  CHECK (cancel_closes_at IS NULL OR cancel_closes_at > notice_at),
  CHECK ((cancel_ref IS NULL) = (cancel_accepted_at IS NULL)),
  CHECK ((state IN ('cancelled', 'not_created', 'closed')) = (terminal_at IS NOT NULL)),
  CHECK ((terminal_at IS NULL) = (purge_after IS NULL)),
  CHECK (state <> 'awaiting_notice' OR (notice_at IS NULL AND cancel_ref IS NULL)),
  CHECK (state <> 'created' OR (notice_at IS NOT NULL AND cancel_ref IS NULL)),
  CHECK (state NOT IN ('cancel_requested', 'cancelled') OR cancel_ref IS NOT NULL),
  CHECK (state <> 'closed' OR (notice_at IS NOT NULL AND cancel_ref IS NULL)),
  CHECK (state <> 'not_created' OR notice_at IS NULL)
);

-- 利用者の索引（idp。利用者の範囲。withWarifuUser でだけ読み書きする）。受信箱に出す項目と、取消の入り口のため。
-- 状態の正本は company-api にある。ここには、承認の手順の途中かどうかと、終端を知った後の消す予定だけを置く。
CREATE TABLE idp.desk_items (
  item_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  tenant_id uuid NOT NULL,
  change_ref uuid NOT NULL UNIQUE,
  action text NOT NULL CHECK (action IN ('desk.case.create')),
  -- approving：正本に記録する前。approved：正本に記録した。closed：正本が終端だと知った（purge_after に消す）。
  state text NOT NULL CHECK (state IN ('approving', 'approved', 'closed')),
  created_at timestamptz NOT NULL,
  purge_after timestamptz,
  CHECK ((state = 'closed') = (purge_after IS NOT NULL)),
  CHECK (purge_after IS NULL OR purge_after > created_at)
);
CREATE INDEX desk_items_user_created ON idp.desk_items (user_id, created_at);

-- 取消の SET（ADR 0026 の O-67）。送信待ちに、種類と、正本の行への参照と、保留と、送り直しの回数を足す。
-- 取消の SET は諦めて消さない（回数の上限を外す）。中身（変更ID と取消要求ID）は、送るときに正本から導く。
ALTER TABLE company_api.set_outbox DROP CONSTRAINT set_outbox_event_type_check;
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_event_type_check CHECK (event_type IN ('verification', 'desk_cancellation'));
ALTER TABLE company_api.set_outbox DROP CONSTRAINT set_outbox_attempts_check;
ALTER TABLE company_api.set_outbox ADD CONSTRAINT set_outbox_attempts_check CHECK (attempts >= 0);
ALTER TABLE company_api.set_outbox ADD COLUMN change_ref uuid;
ALTER TABLE company_api.set_outbox ADD COLUMN held boolean NOT NULL DEFAULT false;
ALTER TABLE company_api.set_outbox ADD COLUMN reissues integer NOT NULL DEFAULT 0 CHECK (reissues BETWEEN 0 AND 16);
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_change_ref_check CHECK ((event_type = 'desk_cancellation') = (change_ref IS NOT NULL));
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_state_check2 CHECK (event_type = 'verification' OR state IS NULL);

ALTER TABLE company_api.desk_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_api.desk_changes FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.desk_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.desk_items FORCE ROW LEVEL SECURITY;

CREATE POLICY company_api_select ON company_api.desk_changes FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON company_api.desk_changes FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_update ON company_api.desk_changes FOR UPDATE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id()) WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_delete ON company_api.desk_changes FOR DELETE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());

CREATE POLICY idp_select ON idp.desk_items FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.desk_items FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.desk_items FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.desk_items FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- 列単位の権限。作った後に変えられるのは、状態と、その時刻と期限だけ（テナント、利用者、索引、操作は変えられない）。
GRANT SELECT (change_ref, tenant_id, user_id, request_mac, change_mac, action, state, approved_at, notice_at,
              cancel_closes_at, cancel_ref, cancel_accepted_at, terminal_at, purge_after),
      INSERT (change_ref, tenant_id, user_id, request_mac, change_mac, action, state, approved_at),
      UPDATE (state, notice_at, cancel_closes_at, cancel_ref, cancel_accepted_at, terminal_at, purge_after)
  ON company_api.desk_changes TO warifu_company_api;
GRANT DELETE ON company_api.desk_changes TO warifu_company_api;

GRANT SELECT (item_id, user_id, tenant_id, change_ref, action, state, created_at, purge_after),
      INSERT (item_id, user_id, tenant_id, change_ref, action, state, created_at),
      UPDATE (state, purge_after)
  ON idp.desk_items TO warifu_idp;
GRANT DELETE ON idp.desk_items TO warifu_idp;

GRANT SELECT (change_ref, held, reissues), INSERT (change_ref), UPDATE (held, reissues)
  ON company_api.set_outbox TO warifu_company_api;

RESET ROLE;
