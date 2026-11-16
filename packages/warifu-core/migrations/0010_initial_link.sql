-- 0010：既存会員の初回紐付けの正本と、続く記録と、利用者の索引と、待機と取消の SET（ADR 0020、ADR 0028）。
-- 企業の申請ID、移行専用ID、会員参照、証跡の原文、承認の JWT は置かない（不変条件4。ADR 0028 の O-92）。
-- 申請ID、移行専用ID、会員参照、証跡、証跡の jti は、照合用の MAC（initial_link_lookup）と、作ったときの鍵の版だけを置く。
-- 外に出す移行専用ID は、内部のレコード ID から MAC（initial_link_public_id）で、行に置いた版を使ってその都度導く
-- （ADR 0028 の O-87）。MAC は base64url の43文字（HMAC-SHA-256）。
SET ROLE warifu_owner;

-- 初回紐付けの正本（company-api。テナントの範囲。withTenant でだけ読み書きする）。
CREATE TABLE company_api.initial_links (
  -- 内部のレコード ID（乱数）。外に出す移行専用ID は、ここから public_id_version の鍵で導く。
  link_ref uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  -- 承認した割符の利用者。prepare の時点では決まっていない（最初の承認で、idp の内部 API が渡す）。
  user_id uuid,
  public_id_version integer NOT NULL CHECK (public_id_version >= 1),
  -- mac(initial_link_lookup, テナント‖"request"‖申請ID)、mac(…‖"link"‖移行専用ID)、mac(…‖"member"‖会員参照)。
  request_mac text NOT NULL CHECK (request_mac ~ '^[A-Za-z0-9_-]{43}$'),
  request_mac_version integer NOT NULL CHECK (request_mac_version >= 1),
  link_mac text NOT NULL CHECK (link_mac ~ '^[A-Za-z0-9_-]{43}$'),
  link_mac_version integer NOT NULL CHECK (link_mac_version >= 1),
  member_mac text NOT NULL CHECK (member_mac ~ '^[A-Za-z0-9_-]{43}$'),
  member_mac_version integer NOT NULL CHECK (member_mac_version >= 1),
  -- 申請に結び付けた、テナントの参加の状態の版と移行プロファイルの版（ADR 0028 の O-89・O-90）。
  participation_revision integer NOT NULL CHECK (participation_revision >= 0),
  profile_version integer NOT NULL CHECK (profile_version >= 1),
  -- 初回の証跡で決まるもの（方式と、企業の側の認証世代）。
  credential_kind text CHECK (credential_kind IN ('passkey', 'fido2')),
  auth_epoch bigint CHECK (auth_epoch >= 0),
  -- mac(initial_link_lookup, テナント‖"proof"‖JWS) と、その版（初回と最終）。
  initial_proof_mac text CHECK (initial_proof_mac ~ '^[A-Za-z0-9_-]{43}$'),
  initial_proof_mac_version integer CHECK (initial_proof_mac_version >= 1),
  final_proof_mac text CHECK (final_proof_mac ~ '^[A-Za-z0-9_-]{43}$'),
  final_proof_mac_version integer CHECK (final_proof_mac_version >= 1),
  state text NOT NULL CHECK (state IN (
    'prepared', 'pending_notice', 'pending_link', 'awaiting_final', 'approved',
    'linked', 'cancel_requested', 'cancelled', 'expired', 'not_linked'
  )),
  -- 状態を変えるたびに上げる（承認と取消と結果の報告の競合を、版の比較で決める。ADR 0028 の O-90）。
  state_version integer NOT NULL DEFAULT 0 CHECK (state_version >= 0),
  created_at timestamptz NOT NULL,
  -- 最初の承認の時刻と、idp の受信箱の項目のレコード ID（ADR 0028 の O-103）。
  approved_at timestamptz,
  item_ref uuid,
  -- 待機の知らせの SET に 202 が返った時刻（待機の起点）と、待機の満了と、親申請の期限（割符の時計）。
  wait_started_at timestamptz,
  wait_until timestamptz,
  parent_expires_at timestamptz,
  -- 紐付けの承認の JWT を出した時刻。
  final_approved_at timestamptz,
  -- 取消を受理した時刻と、取消の内部のレコード ID と、取消の出どころ。外に出す cancellation_id は cancel_ref から導く。
  cancel_ref uuid,
  cancel_accepted_at timestamptz,
  cancel_source text CHECK (cancel_source IN ('user', 'company')),
  -- 終端になった時刻と、消す予定の時刻（終端から7日。ADR 0028 の O-92）。終端でない行は消さない。
  terminal_at timestamptz,
  purge_after timestamptz,
  CONSTRAINT initial_links_request_key UNIQUE (tenant_id, request_mac),
  CONSTRAINT initial_links_link_key UNIQUE (tenant_id, link_mac),
  CHECK ((credential_kind IS NULL) = (auth_epoch IS NULL)),
  CHECK ((credential_kind IS NULL) = (initial_proof_mac IS NULL)),
  CHECK ((initial_proof_mac IS NULL) = (initial_proof_mac_version IS NULL)),
  CHECK ((final_proof_mac IS NULL) = (final_proof_mac_version IS NULL)),
  CHECK ((approved_at IS NULL) = (user_id IS NULL)),
  CHECK ((approved_at IS NULL) = (item_ref IS NULL)),
  CHECK ((wait_started_at IS NULL) = (wait_until IS NULL)),
  CHECK ((wait_started_at IS NULL) = (parent_expires_at IS NULL)),
  CHECK (wait_until IS NULL OR wait_until > wait_started_at),
  CHECK (parent_expires_at IS NULL OR parent_expires_at > wait_until),
  CHECK ((cancel_ref IS NULL) = (cancel_accepted_at IS NULL)),
  CHECK ((cancel_ref IS NULL) = (cancel_source IS NULL)),
  CHECK ((state IN ('linked', 'cancelled', 'expired', 'not_linked')) = (terminal_at IS NOT NULL)),
  CHECK ((terminal_at IS NULL) = (purge_after IS NULL)),
  CHECK (state <> 'prepared' OR (approved_at IS NULL AND cancel_ref IS NULL)),
  CHECK (state NOT IN ('pending_notice', 'pending_link', 'awaiting_final', 'approved', 'linked')
         OR (approved_at IS NOT NULL AND initial_proof_mac IS NOT NULL AND cancel_ref IS NULL)),
  CHECK (state <> 'pending_notice' OR wait_started_at IS NULL),
  CHECK (state NOT IN ('pending_link', 'awaiting_final', 'approved', 'linked') OR wait_started_at IS NOT NULL),
  CHECK (state NOT IN ('approved', 'linked') OR (final_approved_at IS NOT NULL AND final_proof_mac IS NOT NULL)),
  CHECK (state NOT IN ('cancel_requested', 'cancelled') OR cancel_ref IS NOT NULL)
);
-- 1人の割符の利用者（テナントの範囲）につき、同時に開いている申請は1件（ADR 0028 の O-87）。
CREATE UNIQUE INDEX initial_links_open_per_user ON company_api.initial_links (tenant_id, user_id)
  WHERE user_id IS NOT NULL AND terminal_at IS NULL;
CREATE UNIQUE INDEX initial_links_item_ref ON company_api.initial_links (tenant_id, item_ref)
  WHERE item_ref IS NOT NULL;

-- 紐付けが済んだ後の続く記録（company-api。テナントの範囲。ADR 0028 の O-92）。再度の紐付けを防ぎ、
-- 移行中に紐付けたかを区別する。紐付け済みは、1人の割符の利用者（テナントの範囲）につき1件。
CREATE TABLE company_api.initial_link_records (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  credential_kind text NOT NULL CHECK (credential_kind IN ('passkey', 'fido2')),
  profile_version integer NOT NULL CHECK (profile_version >= 1),
  -- 紐付けたときの参加の状態（移行中に紐付けたか。ADR 0028 の O-98）。
  participation text NOT NULL CHECK (participation IN ('full', 'migrating')),
  linked_on date NOT NULL,
  initial_proof_mac text NOT NULL CHECK (initial_proof_mac ~ '^[A-Za-z0-9_-]{43}$'),
  initial_proof_mac_version integer NOT NULL CHECK (initial_proof_mac_version >= 1),
  final_proof_mac text NOT NULL CHECK (final_proof_mac ~ '^[A-Za-z0-9_-]{43}$'),
  final_proof_mac_version integer NOT NULL CHECK (final_proof_mac_version >= 1),
  PRIMARY KEY (tenant_id, user_id)
);

-- 証跡の jti の使い済み（5分。ADR 0028 の O-88）。jti は mac(initial_link_lookup, テナント‖"jti"‖jti) だけを置く。
CREATE TABLE company_api.initial_link_proof_jtis (
  tenant_id uuid NOT NULL,
  jti_mac text NOT NULL CHECK (jti_mac ~ '^[A-Za-z0-9_-]{43}$'),
  jti_mac_version integer NOT NULL CHECK (jti_mac_version >= 1),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, jti_mac)
);
CREATE INDEX initial_link_proof_jtis_expires ON company_api.initial_link_proof_jtis (tenant_id, expires_at);

-- 利用者の索引（idp。利用者の範囲。withWarifuUser でだけ読み書きする）。受信箱に出す項目と、取消の入り口のため。
-- 状態の正本は company-api にある。ここには、承認の手順の途中かどうかと、終端を知った後の消す予定だけを置く。
CREATE TABLE idp.initial_link_items (
  item_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  tenant_id uuid NOT NULL,
  link_ref uuid NOT NULL UNIQUE,
  -- approving：正本に記録する前。approved：正本に記録した。closed：正本が終端だと知った（purge_after に消す）。
  state text NOT NULL CHECK (state IN ('approving', 'approved', 'closed')),
  created_at timestamptz NOT NULL,
  purge_after timestamptz,
  CHECK ((state = 'closed') = (purge_after IS NOT NULL)),
  CHECK (purge_after IS NULL OR purge_after > created_at)
);
CREATE INDEX initial_link_items_user_created ON idp.initial_link_items (user_id, created_at);

-- 待機の知らせの SET と、初回紐付けの取消の SET（ADR 0028 の O-91・O-103）。窓口の取消の SET と同じ送信待ちで送る。
-- 中身（移行専用ID と取消ID）は、送るときに正本から、行に置いた版で導く。
ALTER TABLE company_api.set_outbox DROP CONSTRAINT set_outbox_event_type_check;
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_event_type_check
  CHECK (event_type IN (
    'verification', 'desk_cancellation', 'account_recovered',
    'initial_link_waiting', 'initial_link_cancellation'
  ));
ALTER TABLE company_api.set_outbox ADD COLUMN link_ref uuid;
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_link_ref_check CHECK (
    (event_type IN ('initial_link_waiting', 'initial_link_cancellation')) = (link_ref IS NOT NULL)
  );
-- 同じ申請の、同じ種類の SET は1件だけ（承認や取消の再送で、二重に入れない）。
CREATE UNIQUE INDEX set_outbox_link_event ON company_api.set_outbox (tenant_id, link_ref, event_type)
  WHERE link_ref IS NOT NULL;

ALTER TABLE company_api.initial_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_api.initial_links FORCE ROW LEVEL SECURITY;
ALTER TABLE company_api.initial_link_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_api.initial_link_records FORCE ROW LEVEL SECURITY;
ALTER TABLE company_api.initial_link_proof_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_api.initial_link_proof_jtis FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.initial_link_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.initial_link_items FORCE ROW LEVEL SECURITY;

CREATE POLICY company_api_select ON company_api.initial_links FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON company_api.initial_links FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_update ON company_api.initial_links FOR UPDATE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id()) WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_delete ON company_api.initial_links FOR DELETE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());

-- 続く記録は、足すことと読むことだけ（書き換えない。消すのは M10 で決める）。
CREATE POLICY company_api_select ON company_api.initial_link_records FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON company_api.initial_link_records FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id());

CREATE POLICY company_api_select ON company_api.initial_link_proof_jtis FOR SELECT TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_insert ON company_api.initial_link_proof_jtis FOR INSERT TO warifu_company_api
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY company_api_delete ON company_api.initial_link_proof_jtis FOR DELETE TO warifu_company_api
  USING (tenant_id = warifu.current_tenant_id());

CREATE POLICY idp_select ON idp.initial_link_items FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.initial_link_items FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.initial_link_items FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.initial_link_items FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- 列単位の権限。作った後に変えられるのは、利用者（最初の承認で一度だけ）、証跡の結果、状態と、その時刻と期限だけ
-- （テナント、索引の MAC と版、移行専用ID の版、参加の状態とプロファイルの版は変えられない）。
GRANT SELECT (link_ref, tenant_id, user_id, public_id_version, request_mac, request_mac_version, link_mac,
              link_mac_version, member_mac, member_mac_version, participation_revision, profile_version,
              credential_kind, auth_epoch, initial_proof_mac, initial_proof_mac_version, final_proof_mac,
              final_proof_mac_version, state, state_version, created_at, approved_at, item_ref, wait_started_at,
              wait_until, parent_expires_at, final_approved_at, cancel_ref, cancel_accepted_at, cancel_source,
              terminal_at, purge_after),
      INSERT (link_ref, tenant_id, public_id_version, request_mac, request_mac_version, link_mac,
              link_mac_version, member_mac, member_mac_version, participation_revision, profile_version, state,
              created_at),
      UPDATE (user_id, credential_kind, auth_epoch, initial_proof_mac, initial_proof_mac_version, final_proof_mac,
              final_proof_mac_version, state, state_version, approved_at, item_ref, wait_started_at, wait_until,
              parent_expires_at, final_approved_at, cancel_ref, cancel_accepted_at, cancel_source, terminal_at,
              purge_after)
  ON company_api.initial_links TO warifu_company_api;
GRANT DELETE ON company_api.initial_links TO warifu_company_api;

GRANT SELECT (tenant_id, user_id, credential_kind, profile_version, participation, linked_on, initial_proof_mac,
              initial_proof_mac_version, final_proof_mac, final_proof_mac_version),
      INSERT (tenant_id, user_id, credential_kind, profile_version, participation, linked_on, initial_proof_mac,
              initial_proof_mac_version, final_proof_mac, final_proof_mac_version)
  ON company_api.initial_link_records TO warifu_company_api;

GRANT SELECT (tenant_id, jti_mac, jti_mac_version, expires_at),
      INSERT (tenant_id, jti_mac, jti_mac_version, expires_at)
  ON company_api.initial_link_proof_jtis TO warifu_company_api;
GRANT DELETE ON company_api.initial_link_proof_jtis TO warifu_company_api;

GRANT SELECT (item_id, user_id, tenant_id, link_ref, state, created_at, purge_after),
      INSERT (item_id, user_id, tenant_id, link_ref, state, created_at),
      UPDATE (state, purge_after)
  ON idp.initial_link_items TO warifu_idp;
GRANT DELETE ON idp.initial_link_items TO warifu_idp;

GRANT SELECT (link_ref), INSERT (link_ref) ON company_api.set_outbox TO warifu_company_api;

RESET ROLE;
