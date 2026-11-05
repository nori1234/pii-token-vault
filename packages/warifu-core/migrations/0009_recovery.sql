-- 0009：回復（plan 4章、ADR 0003、ADR 0027）。利用者の範囲（withWarifuUser）でだけ読み書きする。
-- - 回復コードは平文で置かない。照合用の mac(recovery_code, …) だけ（不変条件4、ADR 0012 の決定4）。
-- - 協力関係は、内部 ID の組だけ（PRN-91）。表示名は協力者の端末の中だけに置く。
-- - 招待と、協力者の承認の結び付けは、プロセスのメモリに置き、DB には置かない（ADR 0027 の O-74、O-76）。
-- - 協力者への知らせは、持ち主の変更と同じトランザクションで送信待ち（idp.helper_notice_outbox）に置き、確定の後に
--   協力者の受信箱へ移す（失敗しても後で送り直す。ADR 0027 の O-79）。
SET ROLE warifu_owner;

-- 回復の後の制限（7日）と、取消の後に回復を始められない期間（14日）。
ALTER TABLE idp.users ADD COLUMN recovered_at timestamptz;
ALTER TABLE idp.users ADD COLUMN recovery_locked_until timestamptz;

-- パスキーの状態。pending は、回復の途中で新しい端末に作ったもの（ログインにも承認にも使えない）。
-- suspended は、回復が成立したときに一時停止したもの（ADR 0003）。
ALTER TABLE idp.credentials ADD COLUMN state text NOT NULL DEFAULT 'active'
  CHECK (state IN ('active', 'suspended', 'pending'));
ALTER TABLE idp.credentials ADD COLUMN recovery_attempt_id uuid;
ALTER TABLE idp.credentials
  ADD CONSTRAINT credentials_pending_attempt CHECK ((state = 'pending') = (recovery_attempt_id IS NOT NULL));

-- 回復コード。利用者ごとに1つ。
CREATE TABLE idp.recovery_codes (
  user_id uuid PRIMARY KEY REFERENCES idp.users (user_id),
  code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
  created_at timestamptz NOT NULL
);

-- 協力関係。P0 は持ち主ごとに1人（ADR 0003）。relationship_id は、協力者の端末が表示名を引くためだけに使う。
CREATE TABLE idp.helpers (
  relationship_id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL UNIQUE REFERENCES idp.users (user_id),
  helper_user_id uuid NOT NULL REFERENCES idp.users (user_id),
  created_at timestamptz NOT NULL,
  CHECK (owner_user_id <> helper_user_id)
);
CREATE INDEX helpers_helper ON idp.helpers (helper_user_id);

-- 回復の記録。進行中（awaiting_helper、waiting）は、利用者ごとに1つだけ。
CREATE TABLE idp.recovery_attempts (
  attempt_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  -- 始めた時点の協力者（協力者を入れ替えても、この回復の承認者は変わらない）。
  helper_user_id uuid NOT NULL REFERENCES idp.users (user_id),
  state text NOT NULL CHECK (state IN ('awaiting_helper', 'waiting', 'completed', 'cancelled', 'expired')),
  -- 要求の端末（User-Agent から決めた OS の大まかな種類だけ。ADR 0023 の O-49）。
  request_device text NOT NULL
    CHECK (request_device IN ('iphone', 'ipad', 'android', 'windows', 'chromeos', 'mac', 'linux', 'other')),
  started_at timestamptz NOT NULL,
  -- 協力者の承認を待つ期限（ADR 0027 の O-77）。
  helper_deadline timestamptz NOT NULL,
  approved_at timestamptz,
  ready_at timestamptz,
  ended_at timestamptz,
  purge_after timestamptz,
  -- 成立した回復の、企業への知らせの確定がまだか（ADR 0027 の O-81。確定できるまで送り直す）。
  company_notice_pending boolean NOT NULL DEFAULT false,
  CHECK (helper_user_id <> user_id),
  CHECK (NOT company_notice_pending OR state = 'completed'),
  CHECK (helper_deadline > started_at),
  CHECK ((approved_at IS NULL) = (ready_at IS NULL)),
  CHECK (ready_at IS NULL OR ready_at > approved_at),
  CHECK (state <> 'waiting' OR ready_at IS NOT NULL),
  CHECK (state <> 'completed' OR ready_at IS NOT NULL),
  CHECK ((state IN ('completed', 'cancelled', 'expired')) = (ended_at IS NOT NULL)),
  CHECK ((ended_at IS NULL) = (purge_after IS NULL))
);
CREATE UNIQUE INDEX recovery_attempts_active ON idp.recovery_attempts (user_id)
  WHERE state IN ('awaiting_helper', 'waiting');

ALTER TABLE idp.credentials
  ADD CONSTRAINT credentials_recovery_attempt FOREIGN KEY (recovery_attempt_id)
  REFERENCES idp.recovery_attempts (attempt_id);

-- 協力者への知らせの送信待ち（持ち主の範囲）。notice_id は、協力者の受信箱の項目の ID にもする（送り直しても、
-- 同じ知らせを二重に置かない）。中身は、内部 ID の組と知らせの種類だけ。
CREATE TABLE idp.helper_notice_outbox (
  notice_id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL REFERENCES idp.users (user_id),
  helper_user_id uuid NOT NULL REFERENCES idp.users (user_id),
  relationship_id uuid NOT NULL,
  type text NOT NULL CHECK (type IN ('helper.added', 'helper.ended', 'helper.recovery_started',
                                     'helper.recovery_cancelled', 'helper.recovery_completed',
                                     'helper.code_reissued')),
  created_at timestamptz NOT NULL,
  CHECK (owner_user_id <> helper_user_id)
);
CREATE INDEX helper_notice_outbox_owner ON idp.helper_notice_outbox (owner_user_id, created_at);

-- 企業への回復の SET（ADR 0027 の O-81）。送るときに、テナントの範囲で sub を引く（sub は置かない）。
-- recovery_ref は回復の記録の ID で、同じ回復の再送で二重に入れない。
ALTER TABLE company_api.set_outbox DROP CONSTRAINT set_outbox_event_type_check;
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_event_type_check
  CHECK (event_type IN ('verification', 'desk_cancellation', 'account_recovered'));
ALTER TABLE company_api.set_outbox ADD COLUMN user_id uuid;
ALTER TABLE company_api.set_outbox ADD COLUMN recovery_ref uuid;
ALTER TABLE company_api.set_outbox ADD COLUMN recovered_day bigint CHECK (recovered_day % 86400 = 0);
-- 回復の SET は、成立の前に準備（false）として入れ、成立の後の確定（true）で初めて配送できる（ADR 0027 の O-81）。
-- 取り消された回復は確定されないので、企業には届かない。確定されない行は、30日で消す。
ALTER TABLE company_api.set_outbox ADD COLUMN recovery_confirmed boolean;
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_recovery_check CHECK (
    (event_type = 'account_recovered') = (recovery_ref IS NOT NULL)
    AND (recovery_ref IS NULL) = (user_id IS NULL)
    AND (recovery_ref IS NULL) = (recovered_day IS NULL)
    AND (recovery_ref IS NULL) = (recovery_confirmed IS NULL)
  );
ALTER TABLE company_api.set_outbox
  ADD CONSTRAINT set_outbox_recovery_ref_key UNIQUE (tenant_id, recovery_ref);

ALTER TABLE idp.recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.recovery_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.helpers ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.helpers FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.recovery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.recovery_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.helper_notice_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.helper_notice_outbox FORCE ROW LEVEL SECURITY;

-- idp.users に、回復の2つの列を書き換える UPDATE を足す（いまの利用者の行だけ）。
CREATE POLICY idp_update ON idp.users FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON idp.recovery_codes FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.recovery_codes FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.recovery_codes FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.recovery_codes FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- 協力関係：持ち主も協力者も読める（どちらも、自分が組の片方である行だけ）。書くのは持ち主だけ。
CREATE POLICY idp_select ON idp.helpers FOR SELECT TO warifu_idp
  USING (owner_user_id = warifu.current_user_id() OR helper_user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.helpers FOR INSERT TO warifu_idp
  WITH CHECK (owner_user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.helpers FOR DELETE TO warifu_idp
  USING (owner_user_id = warifu.current_user_id());

CREATE POLICY idp_select ON idp.recovery_attempts FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.recovery_attempts FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.recovery_attempts FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.recovery_attempts FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- 協力者への知らせの送信待ち：持ち主の範囲だけ（協力者の範囲からは読めない）。
CREATE POLICY idp_select ON idp.helper_notice_outbox FOR SELECT TO warifu_idp
  USING (owner_user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.helper_notice_outbox FOR INSERT TO warifu_idp
  WITH CHECK (owner_user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.helper_notice_outbox FOR DELETE TO warifu_idp
  USING (owner_user_id = warifu.current_user_id());

-- 列単位の権限。
GRANT SELECT (recovered_at, recovery_locked_until), UPDATE (recovered_at, recovery_locked_until)
  ON idp.users TO warifu_idp;
GRANT SELECT (state, recovery_attempt_id), INSERT (state, recovery_attempt_id),
      UPDATE (state, recovery_attempt_id)
  ON idp.credentials TO warifu_idp;
GRANT SELECT (user_id, code_mac, created_at), INSERT (user_id, code_mac, created_at),
      UPDATE (code_mac, created_at)
  ON idp.recovery_codes TO warifu_idp;
GRANT DELETE ON idp.recovery_codes TO warifu_idp;
-- 協力関係は、作った後に変えない（入れ替えは、消してから作る）。
GRANT SELECT (relationship_id, owner_user_id, helper_user_id, created_at),
      INSERT (relationship_id, owner_user_id, helper_user_id, created_at)
  ON idp.helpers TO warifu_idp;
GRANT DELETE ON idp.helpers TO warifu_idp;
-- 回復の記録。作った後に変えられるのは、状態と、その時刻と、消す予定だけ。
GRANT SELECT (attempt_id, user_id, helper_user_id, state, request_device, started_at, helper_deadline,
              approved_at, ready_at, ended_at, purge_after, company_notice_pending),
      INSERT (attempt_id, user_id, helper_user_id, state, request_device, started_at, helper_deadline),
      UPDATE (state, approved_at, ready_at, ended_at, purge_after, company_notice_pending)
  ON idp.recovery_attempts TO warifu_idp;
GRANT DELETE ON idp.recovery_attempts TO warifu_idp;
-- 協力者への知らせの送信待ちは、作った後に変えない（送ったら消す）。
GRANT SELECT (notice_id, owner_user_id, helper_user_id, relationship_id, type, created_at),
      INSERT (notice_id, owner_user_id, helper_user_id, relationship_id, type, created_at)
  ON idp.helper_notice_outbox TO warifu_idp;
GRANT DELETE ON idp.helper_notice_outbox TO warifu_idp;

GRANT SELECT (user_id, recovery_ref, recovered_day, recovery_confirmed),
      INSERT (user_id, recovery_ref, recovered_day, recovery_confirmed),
      UPDATE (recovery_confirmed)
  ON company_api.set_outbox TO warifu_company_api;

RESET ROLE;
