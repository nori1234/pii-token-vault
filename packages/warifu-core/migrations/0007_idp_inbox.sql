-- 0007：端末の受信箱（plan 4章「通知」、ADR 0023）。利用者の範囲（withWarifuUser）でだけ読み書きする。
-- 受信箱を正とし、PWA はポーリングで受け取る。項目は「承認待ち」（approval）と「知らせ」（notice）の2種類。
-- 中身（content）は、割符のコードの型が検査した項目だけ（型の外の自由文、連絡先、トークンは入れない。不変条件4）。
-- 企業名は登録簿から引くので、テナント ID だけを置く。
SET ROLE warifu_owner;

CREATE TABLE idp.inbox (
  item_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  kind text NOT NULL CHECK (kind IN ('approval', 'notice')),
  -- 型の名前（割符のコードの定数）。
  type text NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,3}$'),
  tenant_id uuid,
  content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object' AND octet_length(content::text) <= 2048),
  state text NOT NULL,
  created_at timestamptz NOT NULL,
  -- 承認待ちの期限（承認と拒否を受け付ける時刻の上限）。知らせにはない。
  expires_at timestamptz,
  decided_at timestamptz,
  read_at timestamptz,
  -- この時刻を過ぎたら消す（ADR 0023 の保存期間）。
  purge_after timestamptz NOT NULL,
  -- 要求の端末（承認待ちだけ）。User-Agent から決めた OS の大まかな種類だけを置く（DESIGN.md 1章の④）。
  request_device text
    CHECK (request_device IN ('iphone', 'ipad', 'android', 'windows', 'chromeos', 'mac', 'linux', 'other')),
  CHECK ((kind = 'approval') = (expires_at IS NOT NULL)),
  CHECK ((kind = 'approval') = (request_device IS NOT NULL)),
  CHECK (kind <> 'approval' OR tenant_id IS NOT NULL),
  CHECK (
    (kind = 'approval' AND state IN ('pending', 'approved', 'denied'))
    OR (kind = 'notice' AND state IN ('unread', 'read'))
  ),
  CHECK ((state IN ('approved', 'denied')) = (decided_at IS NOT NULL)),
  CHECK ((state = 'read') = (read_at IS NOT NULL)),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK (purge_after > created_at)
);
CREATE INDEX inbox_user_created ON idp.inbox (user_id, created_at);

ALTER TABLE idp.inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.inbox FORCE ROW LEVEL SECURITY;

-- idp：いまの利用者の行だけ。
CREATE POLICY idp_select ON idp.inbox FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.inbox FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.inbox FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.inbox FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- 列単位の権限。作った後に変えられるのは、状態と、その時刻だけ（中身、型、期限は書き換えられない）。
GRANT SELECT (item_id, user_id, kind, type, tenant_id, content, state, created_at, expires_at, decided_at,
              read_at, purge_after, request_device),
      INSERT (item_id, user_id, kind, type, tenant_id, content, state, created_at, expires_at, purge_after,
              request_device),
      UPDATE (state, decided_at, read_at)
  ON idp.inbox TO warifu_idp;
GRANT DELETE ON idp.inbox TO warifu_idp;

RESET ROLE;
