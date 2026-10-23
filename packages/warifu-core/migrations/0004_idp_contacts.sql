-- 0004：idp の表（利用者、パスキー、接続）と、暗号化した本物のメール（ADR 0015、ADR 0018）。
-- どの表も、利用者の範囲（withWarifuUser）でだけ読み書きする。テナントを横断する読み方はない。
-- 本物のメールは、鍵サービスの encrypt(contact) の暗号文だけを置く（不変条件4）。idp は復号できない（不変条件3）。
-- スキーマは DB の CREATE の権限で作る（所有者のロールは DB に CREATE を持たない。0001 と同じ）。
CREATE SCHEMA contacts AUTHORIZATION warifu_owner;  -- 暗号化した本物のメール

SET ROLE warifu_owner;

-- 利用者。パスキーの userHandle は、この ID の16バイト（ADR 0018）。連絡先や属性の列は持たない。
CREATE TABLE idp.users (
  user_id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now()
);

-- パスキー。名前などの自由文は持たない（画面には、同期か端末固定かと、登録日だけを出す）。AAGUID は置かない（ADR 0007）。
CREATE TABLE idp.credentials (
  credential_id bytea PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
  sign_count bigint NOT NULL CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT '{}'::text[]
    CHECK (transports <@ ARRAY['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']::text[]),
  backup_eligible boolean NOT NULL,
  backed_up boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  last_used_at timestamptz
);
CREATE INDEX credentials_user_id ON idp.credentials (user_id);

-- 企業（テナント）への接続の同意（27条の記録。監査ログにも残す）。
CREATE TABLE idp.connections (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES idp.users (user_id),
  consented_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  PRIMARY KEY (tenant_id, user_id)
);

-- 暗号文は、ヘッダー（18バイト）、本文、タグ（16バイト）。本文は 1〜320 バイト（ADR 0013）。
CREATE TABLE contacts.email (
  user_id uuid PRIMARY KEY REFERENCES idp.users (user_id),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 35 AND 354),
  updated_at timestamptz NOT NULL
);

-- 宛先確認の途中。確認コードは平文で置かず、鍵サービスの mac(email_verify_code) だけを置く。
CREATE TABLE contacts.email_pending (
  user_id uuid PRIMARY KEY REFERENCES idp.users (user_id),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 35 AND 354),
  code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now()
);

-- 変更する前のアドレス。旧アドレスへの知らせ（操作のリンクを含まない）を relay が送るために置く（M4）。
CREATE TABLE contacts.email_previous (
  user_id uuid PRIMARY KEY REFERENCES idp.users (user_id),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 35 AND 354),
  replaced_at timestamptz NOT NULL
);

ALTER TABLE idp.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.users FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE idp.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp.connections FORCE ROW LEVEL SECURITY;
ALTER TABLE contacts.email ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts.email FORCE ROW LEVEL SECURITY;
ALTER TABLE contacts.email_pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts.email_pending FORCE ROW LEVEL SECURITY;
ALTER TABLE contacts.email_previous ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts.email_previous FORCE ROW LEVEL SECURITY;

-- idp：いまの利用者の行だけ。
CREATE POLICY idp_select ON idp.users FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.users FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON idp.credentials FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.credentials FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON idp.credentials FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON idp.credentials FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON idp.connections FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON idp.connections FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON contacts.email FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON contacts.email FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON contacts.email FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON contacts.email_pending FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON contacts.email_pending FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_update ON contacts.email_pending FOR UPDATE TO warifu_idp
  USING (user_id = warifu.current_user_id()) WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON contacts.email_pending FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

CREATE POLICY idp_select ON contacts.email_previous FOR SELECT TO warifu_idp
  USING (user_id = warifu.current_user_id());
CREATE POLICY idp_insert ON contacts.email_previous FOR INSERT TO warifu_idp
  WITH CHECK (user_id = warifu.current_user_id());
CREATE POLICY idp_delete ON contacts.email_previous FOR DELETE TO warifu_idp
  USING (user_id = warifu.current_user_id());

-- relay：解決関数で利用者 ID を得た後、その利用者の範囲で暗号文を読む（M4）。
CREATE POLICY relay_select ON contacts.email FOR SELECT TO warifu_relay
  USING (user_id = warifu.current_user_id());
CREATE POLICY relay_select ON contacts.email_pending FOR SELECT TO warifu_relay
  USING (user_id = warifu.current_user_id());
CREATE POLICY relay_select ON contacts.email_previous FOR SELECT TO warifu_relay
  USING (user_id = warifu.current_user_id());

GRANT USAGE ON SCHEMA contacts TO warifu_idp, warifu_relay;

-- 列単位の権限。DELETE は表の単位でしか与えられないので、要る表にだけ与える（x-rls-fixed で固定する）。
GRANT SELECT (user_id, created_at), INSERT (user_id) ON idp.users TO warifu_idp;
GRANT SELECT (credential_id, user_id, public_key, sign_count, transports, backup_eligible, backed_up,
              created_at, last_used_at),
      INSERT (credential_id, user_id, public_key, sign_count, transports, backup_eligible, backed_up),
      UPDATE (sign_count, backed_up, last_used_at)
  ON idp.credentials TO warifu_idp;
GRANT DELETE ON idp.credentials TO warifu_idp;
GRANT SELECT (tenant_id, user_id, consented_at), INSERT (tenant_id, user_id) ON idp.connections TO warifu_idp;

-- idp は暗号文を読めるが、復号の ACL がないので平文にはできない（不変条件3）。移し替え（確認中 → 現在 → 変更前）に要る。
GRANT SELECT (user_id, ciphertext, updated_at), INSERT (user_id, ciphertext, updated_at),
      UPDATE (ciphertext, updated_at)
  ON contacts.email TO warifu_idp;
GRANT SELECT (user_id, ciphertext, code_mac, attempts, expires_at, created_at),
      INSERT (user_id, ciphertext, code_mac, expires_at),
      UPDATE (attempts)
  ON contacts.email_pending TO warifu_idp;
GRANT DELETE ON contacts.email_pending TO warifu_idp;
GRANT SELECT (user_id, replaced_at), INSERT (user_id, ciphertext, replaced_at)
  ON contacts.email_previous TO warifu_idp;
GRANT DELETE ON contacts.email_previous TO warifu_idp;

GRANT SELECT (user_id, ciphertext) ON contacts.email, contacts.email_pending, contacts.email_previous
  TO warifu_relay;

RESET ROLE;
