-- 0005：relay の表（ADR 0021）。どの表も、テナントの範囲（withTenant）でだけ読み書きする。テナントを横断する読み方はない。
-- 受け取ったメールの件名と本文は、どの表にも置かない（メモリの中だけで処理する。ADR 0021）。
-- 別名、本物のアドレス、返信用のアドレスの乱数は平文で置かない（不変条件4）。置くのは鍵サービスの MAC と暗号文だけ。
SET ROLE warifu_owner;

-- リプレイの判定（plan 3-2）。mac(relay_replay, d ‖ s ‖ b= ‖ 宛先) だけを置き、期限が過ぎたら消す。
CREATE TABLE relay.replay (
  tenant_id uuid NOT NULL,
  replay_mac bytea NOT NULL CHECK (octet_length(replay_mac) = 32),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, replay_mac)
);

-- 返信用のアドレス（やり取りごとの使い捨ての乱数。plan 3-2）。乱数は mac(relay_thread) だけを置く。
-- 中継の先（企業の側のアドレス）は、encrypt(relay_queue) の暗号文で置く（文脈は thread_id）。
CREATE TABLE relay.threads (
  thread_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  token_mac bytea NOT NULL CHECK (octet_length(token_mac) = 32),
  target_ciphertext bytea NOT NULL CHECK (octet_length(target_ciphertext) BETWEEN 35 AND 354),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT threads_token_mac_key UNIQUE (token_mac)
);

-- 配送ログ。件名と本文は残さず、Message-ID は mac(message_id) にし、期限で消す（不変条件4）。
CREATE TABLE relay.delivery_log (
  log_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  message_id_mac bytea NOT NULL CHECK (octet_length(message_id_mac) = 32),
  direction text NOT NULL CHECK (direction IN ('to_user', 'to_company')),
  outcome text NOT NULL CHECK (outcome IN ('delivered', 'failed')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
  expires_at timestamptz NOT NULL
);

ALTER TABLE relay.replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay.replay FORCE ROW LEVEL SECURITY;
ALTER TABLE relay.threads ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay.threads FORCE ROW LEVEL SECURITY;
ALTER TABLE relay.delivery_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay.delivery_log FORCE ROW LEVEL SECURITY;

CREATE POLICY relay_select ON relay.replay FOR SELECT TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_insert ON relay.replay FOR INSERT TO warifu_relay
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_delete ON relay.replay FOR DELETE TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());

CREATE POLICY relay_select ON relay.threads FOR SELECT TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_insert ON relay.threads FOR INSERT TO warifu_relay
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_delete ON relay.threads FOR DELETE TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());

CREATE POLICY relay_select ON relay.delivery_log FOR SELECT TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_insert ON relay.delivery_log FOR INSERT TO warifu_relay
  WITH CHECK (tenant_id = warifu.current_tenant_id());
CREATE POLICY relay_delete ON relay.delivery_log FOR DELETE TO warifu_relay
  USING (tenant_id = warifu.current_tenant_id());

-- 列単位の権限。UPDATE はどの列にも与えない（足すか消すだけ）。DELETE は期限の過ぎた行を消すために要る。
GRANT SELECT (tenant_id, replay_mac, expires_at), INSERT (tenant_id, replay_mac, expires_at)
  ON relay.replay TO warifu_relay;
GRANT SELECT (thread_id, tenant_id, user_id, token_mac, target_ciphertext, expires_at),
      INSERT (thread_id, tenant_id, user_id, token_mac, target_ciphertext, expires_at)
  ON relay.threads TO warifu_relay;
GRANT SELECT (log_id, tenant_id, direction, outcome, created_at, expires_at),
      INSERT (log_id, tenant_id, message_id_mac, direction, outcome, expires_at)
  ON relay.delivery_log TO warifu_relay;
GRANT DELETE ON relay.replay, relay.threads, relay.delivery_log TO warifu_relay;

RESET ROLE;
