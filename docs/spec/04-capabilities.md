# 04. サービスと能力の対応表

> 状態：M1 時点の骨子（M10 で確定）。正は [docs/plan.md](../plan.md) の 8章（能力の表）、2章、9章。
> 出典：[CLAUDE.md](../../CLAUDE.md) の不変条件2・3・4・7・8・9・10 と「配置」、[ADR 0005](../adr/0005-alias-derivation.md)、[ADR 0006](../adr/0006-ciba-spike-findings.md)、[ADR 0010](../adr/0010-staged-participation.md)、[ADR 0013](../adr/0013-local-key-service.md)〜[ADR 0017](../adr/0017-log-allowlist.md)、[ADR 0021](../adr/0021-relay.md)、[ADR 0022](../adr/0022-company-api-sender.md)。

## 0. 読み方

- 「能力」は、各サービスが、鍵の操作、DB、外向きの通信、外から呼べるルート、平文の扱い、のそれぞれで何をできるかを指す。
- 表にない能力は、持たせてはならない（肯定リストと同じ考え方）。表を広げる変更は、plan と ADR を先に直す。不変条件に触れるなら、実装せずに止まって、オーナーに確認する。
- 配置（`packages/` の名前）を変えたら、principle-review の skill も同じ PR で直す（CLAUDE.md「配置」）。
- この表は、テスト6・7・8・11で確かめる（9章）。

## 1. サービスの一覧

| サービス | 役割 | 位置づけ |
|---|---|---|
| warifu-core | 暗号、DB の境界（`withTenant` と `withWarifuUser`）、ログの伏せ字、監査ログ | ライブラリ。各サービスに組み込み、そのサービスの資格情報で動く |
| keysvc | 鍵サービス（encrypt、mac、derive_alias、decrypt と、その ACL） | 割符。ローカルでは別プロセスで立て、KMS の IAM を模す。本番は KMS |
| idp | OIDC、パスキー、操作別承認、回復、PWA | 割符 |
| relay | メール中継。decrypt できる唯一のサービス | 割符 |
| company-api | 企業向け API | 割符 |
| sender | 外向きの通信の唯一の出口 | 割符 |
| rp-kit | 企業向け SDK と適合テスト | 企業の側で動く |
| demo-rp | デモ用の予約サイト（A社、B社）と、窓口担当者の画面 | 企業の側（デモ） |

## 2. 鍵の操作

| ID | 要件 |
|---|---|
| CAP-01 | 各サービスは、下の表で ○ の操作だけを呼べる。表にない操作を呼ぶと、鍵サービスは 403 を返す（テスト8） |
| CAP-02 | decrypt の ACL を持つ資格情報は、relay の1つだけにする（不変条件3） |
| CAP-03 | 鍵サービスのクライアントの型には、そのサービスに許した操作のメソッドだけを持たせる（不変条件3） |
| CAP-04 | 鍵は、鍵サービス（ローカル）か KMS（本番）の外に出さない。HMAC 鍵も同じ（plan 8章、ADR 0005） |
| CAP-05 | `derive_alias` の鍵と、照合用の mac の鍵は、別にする（ADR 0005） |
| CAP-06 | サービスの資格情報（鍵サービスを呼ぶ資格情報、DB のログインロールの資格情報）と鍵を、リポジトリ、コンテナのイメージ、設定ファイル、配信物に平文で置かない（plan 8章） |
| CAP-07 | 割符の鍵、サービスの資格情報、テナントの資格情報には、漏えいが疑われるときの失効と、入れ替えの手順を持たせる。定期的に入れ替えるかと、その周期は、鍵ごとに決める（plan 2章） |

| 操作（対象） | idp | company-api | relay | 使い始める |
|---|---|---|---|---|
| encrypt（contact：本物のメール） | ○ | — | — | M3 |
| encrypt（relay_queue：返信用のアドレスの宛先） | — | — | ○ | M4（ADR 0021） |
| decrypt（contact、relay_queue） | — | — | ○（唯一） | M4 |
| mac（alias_lookup：別名の照合用の索引） | ○ | ○ | ○ | M3〜M5 |
| mac（audit_chain：監査ログのチェーン） | ○ | ○ | ○ | M2 |
| derive_alias（alias_derive） | ○ | ○ | — | M3・M5 |
| sign（id_token）、public_keys（id_token） | ○ | — | — | M3（ADR 0014） |
| sign（dkim）、public_keys（dkim）：relay の DKIM と ARC の署名（RSA 2048） | — | — | ○ | M4（ADR 0021） |
| mac（relay_replay：リプレイの判定、relay_thread：返信用のアドレス、message_id：配送ログの Message-ID） | — | — | ○ | M4（ADR 0021） |
| mac（pairwise_sub：sub の導出、oidc_storage_id：idp の保存の鍵、email_verify_code：宛先確認のコード） | ○ | — | — | M3（ADR 0018） |
| sign（tenant_jwt、set）、public_keys（tenant_jwt、set）：テナントの JWT と SET の署名（ES256） | — | ○ | — | M5（ADR 0022） |

- sender、rp-kit、demo-rp は、鍵サービスの資格情報を持たない。表にない (サービス, 操作, 対象) は、すべて 403（理由によらず同じ本文とヘッダー）。表の本体は `packages/keysvc/src/acl.ts` の1か所に置く（ADR 0013）。
- MAC の鍵は用途ごとに独立させる（KMS の鍵ごとのポリシーに写せるようにするため）。用途は使うマイルストーンで足す。M3 で、idp だけの用途として `pairwise_sub`、`oidc_storage_id`、`email_verify_code` を足した（ADR 0018）。M4 で、relay だけの用途として `relay_replay`、`relay_thread`、`message_id` を足した（ADR 0021）。見込みは、窓口・初回紐付け用の用途（下記の追加案）、`recovery_code`・`invite_code`（M8）。
- 暗号化は鍵サービスの中で直接 AES-256-GCM にかけ（エンベロープにしない）、暗号文を文脈（`contact` は `{ field: 'email', user_id }`、`relay_queue` は `{ queue_item_id }`。返信用のアドレスの行の ID を使う）に結び付ける（ADR 0013）。

- warifu-core は資格情報を持たない。組み込まれたサービスの資格情報で、鍵サービスを呼ぶ。
- idp から本物のアドレスへ送るメール（宛先確認、旧アドレスへの知らせ）は、relay の内部配送 API に利用者 ID を渡して、relay に送らせる（不変条件3）。
- 未定：
  - sub の導出は、M3 で MAC の用途 `pairwise_sub`（idp だけ）にした。コードフローの `pairwiseIdentifier` で導出関数（`packages/idp/src/subject.ts`）を使う（ADR 0018）。company-api は sub を導かず、idp が接続の同意のときに置く sub の索引（`aliases.subject`）を、テナントの中で読むだけにした（ADR 0022）。
  - 操作ごとの承認（M7）の署名の鍵は、sign の keyId として足す（ADR 0014）。relay の DKIM と ARC の鍵（RSA 2048、rsa-sha256）は `dkim`、テナントの JWT と SET の鍵（ES256）は `tenant_jwt` と `set` として、鍵サービスに置いた（ADR 0021、ADR 0022）。
  - サービスの資格情報の本番の渡し方（CAP-06）。P1 の AWS アダプタで決める（ローカルは ADR 0013 と ADR 0015）。
  - 失効と入れ替え（CAP-07）：保存用の鍵、照合用の HMAC 鍵、署名の鍵、サービスの資格情報の手順は ADR 0013 と ADR 0014 で決めた。定期的な入れ替えの周期は P1。sub の導出に使う鍵は入れ替えない（付け替えのイベントと合わせて P1。ADR 0018）。DKIM と ARC の鍵は、新しいセレクタで作り直して DNS を差し替える（ADR 0021。DNS の更新の手順は P1）。テナントの資格情報は、jwks に新しい鍵を足して切り替えた後に古い鍵を外す（ADR 0022）。別名の導出鍵と `alias_lookup` の鍵の入れ替えは P1（ADR 0005、ADR 0022）。
  - 本番で KMS へつなぐ経路。P1 の AWS アダプタで決める。
  - 導出鍵の入れ替えの手順（旧鍵での照合を一定期間残す、企業に SET で知らせる）。P1（ADR 0005）。

### 2.1 窓口と初回移行に追加する能力の設計案

下表は**追加する能力の案**であり、現行ACLで使える操作ではない。各用途は別鍵とし、tenant・用途・鍵の版を結び付ける。入力・出力はログへ出さず、許可外の呼び出しは403にする（ADR 0019・0020、テスト8）。

| 操作・用途の候補 | idp | company-api | relay・sender | 目的 |
| --- | --- | --- | --- | --- |
| mac（desk_request_lookup） | — | ○ | — | テナント別の窓口申請IDの照合 |
| mac（desk_change_lookup） | — | ○ | — | テナント別の変更・取消IDの照合 |
| mac（initial_link_lookup） | — | ○ | — | テナント別の移行申請・再送識別子の照合 |
| mac（desk_public_id） | — | ○ | — | 内部の乱数IDから企業へ渡す変更・取消IDを用途別に再導出 |
| mac（desk_subject_lookup） | ○ | — | — | idp内で承認済み企業別主体と利用者の対応をテナント別に照合 |
| sign（desk_approval、initial_link） | ○ | — | — | 本人の操作別承認と初回移行の最終承認を用途別に署名 |

用途名・keyId・鍵の版・失効条件はM7・M9の実装前にADR 0013・0014と合わせて確定する。sender・rp-kit・demo-rpに割符の鍵サービス資格情報を渡さず、relay以外へのdecryptは追加しない。外部IDとして使うMACの出力は原値として保護し、照合用索引とは用途と鍵を分ける。

## 3. DB

| ID | 要件 |
|---|---|
| CAP-10 | アプリのコードは、`withTenant(tenantId, fn)` か `withWarifuUser(userId, fn)` を通してだけ DB に触れる。どちらも、トランザクションごとに `set_config(…, …, true)` で境界を渡す |
| CAP-11 | 全テーブルに、RLS の ENABLE と FORCE の両方を付ける |
| CAP-12 | 接続ロールは、NOSUPERUSER と NOBYPASSRLS にする |
| CAP-13 | DB は1つにし、サービスごとにスキーマとログインロールを分け、列単位で GRANT する |
| CAP-14 | relay がテナントを横断して使えるのは、SECURITY DEFINER 関数1つ（別名の HMAC → 利用者 ID とテナント ID）だけ。所有者は非ログインの専用ロールにし、`search_path` を固定し、返すのは2つの ID だけにする |
| CAP-15 | 境界の例外は、8章の一覧だけ。新しい例外は作らない |
| CAP-16 | DB に、本物の連絡先も別名も平文で置かない。本物の連絡先は暗号化し、別名は置かずに `derive_alias` で導く。oidc-provider のアダプタは id を HMAC にしてから保存する。relay は受け取ったメールを DB に置かず、返信用のアドレスの宛先は暗号化して置く（ADR 0021） |
| CAP-17 | 監査ログはチェーンにし、検証できるようにする（テスト8）。チェーンへの追記は `pg_advisory_xact_lock` で直列にする |
| CAP-18 | 割符の DB に、BI ツール、分析基盤、SQL を自由に書ける管理ツールをつながない。そのためのログインロールを作らない（CAP-15。8章の例外にない。plan 9章） |
| CAP-19 | 保存するものごとに保存期間を決め、過ぎたら消す（plan 8章） |

| サービス | スキーマとログインロール | 境界 | plan と ADR に書かれた保存物 |
|---|---|---|---|
| idp | 専用 | 利用者のルートは `withWarifuUser`（パスキーのログインも、userHandle の利用者の範囲で引く）。別名の世代は `withTenant`。oidc-provider の保存物と PWA のセッションは DB に置かない（メモリ。id は HMAC。ADR 0018） | 利用者、パスキー（BE/BS フラグを含む。名前などの自由文と AAGUID は置かない）、接続の同意、回復（回復コードは平文で置かない。M8）、協力関係（内部 ID の組だけ）、端末の受信箱（M6） |
| relay | 専用 | テナントの横断は CAP-14 の関数だけ。引いた後は、`relay.*` の表は `withTenant`、本物のアドレスは `withWarifuUser`（ADR 0021） | 受け取ったメールは置かない（メモリで処理する）。配送ログ（`relay.delivery_log`。件名、本文、宛先を残さない。Message-ID は HMAC。30日）、リプレイの判定の記録（`relay.replay`。d=、s=、b=、別名の HMAC。署名を受け付ける間と1時間。別名は平文で置かない）、返信用の使い捨てのアドレス（`relay.threads`。トークンの HMAC、利用者 ID、暗号化した企業の側の宛先。30日） |
| company-api | 専用 | `withTenant`（テナントはテナントの JWT から決める） | sub の索引（`aliases.subject`。読むだけ。idp が置く）、別名の世代の第2世代以降（`aliases.generation`）、SET の送信待ち（`company_api.set_outbox`。署名した SET は置かない。送れたら、または6回で諦めたら消す）。テナントの登録（企業の公開鍵、参加の状態、緊急停止、受け口）は DB に置かず、配備のときの静的な設定にする（ADR 0010、ADR 0022） |
| sender | 使わない（ADR 0022） | — | なし |
| keysvc | 使わない（ADR 0013） | — | なし（鍵はメモリの中だけ） |
| rp-kit、demo-rp | 割符の DB を使わない | — | demo-rp の DB は、テスト7の対象外 |

- 決めたこと（ADR 0015）：
  - ロール：全オブジェクトの所有者 `warifu_owner` と、解決関数の所有者 `warifu_alias_resolver` はログインしない。ログインロールは `warifu_idp`、`warifu_relay`、`warifu_company_api`（NOSUPERUSER、NOBYPASSRLS、NOINHERIT、`search_path` は空、時間切れを設定）と、マイグレーションとテスト用の DB の作成だけに使うブートストラップのロール。
  - スキーマ：`warifu`（境界の関数）、`warifu_meta`（マイグレーションの記録）、`audit`（監査ログ。ADR 0016）、`aliases`（別名の世代）、`idp`、`relay`、`company_api`、`contacts`（暗号化した本物のメール。M3 で作った）。`public` は使わない。
  - 別名の世代 `aliases.generation` は M2 で作った（照合用の HMAC だけを置き、一意にする。追記だけで、最新でない世代が廃番）。CAP-14 の関数は `relay.resolve_alias(bytea)` で、最新の世代だけを2つの ID で返す。
  - 暗号化した本物のメール（`contacts.email`、確認中の `contacts.email_pending`、変更前の `contacts.email_previous`）は、M3 で作った。idp は移し替えのために暗号文の列も読めるが、復号できない（不変条件3）。relay には `withWarifuUser` で `(user_id, ciphertext)` だけを読ませる（ADR 0015、ADR 0018）。本物のメールの一意性は、P0 では検査しない（ADR 0018）。
  - DB ごとに、PUBLIC の CONNECT と TEMP を外し、アプリのロールには CONNECT だけを与える。
  - SQL は `sql` タグでだけ組み立て、値はパラメータにし、拡張プロトコルで1つの文だけを送る。
- 未定：
  - 保存期間（CAP-19）。監査ログは、P0 では消さない（ADR 0016）。いま期限が決まっているのは、配送ログ（30日）、リプレイの判定の記録（署名を受け付ける間と1時間）、返信用のアドレス（30日。どれも ADR 0021）だけ。受付番号は企業側で管理し、割符へ渡さない。oidc-provider の保存物と PWA のセッションは、メモリの中で期限（ADR 0018 の表）が過ぎたら消える。端末の受信箱、回復の記録、退会した利用者や接続をやめた企業のデータの保存期間と消し方は、その保存物を作るマイルストーンで決めて、ADR に記録する。別名の照合用の HMAC は、P0 では消さない（ADR 0018）。退会の流れ（保存物の消し方、別名の廃番、企業への知らせ）は P1 で扱う（plan 10章）。plan 8章）。
  - 運用で集計が要るときの扱い（CAP-18）。P1 の本番の運用の手順で決める。
  - 参加の状態（ADR 0010）：M5 で、テナントの登録を配備のときの静的な設定にし、参加の状態、移行中の期限、割符が確かめた入り口はそこに持たせた（DB の列はない。ADR 0022）。M9 で表示ができるまでは、完全な参加、期限なし、確かめた入り口は空だけを受け付ける。割符が確かめた結果を記録する経路と、idp が警告文 I を出すために参加の状態を読む方法（列単位の GRANT など）は、M9 で決める。どちらも、管理 API も、8章の新しい例外も作らない方法から選ぶ。参加の状態、移行中の期限、割符が確かめた入り口と確かめた日は、企業向けのルート（company-api と、窓口承認の結果で呼べるもの）から書き換えられないようにする。企業向けのルートを処理するログインロールには、これらの列の INSERT と UPDATE を GRANT しない（テスト6）。

### 窓口・初回移行の保存先（将来の設計案）

上の表は M5 までの保存物を含む既存の仕様である。次は ADR 0019・0020 の提案で、実装済みの表や既存の DB 権限を表さない。窓口・初回移行の申請状態の正本を company-api の `company_api` スキーマに置き、HMAC 索引とテナント境界で扱う。idp は本人の承認・チャレンジと受信箱を利用者境界で扱う。両サービスは認証済み内部経路で必要最小限の状態を連携する。表・列ごとの GRANT、内部経路の認証、鍵と ACL は M7・M9 の実装前に決定し、テスト6・8を更新する。新たなテナント横断や復号の例外は作らない。詳細は[仕様案 §2.5.1](../proposals/desk-and-initial-binding-v0.7.md#251-申請の保存先db境界鍵の能力案)を参照する。

## 4. 外向きの通信

| ID | 要件 |
|---|---|
| CAP-20 | 外向きの通信（HTTP(S)、SMTP、テナントや利用者が指定した宛先への接続、名前解決）は、sender だけが行う。各サービスのコードでも、ライブラリの設定でも、外部へ直接つながない |
| CAP-21 | sender は、KMS の権限を持たず、IMDS にも VPC 内にも届かない |
| CAP-22 | sender は、URL を https に限る。名前解決した IP がプライベートなら拒否し、その IP に直接つなぐ（DNS rebinding 対策）。MX の名前解決の結果にも同じ制限をかける。リダイレクトに従わず、サイズと時間に上限を設ける |
| CAP-23 | Web Push の宛先は、既知のプッシュサービスのホストに限る（実配信は P1） |
| CAP-24 | DNS は、注入したリゾルバを通してだけ引く（mailauth の `resolver` を使う） |
| CAP-25 | oidc-provider では、`jwks_uri`、`sector_identifier_uri`、`request_uri` を受け付けず、動的クライアント登録を無効にする。企業の鍵は登録時に `jwks` で受け取る。ロゴは登録時に取り込み、割符の側で配信する |
| CAP-26 | relay から本物のアドレスへの配送は、署名と封印を付けたメッセージを sender の内部 API に渡し、sender が MX を引いて接続する（ADR 0021、ADR 0022）。実配送は、受け取ったメールの永続化と再試行を作るまで始めない（ADR 0021 の O-19） |
| CAP-27 | 割符の内部の接続は、この文書の表で必要としたサービスの組だけに限る。本番では、それ以外の組をネットワークの設定でも塞ぐ（plan 2章「内部の API」。侵害の後の横展開への備え） |

| サービス | 外向きの通信 |
|---|---|
| idp | なし。oidc-provider の外向きの通信は、外へつながない関数に差し替える（ADR 0006）。本物のアドレスへのメールは relay に送らせる |
| relay | なし。送信元ロックの DKIM の検証は、登録した公開鍵だけを返すリゾルバで行い、DNS を引かない。返信の DMARC の判定は、注入したリゾルバだけを通す（リゾルバがなければ返信を中継しない）。リゾルバは sender の名前解決の口（TXT、MX、A、AAAA だけ）。配送は sender に渡す（CAP-26。ADR 0021、ADR 0022） |
| company-api | なし。SET の Webhook は sender に送らせる |
| sender | 唯一の出口（CAP-21〜23） |
| keysvc | なし |
| warifu-core | なし |
| rp-kit、demo-rp | 企業の側のコード。割符のエンドポイント（トークン、company-api）を呼ぶ方法と、不変条件7・lint の規則との関係は、未定（M9 で決める） |

- 割符の内部の接続（サービスから keysvc、DB、relay の内部配送 API、sender へ）は、外向きの通信に当たらない。内部の接続の認証は、keysvc はサービスごとの bearer の資格情報と Unix ドメインソケットにした（ADR 0013）。relay の内部配送 API も同じ形にした（`POST /v1/deliver` だけ。呼べるのは idp だけ。ADR 0021）。sender も同じ形にし、口を呼び出し元ごとに分けた（`/v1/webhook` は company-api、`/v1/mail` と `/v1/dns` は relay。ADR 0022）。
- 内部の接続の組の一覧（CAP-27）は、各サービスを作るマイルストーンで足す。本番のネットワークの設定は、未定（P1 の AWS アダプタで決める）。
- 移行中の企業の入り口が閉じたことを、割符の側から外の検査で確かめる場合（ADR 0010。方法は M9 で決める）も、外へつなぐのは sender だけにする（CAP-20）。
- 静的な検査：lint（`biome.json`）で、sender の外からの通信用のモジュール（`node:dns`、`node:net`、`node:https`、`node:http` のうちサーバーを立てる名前以外、`node:child_process` など）と、`fetch` などのグローバルの利用を禁じる。`globalThis`、`global`、グローバルの `crypto` と、`node:module` の import は、sender でも禁じる。テスト（`*.test.ts`、`*.e2e.ts`）、`scripts/`、`test/`、ルートの `*.config.ts` は除き、`public/` の中ではグローバルの制限を外している。CI では、lint を外せる書き方（`biome-ignore`、`getBuiltinModule`、ルートの `biome.json` 以外の Biome の設定ファイル）も拒否する（CLAUDE.md の「コマンド」）。例外は `packages/warifu-core/src/internal/uds-client.ts` の1ファイルだけで、割符の内部の Unix ドメインソケットにつなぐために `node:http` の `request` を許す（ADR 0013。t08-key-client-surface で、範囲が広がっていないことを固定する）。

## 5. 外から呼べるルート

| ID | 要件 |
|---|---|
| CAP-30 | 外から呼べるルート（HTTP、SMTP の応答、管理用のものを含む）で、sub・別名・受付番号から、本物の連絡先や本人の属性を返さない（不変条件2）。内部の例外は、relay の配送処理で使う SECURITY DEFINER 関数1つだけで、その戻り値を relay の外に出さない |
| CAP-31 | ルート一覧をテストで固定する（テスト6）。oidc-provider が設定で消せないルート（GET /auth、GET /auth/:uid、POST /token、GET /jwks、discovery の2つ、POST /session/end/confirm）も含める（ADR 0006） |
| CAP-32 | P0 では管理 API を作らない。連絡先、認証器、協力者、回復の設定を変える機能は、段階を問わず、管理 API に作らない |
| CAP-33 | 利用者向けのすべてのルートで、所有者を照合する認可をかける（別名の一覧、協力者、受信箱、窓口の承認申請 など） |
| CAP-34 | 機能ごとにレート制限をかける（ログイン、回復の開始、受付番号の試行、窓口の操作別承認、宛先確認の送信、協力者への依頼、企業向け API）。キーは「アカウント」「送信元（IP、端末、テナント）」「その組み合わせ」の3つ。値は M3（ログイン、宛先確認の送信）、M5（企業向け API。ADR 0022）、M7（受付番号と窓口の承認）、M8（回復の開始、協力者への依頼）で ADR に記録する。SMTP の受信は、1通 10 MiB、同時接続 100、1トランザクション1宛先。送信元ごとの上限は P1 の受信の前段で決める（ADR 0021） |
| CAP-35 | 登録、回復、宛先確認、SMTP の RCPT への応答は、登録済みかどうかで、本文・ステータス・所要時間を変えない（不変条件10、テスト10） |
| CAP-36 | PWA には、厳格な CSP（nonce を使う）と Trusted Types を必須にし、テナント由来の文字列はテキストとしてだけ描画する。承認系の画面（承認、回復、協力者）は、別のオリジンに置く |
| CAP-37 | PWA と承認系の画面の配信物（HTML、JavaScript、Service Worker）に、資格情報、鍵、API キーを含めない。認証と認可の判断はすべてサーバーで行い、配信物の中の検査に頼らない（plan 2章） |
| CAP-38 | 内部の API（keysvc、relay の内部配送 API、sender）は、外から届かないようにする。呼べるのは、それぞれを使うと決めたサービスの資格情報だけにする（relay の内部配送 API は idp だけ。plan 2章） |
| CAP-39 | 割符が発行するトークンは、用途に要る範囲と期間に限り、漏えいが疑われるときに、発行済みのものを無効にできるようにする（plan 2章） |

| サービス | 外から呼べるルートの種類（P0） | 呼ぶ人 | 認証 |
|---|---|---|---|
| idp | OIDC（discovery、jwks、認可、トークン）。パスキーの登録とログイン。step-up。PWA（別名の一覧、パスキーの管理、協力者、受信箱、回復、メールアドレスの登録と変更）。承認系の画面（別オリジン） | 利用者の端末、企業 | パスキー（UV 付き）、private_key_jwt（ES256） |
| relay | SMTP の受信（別名あてと、返信用のアドレスあて） | 企業の送信サーバー、利用者のメール事業者 | 送信元ロック、DMARC の整合 |
| company-api | 企業向け API（`POST /token`、`POST /v1/aliases/rotate`、`POST /v1/events/verification`、`GET /jwks`。ADR 0022） | 企業 | private_key_jwt（ES256）の client_credentials で得た、テナントに結び付いた JWT（ES256） |
| sender | なし（割符の内部のサービスからだけ呼ばれる） | — | — |
| keysvc | なし（割符の内部のサービスからだけ呼ばれる） | — | サービスごとの資格情報 |
| rp-kit | なし（ライブラリ） | — | — |
| demo-rp | デモの企業のサイトと、窓口担当者の画面（割符のルートではない） | — | — |

- relay の内部配送 API は、割符の内部からだけ呼べる（呼ぶのは idp）。
- P1：利用者アカウントの凍結と、法令に基づく開示。開示の対象・請求者・承認の手順を ADR で決めるまで実装しない。法令に基づく開示は、テスト6の唯一の例外として扱い、2人承認、根拠法令の記録、監査ログへの追記を必須にする（plan 4章）。
- テナントの封じ込め（緊急停止、別名の再発行）は、P0 では運用の手順として行う。静的な設定を直して配備し直す（company-api の登録の `suspended`、relay と idp の登録からテナントとクライアントを外す。ADR 0022）。管理 API も不変条件8の新しい例外も作らない。管理の機能にする場合は、2人承認と実行までの遅延を付ける（plan 2章）。
- oidc-provider で既定で有効な機能のうち、使わないもの（devInteractions、PAR、DPoP、rpInitiatedLogout、userinfo、resourceIndicators）は、明示的に無効にする（ADR 0006。DPoP の扱いは P1 で決める）。
- CAP-37 の確かめ方：配信物（HTML、JavaScript、CSS）は、`test/leak/x-idp-routes` で CSP（応答ごとの nonce、Trusted Types、インラインのスクリプトがないこと）を確かめ、principle-review の観点7で、配信物に鍵や資格情報の文字列がないことを読む（ADR 0018）。
- 内部の API に外から届かないことの確かめ方：keysvc は、TCP と UDP で待ち受けないこと、ソケットとディレクトリの権限、資格情報と能力の表を、t08-keysvc-isolation、t08-keysvc-auth、t08-keysvc-acl で確かめる（ADR 0013）。relay の内部配送 API は、ソケットの親のディレクトリの権限、資格情報、パスとメソッド、受け付ける入力を `test/leak/x-relay-internal-api` で確かめる。受け付ける入力は、割符が定めた種類（宛先確認と、旧アドレスへの知らせ）と利用者 ID と確認コードだけで、宛先、件名、本文を呼び出し側から受け取らない（ADR 0021）。sender は、資格情報、呼び出し元ごとの口、パスとメソッド、本文の形、ソケットの権限を `test/leak/x-sender-internal-api` で確かめる（ADR 0022）。
- トークンの期限と無効化（CAP-39）の未定（plan 2章）：ID トークンとセッションの有効期間とリフレッシュトークンは M3 で決めた（ID トークン5分、リフレッシュトークンなし、パスキーを削除したらその利用者のセッションをすべて消す。ADR 0018）。パスキーの一時停止（回復の後）のときの扱いは M8。テナントの JWT は ES256 で5分、scope は1つ（M5では別名の入れ替えと検証SET）、リフレッシュトークンなし。窓口・初回移行用の限定scopeはM7・M9で設計する。緊急停止にして配備し直すと、発行済みのものも断る（M5。ADR 0022）。操作ごとの承認の有効期間は M7。

## 6. 暗号の許可リスト

| ID | 要件 |
|---|---|
| CAP-50 | 自前のコードが直接呼ぶ `node:crypto` と、ライブラリに渡すアルゴリズムの設定は、下の表の用途と方式に限る（不変条件9、テスト8） |
| CAP-51 | `node:crypto` は、warifu-core と keysvc からだけ使う。lint で、ほかのパッケージからの import を禁じる（テスト、`scripts/`、`test/`、捨てスパイクは除く） |

| 用途 | 許す方式 |
|---|---|
| 保存 | AES-256-GCM（IV は96ビットの乱数） |
| MAC と照合用の索引（Message-ID などの「ハッシュ」も含む） | HMAC-SHA-256 |
| JWS（ID トークン、SET、操作ごとの承認、テナントの JWT、企業の client assertion の検証） | ES256 だけ。oidc-provider の設定で固定する |
| WebAuthn | ES256、EdDSA（曲線は Ed25519）、RS256 だけを受け付ける。それ以外は登録時に拒否する。RS256 は、登録のときに RSA の鍵長を確かめて記録し、2048 ビット未満は拒否する（ADR 0012） |
| プロトコルで決まる例外（CRYPTREC への掲載を問わない） | Web Push（RFC 8291、VAPID は ES256）。DKIM と ARC の署名（rsa-sha256）。受け取ったメールの DKIM の検証（rsa-sha256 と ed25519-sha256。rsa-sha1 は不合格） |

## 7. 平文で扱ってよいもの

| ID | 要件 |
|---|---|
| CAP-40 | 本物の連絡先を復号して平文にできるのは、relay だけ。平文はメモリの中だけで扱う |
| CAP-41 | 次のものは、どのサービスでも、DB、ログ、配送ログ、エラー報告に平文で書かない：本物の連絡先、別名、トークン（認可コード、アクセス・リフレッシュ・ID の各トークン、auth_req_id、SET、client assertion）、回復コード、窓口コード（P0では作らない）、招待コード、協力者の表示名、申請ID、受付番号、変更ID、取消要求ID、移行証跡 |
| CAP-42 | 別名を、URL のパスやクエリに載せない |
| CAP-43 | ログには値を文字列に埋め込まず、構造化したフィールドで渡す。伏せる対象（Cookie と Authorization のヘッダー、`req.url` のクエリ、リクエストの本文を含む）は、warifu-core の1か所にまとめる。配送ログには件名と本文を残さず、Message-ID は HMAC にし、期限で消す |
| CAP-44 | 協力者の表示名は、協力者の端末の中だけに保存し、サーバーに送らない |

| サービス | メモリの中で平文で扱うもの | 扱わないもの |
|---|---|---|
| idp | 利用者が入力した本物のメール（暗号化と照合用の mac のときだけ。保存した後は読み戻せない）。導いた別名（email クレームと、別名の一覧）。発行するトークン、回復コード、招待コード（発行と照合のときだけ） | 保存済みの本物の連絡先（復号できない）。協力者の表示名 |
| relay | 復号した本物のアドレス（配送のときだけ）。受け取った別名。中継するメールの件名と本文（バイト単位で変えずに渡す） | — |
| company-api | 導いた別名（企業に返すときだけ） | 本物の連絡先 |
| sender | 送る宛先（Webhook の URL、封筒の宛先）と内容（SET、relay が署名と封印を付けたメッセージ）。送るときだけ | 鍵サービスの資格情報、DB。宛先と内容をログに書かない（ADR 0022） |
| keysvc | 操作に渡された入力と出力（encrypt と decrypt の平文、mac と derive_alias の入力、署名の対象）。暗号化は鍵サービスの中で直接行う（ADR 0013）ので、本物の連絡先の平文も、encrypt と decrypt のときにメモリの中を通る | 鍵サービスのログには、入力も出力も書かない（t08-keysvc-isolation） |
| warifu-core | 組み込まれたサービスと同じ | — |
| rp-kit、demo-rp | 別名と sub（企業の側の値） | 本物の連絡先 |

- 「本物の連絡先を平文で扱う」のは、relay（復号した後）と、idp（利用者が入力したとき）と、keysvc（操作の入出力）のメモリの中だけになる。どれも、CAP-41 の書き込み先には残さない。
- 検知の対象と監視の仕組みは、未定（本番の運用の手順として P1 で決める。plan 2章「検知と初動」）。監視に使うログも、CAP-41〜43 に従う。

## 8. 例外の一覧（不変条件8）

DB の境界（CAP-10〜14）の例外は、次の5つだけ。新しい例外は作らない。

1. マイグレーション
2. テスト用の DB の作成
3. 時刻を進めるハーネス（例：回復の `ready_at` を書き換える。テスト3）
4. pg_dump による漏えいテスト（テスト7）
5. relay の SECURITY DEFINER 関数（別名の HMAC → 利用者 ID とテナント ID。CAP-14）

## 9. 確かめ方

| テスト | 確かめること | 対象の要件 | マイルストーン |
|---|---|---|---|
| 6 | A社のトークンでB社のものに触れない。利用者 U1 は U2 のものに触れない。逆引きのルートが存在しない。連絡先・認証器・回復協力者・回復の設定を変えるルートは、利用者自身が plan 4章の手順（step-up と、回復の流れ）で行う idp のルートだけにする。管理用のルートにも、企業向けのルート（company-api、窓口承認の結果で呼べるもの）にも置かない（ルート一覧で固定）。機能ごとのレート制限が働く | CAP-10〜14、CAP-30〜34 | M5（受付番号と窓口承認のレート制限は M7、回復のレート制限は M8。利用者どうしの BOLA の横断は M10） |
| 7 | 割符の全サービスの DB（pg_dump）、ログ、配送ログを、本物のアドレス、別名、トークン、回復コード、窓口コード（P0では作らない）、招待コード、協力者の表示名、申請ID、受付番号、変更ID、取消要求ID、移行証跡で検索して、ヒットが0件（demo-rp の DB とテスト用の受信箱は対象外） | CAP-16、CAP-40〜44 | M10 |
| 8 | 能力の表（2章）にない鍵の操作をすると 403。監査ログのチェーンが検証できる。暗号の呼び出しとアルゴリズムの設定が、許可リストどおりに固定されている。暗号文が文脈に結び付いている | CAP-01〜05、CAP-17、CAP-38（keysvc）、CAP-50、CAP-51 | M2（`test/leak/t08-*`。ライブラリに渡すアルゴリズムの設定は M3） |
| 11 | IMDS、内部 API、プライベート IP、DNS rebinding、リダイレクト、MX が内部の IP を指すアドレスへの配送は、sender で拒否される | CAP-20〜26 | M5（`test/leak/t11-sender-ssrf`、`x-sender-internal-api`、`x-relay-sender`。SSRF の横断は M10） |

- RLS の ENABLE と FORCE は、`pg_class` の `relrowsecurity` と `relforcerowsecurity` で全テーブルを確かめる固定テストで守る（M2。`test/leak/x-rls-fixed.test.ts`。ポリシーと列単位の GRANT の一覧、SECURITY DEFINER が1つだけであることも固定する）。DB の境界は `x-db-boundary`、CAP-14 の関数は `x-relay-resolver` で確かめる。
- 列挙の防止（CAP-35）はテスト10、企業に渡る値の一覧はテスト4で確かめる。
- 利用者自身による変更（メールアドレスは step-up と宛先確認、パスキーと協力者は step-up、回復は回復の流れ。5章の表の idp）は、plan 4章の手順で行う。連絡先・認証器・回復協力者・回復設定の変更にテスト6が許すルートは、これだけである。窓口取消・初回紐付けの追加経路も同テストで固定し、本人・テナント境界を検査する（ADR 0019・0020）。管理用のルートにも、企業向けのルート（company-api、窓口承認の結果で呼べるもの）にも、変更のルートを置かない（plan 11章）。
- CAP-06、CAP-07、CAP-15、CAP-18、CAP-19、CAP-27、CAP-36〜39 には、まだテストを割り当てていない。CAP-37 と CAP-38 の確かめ方は、5章のとおり（CAP-37 は M3。CAP-38 は、keysvc は M2、relay の内部配送 API は M4、sender は M5 で済み）。それ以外の CAP にテストか監査の項目を割り当てるかは、未定（M10 で決める）。CAP-36 は TH-15（未割り当て。03 の 4-9）に当たる。
