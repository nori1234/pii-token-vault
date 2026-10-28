# ADR 0018：idp（パスキー、OIDC、テナント単位の pairwise、step-up、本物のメールの登録）

- 状態：提案（オーナーの確認待ち。下の「オーナーの確認」の既定の案で実装した）
- 日付：2026-10-23

## 状況

M3（イシュー #5）で、idp を作る。plan 10章の範囲は、パスキー、OIDC、テナント単位の pairwise、step-up、宛先確認（Mailer とメモリの送信箱）、テスト4の前半、テスト10（登録時の応答）。plan と仕様書には、「M3 で決める」とした項目が残っていた。

- ID トークンとセッションの有効期間、リフレッシュトークン、パスキーを消したときのセッション（plan 2章）
- ログインと宛先確認の送信のレート制限の値（plan 2章、CAP-34）
- sub の導出に使う鍵と操作（plan 8章、spec 04 2章）
- 別名を email クレームと `contact_alias` のどちらで渡すかの選び方（spec 02 1章）
- 企業のモバイルアプリから割符のログインを使う方法（plan 3-3）
- oidc-provider の保存先と、その保存期間（plan 8章、ADR 0006）
- CAP-37（配信物に資格情報を含めない）の確かめ方（spec 04 5章）
- 別名の照合用の HMAC の残し方（plan 8章）

ADR 0007（パスキーの検証の守り）と ADR 0006（oidc-provider の調べ）を、本実装に持ち込む必要もあった。

## 決定

### 構成

- `packages/idp` に Fastify 5 のアプリを置き、oidc-provider 9.12.2 を `@fastify/middie` で `/oidc` に載せる。issuer は `<origin>/oidc`。oidc-provider の経路には Fastify のボディ解析を通さない（middie は onRequest で処理して応答を終える）。
- 画面（PWA）、API（`/api/*`）、OIDC のインタラクション（`/interaction/:uid`）は、同じオリジンに置く。承認用の別オリジン（DESIGN.md 原則8）は、承認画面を作る M6・M7 で用意する（O-17）。→ M6 で、承認待ちの画面と、承認と拒否の API を承認用のオリジンに置いた（ADR 0023）。
- ルートは `test/leak/x-idp-routes.test.ts` の一覧で固定する。逆引き、管理用、連絡先・認証器を変える別の経路はない（不変条件2）。

### oidc-provider の設定（`packages/idp/src/provider.ts`）

- 認可コードと PKCE（S256）だけ。refresh token は出さない。userinfo、登録、introspection、revocation、ログアウト、PAR、要求オブジェクト、claims パラメータ、resource indicators、CIBA（M7）、デバイスフローは無効。
- クライアント認証は private_key_jwt（ES256）だけで、client assertion の aud は issuer だけ（ADR 0006）。企業の鍵は登録簿の jwks。
- `subject_type` は pairwise だけ。`pairwiseIdentifier` で sub を導く（下の「sub」）。セッションの accountId は内部の利用者 ID で、企業には渡らない（ADR 0006 の申し送り）。
- `conformIdTokenClaims: false`。userinfo を無効にしたので、別名のクレームを ID トークンに入れる。
- 外へはつながない：`fetch` を常に失敗させる。登録簿の検査と `extraClientMetadata.validator` で、jwks_uri、sector_identifier_uri、request_uris、ロゴなどの URL を受け付けない（不変条件7）。
- 認可の要求は GET だけにし、`id_token_hint`、`request`、`request_uri`、`registration`、`claims` を付けた要求は、入口で 400 にする。id_token_hint を検証するには、自分の公開鍵の KeyObject が要る（下の「署名」）。
- エラーの画面（`renderError`）には、受け取った値（state、redirect_uri、エラーの説明）を出さない。

### 署名（ADR 0014 の実装）

- oidc-provider の `ExternalSigningKey`（`features.externalSigningSupport`、experimental-01）を継いだ `KeysvcSigningKey` で、鍵サービスの `sign('id_token')` を呼ぶ。秘密鍵は鍵サービスの外に出ない。
- 公開鍵の座標（kty、crv、x、y）は getter で返す。基底クラスは `keyObject()` から作るが、それには `node:crypto` の KeyObject が要る（idp では import できない）。`keyObject()` を呼ぶのは、自分が出した JWT を検証する経路（id_token_hint、ログアウト）だけで、どれも無効にした。
- 起動のときに試しに署名し、返った kid の公開鍵を使う（入れ替えの後は公開鍵が複数返るため）。署名の直前に鍵サービスの鍵が入れ替わっていたら、JWS のヘッダーの kid と食い違うので、署名を返さずに止める。鍵は oidc-provider を作るときに固定されるので、鍵サービスの鍵を入れ替えたら idp を再起動する（ADR 0014 の手順に足す）。
- 実験的な機能なので、oidc-provider の版を上げるときは、`test/leak/t04-pairwise` と `x-idp-oidc` で署名と検証を確かめ直す。

### クッキー（O-9）

- oidc-provider にも PWA にも、クッキーの署名の鍵を渡さない。クッキーの値は、推測できない長さの乱数の id（oidc-provider のセッションとインタラクションは nanoid、PWA のセッションは32バイト）で、サーバー側の保存の鍵は MAC にする（下の「保存」）。
- ADR 0006 は、スパイクで「HMAC-SHA-256 の Keygrip 形のオブジェクトで署名し、M3 でもこの形を保つ」とした。変えた理由は2つ。Keygrip の sign は同期の関数なので鍵サービスを呼べず、idp のプロセスに HMAC 鍵を置くことになる（「鍵を使う処理は鍵サービスの中だけ」に反する）。値が乱数の id なので、署名で守るものがない（署名しても、攻撃者が自分のブラウザの正しいクッキーを写す固定化は防げない）。
- 名前はアプリごとに一意にする（`warifu_idp_oidc`、`warifu_idp_interaction`、`warifu_idp_resume`、`warifu_idp_pwa`）。PWA のセッションは HttpOnly、SameSite=Strict、Path=/。https で動かすときは Secure を付ける。本番では `__Host-` の接頭辞を付ける（P1 の AWS アダプタで決める）。

### 保存（O-10）

- oidc-provider の保存物（Session、Interaction、Grant、AuthorizationCode、AccessToken）、PWA のセッション、WebAuthn のチャレンジは、プロセスのメモリに置く（`packages/idp/src/storage.ts`）。保存の鍵は鍵サービスの `mac(oidc_storage_id, lp('warifu/storage/v1', 種類, id))` で、payload から jti を取り除く。Client は保存しない。行数の上限（10万）を超えたら、期限切れを掃除しても空きがなければ、503 にする。
- DB に置かない理由：Session と Interaction は、境界（テナントも利用者も）が決まる前に引く。DB に置くと、不変条件8に新しい例外が要る。テナントに結び付く保存物（認可コードなど）は `Provider.ctx` で withTenant に載せられる（ADR 0006）が、P0 の PoC で永続化して得るものがない。
- 再起動すると、ログイン中のセッションと、途中のインタラクションは消える（利用者はパスキーでログインし直す）。複数のプロセスで動かすとき、再起動をまたぐときの永続化は、P1 の AWS アダプタで決める。
- 保存期間は、下の「期限」のとおり（期限が過ぎたら読めず、掃除の対象になる）。

### パスキー（ADR 0007 の実装）

- ADR 0007 の決定1〜6を、`packages/idp/src/webauthn.ts` に置いた。attestation は none だけ（ライブラリに渡す前に確かめる）、アルゴリズムは [-7, -8, -257] を選択肢と検証の両方に渡す（ADR 0012 の決定10）、UV はサーバーで確かめる、失敗は理由を問わず同じ応答、AAGUID は保存しない、BE と BS は保存する。
- 登録した公開鍵（COSE）を、ライブラリの検証の後に確かめる（ADR 0012 の決定6・10）。attestation が none の登録では、ライブラリは公開鍵で署名を確かめないので、alg と鍵が合わない応答も通ってしまうため。
  - ES256 は EC2 の P-256、EdDSA は OKP の Ed25519、RS256 は RSA で 2048 ビット以上の鍵だけを受け付ける。それ以外は、ほかの失敗と同じ応答で拒否する。
  - `idp.credentials` に、アルゴリズム（`alg`）と、RS256 の鍵長（`rsa_bits`）を記録する。DB でも、`alg` は3つの値だけ、`rsa_bits` は RS256 のときだけ置けて 2048 以上、と制約をかける。2030年に 3072 ビット未満の RSA の資格情報を止めるとき（決定6）、対象の利用者をこの列で探す。
- **userHandle は利用者 ID（UUID）の16バイト**（O-15）。ログインでは、アサーションの userHandle の利用者の範囲（withWarifuUser）の中で、資格情報 ID が一致するものだけを使う。見つからなければ拒否する（別の利用者の資格情報 ID でも、存在しない ID でも、同じ拒否）。境界の外で資格情報を引かないので、不変条件8の例外が要らない。ADR 0007 の3（資格情報 ID で引き、userHandle が持ち主と一致することを確かめる）と、結果は同じになる。利用者 ID は乱数で、連絡先や属性から作らない。認証器の画面に出る名前は乱数のラベル。
- パスキーに自由文の名前を付けない。画面には「同期パスキー／端末固定のパスキー」と、登録と最後に使った日時だけを出す。
- チャレンジは使い捨てで、目的（作成、ログイン、step-up、追加）と相手（インタラクションの uid、PWA のセッションの参照）に結び付ける。75秒で切れる。
- 追加と削除には step-up（5分以内の認証）が要る。**最後の1つは消させない**（回復の手段が整う M8 まで。O-16）。残りの数は、その利用者のパスキーの行を `FOR UPDATE` でロックしてから数える（同時に2つ消すと、どちらも「残り2つ」と数えて、最後の1つまで消せてしまうため）。削除したら、その利用者の PWA と oidc-provider のセッションをすべて消す（plan 2章の「M3 で決める」）。一時停止（回復の後。plan 4章）は M8 で作る。
- 全端末への知らせ（plan 4章）は、受信箱を作る M6 で足す。M3 では監査ログに残す。→ M6 で、追加と削除を受信箱の知らせにした（ADR 0023）。

### セッションと step-up、期限（O-11）

| もの | 期限 |
|---|---|
| ID トークン | 5分（企業は受け取った後、自前のセッションを作る） |
| 認可コード | 60秒 |
| アクセストークン | 5分（企業は使わない。根拠にしてよいのは ID トークンの iss・sub・acr・auth_time だけ） |
| リフレッシュトークン | 出さない |
| oidc-provider のセッション（SSO の窓） | 10分 |
| インタラクション | 10分 |
| Grant | 10分（同意は DB の `idp.connections` を正にし、毎回 Grant を作り直す） |
| PWA のセッション | 最後の操作から30分、最長8時間 |
| step-up（新しい認証） | 5分以内 |
| 確認コード | 15分、5回まで |
| WebAuthn のチャレンジ | 75秒 |

- acr は `urn:warifu:acr:passkey`（UV 付きのパスキー）。企業のクライアントに `default_acr_values` と `require_auth_time` を付けるので、acr と auth_time は常に ID トークンに入る（ADR 0006）。
- **step-up**：企業は `max_age`（0 も可）か `prompt=login` で、新しい認証を求める。割符のログインは毎回 UV 付きのパスキーなので、auth_time が新しくなる。操作に結び付いた承認（RAR）は M7。CIBA の acr は M7 で決める。
- PWA のメールの登録と変更、パスキーの追加と削除は、5分以内の認証を求める。古ければ `reauth_required` を返し、画面がパスキーで step-up してから送り直す。

### sub

- `sub = base64url(HMAC(k_pairwise_sub, lp('warifu/sub/v1', テナント ID の16バイト, 利用者 ID の16バイト)))`。鍵は鍵サービスの MAC の用途 `pairwise_sub`（idp だけ）。
- コードフローの `pairwiseIdentifier` と、M7 の CIBA の `processLoginHintToken` は、この関数（`packages/idp/src/subject.ts`）だけを使う。同じテナントの別のクライアントでは同じ値、別のテナントでは別の値になる（テスト4）。
- `pairwise_sub` の鍵は入れ替えない。入れ替えると、全企業の sub が変わり、企業の側で会員とのつながりが切れる。入れ替えの手順は、付け替えのイベント（P1）と合わせて決める。ローカルでは、鍵サービスを起動するたびに鍵が変わる（O-6）ので、sub も変わる。

### 別名とクレーム（O-12）

- 初めての接続の同意で、idp が `aliases.generation` に第1世代を置く（照合用の `mac(alias_lookup)` だけ。ADR 0015）。別名は `derive_alias` で、その都度導く（ADR 0005）。別名の右側は、テナントごとの relay のドメイン（登録簿）。
- クレームは scope `email` のときだけ出す。登録簿のクライアントごとの `aliasClaim` で選ぶ：`email`（既定。`email_verified` は常に false）か `contact_alias`。どちらにも本物の連絡先は入らない。
- 別名の照合用の HMAC（`lookup_mac`）は、P0 では消さない（再利用しないことを一意制約で保つため）。退会の流れ（P1）で、残し方を決める。

### 接続の同意

- 初めてのテナントでは、同意の画面を出す。出すのは、登録簿の企業名、渡すもの（この企業だけで使う ID、この企業だけで使う連絡用のアドレス）、「接続する」「接続しない」（同じ大きさ、既定の選択なし、初期フォーカスは見出し）。
- 同意は `idp.connections` と監査ログ（`idp.connection.consented`）に残す（27条の記録）。同意の文面の版、第三者提供の同意として足りるかは、法務の確認（イシュー #15）の後に足す。
- 移行中の参加の企業の警告文 I は、M9 で足す（ADR 0010）。

### 本物のメールの登録と変更（plan 4章）

1. step-up（5分以内の認証）を確かめる。
2. 入力を整える（前後の空白を除き、ドメインだけを小文字にする。空白、制御文字、引用符などは受け付けない）。
3. 鍵サービスで暗号化する（`encrypt(contact)`、その利用者の文脈）。平文は、そのリクエストのメモリの中だけ。
4. 8桁の確認コードを作り、`mac(email_verify_code)` だけを `contacts.email_pending` に置く。コードは Mailer に渡す。
5. コードの照合は SQL の WHERE で MAC を比べる。5回まで。通ったら、確認中の暗号文を `contacts.email` に移し、前のものは `contacts.email_previous` に移して、旧アドレスあての知らせ（操作のリンクもコードも含まない）を Mailer に渡す。
- **一意性（O-13）**：P0 では、同じ本物のアドレスを複数の割符アカウントに登録することを拒否しない（照合用の列を作らない）。一意性の検査は不変条件1(e) で許された例外だが、要件ではない。検査をすると、登録済みのときの分岐（列挙の余地）ができる。ADR 0015 の「照合用の HMAC の列と合わせて作る」は、これに合わせて直した。
- idp は、確認中・現在・変更前の暗号文の列を読める（移し替えに SELECT が要るため）。復号の ACL がないので、平文にはできない（不変条件3）。ADR 0015 の「idp には暗号文の列を読ませない」は、これに合わせて直した。
- 応答は、そのアドレスがほかのアカウントで使われているかどうかで変わらない（不変条件10。テスト10）。形の違う入力（400）とレート制限（429）は、登録済みかどうかとは関係しない。

### Mailer

- `sendToUser({ userId, kind, code? })`。送り先は利用者 ID だけで指定し、どのアドレス（確認中、現在、変更前）に送るかは種類で決める。M4 で relay の内部配送 API に差し替える。relay は、その利用者の範囲で暗号文を読み、復号して、固定の文面で送る（不変条件3）。
- M3 では、メモリの送信箱（`MemoryOutbox`）だけを使う。

### レート制限（O-14）

プロセスのメモリの固定窓。値は `packages/idp/src/rate-limit.ts` の `RATE_LIMITS` を正とする。

| 機能 | キー | 上限 |
|---|---|---|
| アカウントの作成 | IP | 1時間に10 |
| パスキーの検証（ログイン、step-up） | IP | 1分に20 |
| パスキーの検証（ログイン、step-up） | userHandle の利用者 | 1分に10 |
| 確認コードの送信 | 利用者 | 15分に3 |
| 確認コードの送信 | IP | 1時間に20 |
| WebAuthn の選択肢の発行 | IP | 1分に60 |
| 確認コードの照合 | 確認中の1件 | 5回 |

- 根拠のある値ではない（総当たりと、メモリの使い切りを止める目安）。運用の実績で見直す。複数のプロセスで共有する方法は、P1 で決める。

### 静的な登録簿（M3 だけ）

- テナント（ID、企業名、relay のドメイン）とクライアント（client_id、テナント、redirect_uris、jwks、aliasClaim）を、起動の設定で受け取る（`packages/idp/src/registry.ts`）。M5 で company-api の登録に置き換える。→ M5 では、登録をサービスごとの静的な設定のまま残した（company-api の登録は ADR 0022）。1つの登録簿にまとめるかは M9 で決める。
- 許す項目を肯定リストで決める。redirect_uris は https（開発では http://localhost と 127.0.0.1）で、ホストは1つ（sector_identifier_uri を使わないため。ADR 0006）。企業名に制御文字と書式の制御文字（双方向の制御など）を入れさせない。relay のドメインはテナントごとに違う。

### 企業のモバイルアプリ（plan 3-3）

- 企業のサーバーを割符の OIDC のクライアントにし、モバイルアプリは企業のサーバーとだけ話す。アプリそのものは割符のクライアントにしない（private_key_jwt の秘密鍵を公開アプリに置けないため。RP-70、不変条件7）。アプリの中では、企業のサーバーが始めた認可を、システムのブラウザ（ASWebAuthenticationSession、Custom Tabs）で開く。

### ブラウザ側（plan 2章）

- HTML は、応答ごとの nonce と `'strict-dynamic'` の CSP で配る。Trusted Types を必須にし、ポリシーは `'none'`（1つも作らせない）。画面は DOM の API（createElement、textContent）だけで組む。外部のフォントや CDN は使わない。
- Host は設定した1つだけ（421）。`/oidc` 以外への POST は、同じオリジンの Origin だけ（403）。本文は JSON だけで、16KB まで。
- 配信物（HTML、JavaScript、CSS、@simplewebauthn/browser の UMD 版）には、資格情報、鍵、API キーを含めない。判断はすべてサーバーで行う（CAP-37）。確かめ方は、`x-idp-routes`（CSP、nonce、インラインのスクリプトがないこと）と、principle-review の観点7（配信物に鍵や資格情報の文字列がないことを読む）にする。

## 採らなかった案

- **oidc-provider の保存物を DB に置く**：上の「保存」。
- **クッキーを HMAC-SHA-256 で署名する（ADR 0006 のスパイクの形）**：上の「クッキー」。
- **userHandle を乱数にして、userHandle → 利用者の表を引く**：境界の外で引くことになり、不変条件8の新しい例外が要る。
- **アカウントの作成で、メールアドレスを求める**：アカウントを探す手がかりにはしないが、作成の時点で登録済みかどうかの分岐を作ることになる。メールの登録は、作成とは別の、step-up の後の手順にした。
- **最後のパスキーも消せるようにする**：回復（M8）が整うまでは、ログインできなくなる。
- **本物のメールの一意性を、確認コードの照合の後に検査する**：メールを持つ人には登録済みかどうかが分かるだけだが、要件ではないので、分岐を作らない。

## 残るリスク

- **メモリの保存先**：再起動でセッションが消える。プロセスのメモリを読める者は、保存中のトークン（認可コードなど）の平文を得られる（DB のダンプとは違う）。P1 で永続化と合わせて決める。
- **userHandle が利用者 ID**：利用者の認証器（とブラウザ）には、内部の利用者 ID が残る。企業には渡らない（企業に渡るのはテナント単位の sub）。認証器を手にした者は、利用者 ID を知れるが、それだけでは何も許可されない（不変条件1(c) と同じ考え方）。
- **ローカルのクッキーの共有**：ポート違いのアプリ（demo-rp など）は、同じ名前のクッキーを読み書きできる（CLAUDE.md「環境の注意」）。本番では別のドメインと `__Host-` で分ける。
- **レート制限はプロセスごと**：複数のプロセスで動かすと、上限は台数倍になる。
- **パスキーの追加と削除の知らせ**：全端末への知らせは M6 まで出ない。追加と削除には step-up を求める。→ M6 で受信箱に出すようにした（ADR 0023）。

## 結果

- テスト（`test/leak/`）：
  - `t04-pairwise`：テスト4の前半（A社とB社で sub と別名が違い、同じテナントの2つのクライアントで sub が同じ、企業に渡る値の一覧、別名から relay の解決関数でテナントと利用者に戻ること）。
  - `x-webauthn-guards`：ADR 0007 の決定1〜5。
  - `x-webauthn-algorithms`：受け付けるアルゴリズムと、登録した公開鍵の検査（ADR 0012 の決定6・10）。
  - `t10-email-registration`：テスト10（メールの登録の応答が、登録済みかどうかで変わらない）。宛先確認、DB に暗号文だけが残ること、試行の上限、旧アドレスへの知らせ、step-up。
  - `x-idp-oidc`：discovery の方式、step-up（max_age=0、prompt=login）、受け付けない項目、PKCE、クライアント認証、接続しない、別のテナントの同意。
  - `x-idp-routes`：ルートの一覧、Host と Origin、CSP と Trusted Types、PWA のクッキー。
  - `x-idp-passkeys`：追加と削除の step-up、削除でセッションが消えること、最後の1つは消せないこと。
- E2E（`test/leak/x-idp-browser.e2e.ts`）：CDP の仮想認証器で、企業の認可 → アカウントの作成 → 同意 → ID トークン、PWA でのメールの登録、UV のないログインの拒否。一時的な Postgres と鍵サービスと idp を、テストのワーカーの中で起動する。
- 捨てスパイク1（`spikes/passkey`）を消した（spikes/README.md の決まり）。
- 鍵サービスの MAC の用途に、`pairwise_sub`、`oidc_storage_id`、`email_verify_code` を足した（idp だけ。ADR 0013）。
- マイグレーション 0004：`idp.users`、`idp.credentials`、`idp.connections`、`contacts.email`、`contacts.email_pending`、`contacts.email_previous`（ADR 0015）。

## オーナーの確認

| ID | 判断すること | 既定の案 |
|---|---|---|
| O-9 | クッキーを署名しない（ADR 0006 の申し送りを変える） | 署名しない（値は乱数の id） |
| O-10 | oidc-provider の保存物、PWA のセッション、チャレンジをメモリに置く | メモリ。永続化は P1 |
| O-11 | 期限（上の表）とリフレッシュトークン | 表のとおり。リフレッシュトークンは出さない |
| O-12 | 別名のクレームの選び方 | 登録簿のクライアントごとの aliasClaim。既定は email（email_verified は false） |
| O-13 | 本物のメールの一意性 | P0 では検査しない |
| O-14 | レート制限の値 | 上の表 |
| O-15 | パスキーの userHandle | 利用者 ID の16バイト |
| O-16 | 最後のパスキーの削除 | M8 まで消させない |
| O-17 | 承認用の別オリジン | 承認画面を作る M6・M7 で用意する（→ M6 で用意した。ADR 0023 の O-45） |
