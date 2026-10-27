# ADR 0006：CIBA（poll）の捨てスパイクで分かったこと

> **現行仕様への注記（ADR 0019・0020の文書PR案）**：窓口へのCIBAの採用・M7のクライアント設定と窓口コードは、ADR 0019案ではP0から外す。 この文書の過去の決定・試験結果は履歴として残す。

- 状態：採用（2026-10-20 にオーナーが確認した。plan 9章と ADR 0002 は、この ADR に合わせて 2026-10-20 に直した）
- 日付：2026-10-17

## 状況

M1 の捨てスパイク2として、`oidc-provider` 9.12.2 の CIBA を poll モードで1往復させた（`spikes/ciba-poll/`）。目的は2つ。

- ADR 0002 で「自作になる」とした範囲を確かめる。
- 不変条件4・5・6・7・9 を、どの設定とフックで守れるかを、パッケージのソース（`node_modules/oidc-provider/lib`）で確かめる。

スパイクの作り：

- プロセスの中で http サーバーを立て、企業の役はテストから fetch で呼ぶ。
- 静的なクライアントは、テナント A に2つ（rp-a-web、rp-a-desk）、テナント B に1つ（rp-b-desk）。どれも CIBA だけを使う。
- 窓口コード、端末の受信箱、保存アダプタは、メモリ上の仮の実装にした。承認は、テストが受信箱から要求を選んで行う。
- 型は `@types/oidc-provider` 9.12.1 を使った。
- テストは32件で、`npx vitest run spikes/ciba-poll` で全件が通る。各テストの先頭に、漏えいシナリオのテストの形式でコメントを書いた。

以下、`lib/` は `node_modules/oidc-provider/lib/` を指す。

## oidc-provider がそのまま担うもの

- バックチャネル認証のエンドポイント（POST /backchannel）と、トークンエンドポイントでの poll。承認前は `authorization_pending`、期限切れは `expired_token`、拒否は `access_denied`、使用済みの auth_req_id は `invalid_grant` を返す（`lib/actions/authorization/ciba.js`、`lib/actions/grants/ciba.js`）。
- auth_req_id の発行（既定で256ビットの乱数）と期限。auth_req_id は発行先のクライアントに結び付き、別のクライアントの poll は `invalid_grant` になる（`lib/helpers/grant_source.js` の findGrantSource）。テストで、別のテナントと、同じテナントの別のクライアントの両方を確かめた。
- private_key_jwt のクライアント認証。alg の照合、exp・jti・iss・aud の検査、jti の再利用の拒否を行う（`lib/shared/jwt_client_auth.js`）。
- 承認と拒否を結果に反映する API。`provider.backchannelResult(request, grant または error, { acr, authTime })`（`lib/provider.js`）。
- ES256 の ID トークンの発行（aud は client_id）。
- 要求オブジェクトの拒否。requestObjects を無効にすると、`request` は `request_not_supported` になる。`request_uri` は、authorization エンドポイント以外では常に `request_uri_not_supported` になる（`lib/actions/authorization/request_parameters.js` の rejectUnsupported）。
- 動的なクライアント登録は、既定で無効（`lib/helpers/defaults.js`）。POST /reg は 404 になる。

## 不変条件ごとの使い方

### 不変条件5（sub はテナント単位）

- oidc-provider 9.12.2 は、pairwise の CIBA クライアントに jwks_uri を必須にする（`lib/helpers/client_schema.js` の required()）。CIBA のクライアントのセクター識別子を、jwks_uri のホストから取るためである（`lib/helpers/sector_identifier.js`）。jwks と jwks_uri は同時に使えない（同じファイル）。
- sector_identifier_uri が必須になるのは、response_types が空でないとき（コードフローを兼ねるクライアント）だけである。redirect_uris のない CIBA だけのクライアントでは求められない。ただし、付けても jwks_uri の必須は外れない。
- `pairwiseIdentifier` は、pairwise のクライアントのときだけ、ID トークンのクレームを作る最後の段階で呼ばれる（`lib/helpers/claims.js` の Claims.result）。
- したがって、jwks_uri を受け付けない限り（不変条件7）、CIBA のクライアントでは pairwise も `pairwiseIdentifier` も使えない。テストで、pairwise の CIBA クライアントを4通りに組んで確かめた（どれも外へのつなぎは0回）。
  - jwks だけ：`jwks_uri is mandatory property`
  - jwks と sector_identifier_uri：同じく `jwks_uri is mandatory property`
  - jwks と jwks_uri：`jwks and jwks_uri must not be used at the same time`
  - jwks_uri だけ：検証は通る。鍵は、最初のクライアント認証のときに取りに行く（`lib/models/client.js` の ClientKeyStore.refresh）。
- そこで、CIBA のクライアントは `subject_type: public` にする。`processLoginHintToken` は、導出済みの sub を accountId として返す。sub は base64url(HMAC-SHA-256(鍵, tenant_id + ':' + 利用者 ID))。tenant_id には ':' を含めない。
- public のクライアントでは、ID トークンの sub は accountId そのものになる。`lib/helpers/account_claims.js` が、claims() の返した sub を accountId で上書きするためである。
- このため、oidc-provider の保存先（CIBA の要求、Grant、アクセストークン）には、割符の内部の利用者 ID が入らず、テナント単位の sub だけが入る。テストで確かめた。
- findAccount は、発行済みの sub の表（sub → テナントと利用者）を引き、要求したクライアントのテナントと一致するときだけアカウントを返す。claims() は sub だけを返す。この表は内部でだけ使い、外から呼べるルートには出さない（不変条件2）。
- テストで、同じ利用者について、rp-a-web と rp-a-desk で sub が同じになること、rp-b-desk とは別になること、別の利用者とも別になることを確かめた。

### 不変条件6（hint は窓口コードだけ）

バックチャネル認証の処理の順番は、`lib/actions/authorization/index.js` で決まっている。要点は次のとおり。

1. クライアント認証
2. パラメータの組み立てと、重複・未対応の拒否（request、request_uri）
3. 要求オブジェクトの展開
4. scope などの検査
5. checkCibaContext（`validateRequestContext` と `validateBindingMessage` を Promise.all で呼ぶ）
6. checkExtraParams、assignClaims
7. cibaLoadAccount（hint の処理）
8. 要求の保存、応答の本文、`triggerAuthenticationDevice`

パラメータは、ルートごとの許可リストで組み立てる（`lib/actions/authorization/request_parameters.js` の getAuthorizationParams と `lib/helpers/params.js`）。CIBA のルートでは、login_hint、id_token_hint、user_code のどれもが ctx.oidc.params に載る。空の文字列は undefined になる。

cibaLoadAccount（`lib/actions/authorization/ciba.js`）の中身：

- id_token_hint は、oidc-provider 自身が検証し（checkIdTokenHint）、その sub を accountId にする。ここにフックはない。
- login_hint は `processLoginHint`、login_hint_token は `processLoginHintToken` に渡る。
- user_code は、アカウントを読み込んだ後の `verifyUserCode` に渡る。つまり、窓口コードの照合より後になる。

そこで、次のようにした。

- `features.ciba.validateRequestContext` を「hint の入口の検査」に使う（request_context 自体は使わない）。login_hint、id_token_hint、user_code のどれかがあれば、`invalid_request`（400）で拒否する。login_hint_token がないときも、同じく拒否する。
- この時点では、窓口コードにも id_token_hint にも触れていない。user_code 付きの要求を拒否した後でも、同じ窓口コードが使えることで確かめた。本物の ID トークンを id_token_hint に付けても、検証の前に拒否される。
- 二重の守りとして、`processLoginHint` は常に拒否し、`verifyUserCode` は user_code があれば拒否する。
- discovery は `backchannel_user_code_parameter_supported: true` を必ず返す。`configuration.discovery` は値のない項目しか埋めないので、上書きできない（`lib/actions/discovery.js`）。`provider.use` のミドルウェアで応答を書き換えて false にした。

binding_message：

- 企業が送った値は、拒否せずに無視する（`validateBindingMessage` は何もしない）。plan 3-1 は「企業が送ったものは使わない」としていて、拒否までは求めていない。表示と保存から外せば、利用者には届かない。
- 既定の `validateBindingMessage` は、1〜20文字の限られた ASCII だけを受け付け、それ以外を `invalid_binding_message` で拒否する（`lib/helpers/defaults.js`）。割符では値を使わないので、何もしない関数に置き換えた。長さの上限は、本文の上限（56KB。`lib/shared/selective_body.js`）だけになる。
- 承認画面（受信箱）には、割符の登録簿の企業名と窓口の種類から作った文言だけを出す（例：「B社の電話窓口での本人確認」）。企業が送った文言が、受信箱にも保存先にも残らないことを確かめた。
- 保存アダプタは、CIBA の要求の params から binding_message を取り除く（後述）。

窓口コード：

- 照合と同時に失効させる。照合の後の手順が失敗しても戻さない。
- 発行先の client_id と違う、期限切れ、使用済み、形式違いは、すべて `unknown_user_id`（400）の同じ本文にする。`processLoginHintToken` が undefined を返すと、oidc-provider がこのエラーにする。`expired_login_hint_token` は使わない（コードが存在したことを知らせてしまうため）。
- 別のクライアントで照合されたコードは、その時点で失効する。同じテナントの別のクライアントでも同じ。
- 平文は保存せず、HMAC-SHA-256 を索引にする。

### 不変条件7（外向きの通信）

- oidc-provider の外向きの通信は、すべて `configuration.fetch` を通る（`lib/helpers/fetch_request.js`）。呼び出し元は次のとおり。
  - jwks_uri の取得（`lib/models/client.js` の ClientKeyStore.refresh）
  - sector_identifier_uri の検証（`lib/helpers/sector_validate.js`）
  - ping モードの通知と、backchannel logout（`lib/models/client.js`）
  - Client ID Metadata Document（`lib/helpers/client_id_metadata_document.js`。既定で無効）
- `fetch` を、常に失敗し、呼ばれたホスト名を数える関数に差し替えた。全テストで0回だった。テストの側でも、自分のサーバー以外への fetch を失敗させて数えた（0回）。
- jwks_uri などを受け付けない設定は、oidc-provider にない。そこで2段で守る。
  1. Provider を作る前に、静的なクライアントを肯定リストで検査する（`spikes/ciba-poll/static-clients.ts`）。許す項目は、client_id、tenant_id、jwks、grant_types、response_types、redirect_uris、token_endpoint_auth_method、token_endpoint_auth_signing_alg、id_token_signed_response_alg、backchannel_token_delivery_mode だけ。jwks の鍵は EC P-256 の公開鍵だけにする（d、x5u、x5c などは拒否）。
  2. `extraClientMetadata.validator` で、jwks_uri、sector_identifier_uri、backchannel_client_notification_endpoint などを拒否する。この関数は、登録した追加の項目（tenant_id）ごとに必ず呼ばれ、metadata の全体を見られる。Client を作る処理の最初に走り、required() や sector_identifier_uri の取得より前に当たる（`lib/helpers/client_schema.js` の processCustomMetadata）。
- request_uris は、9.12.2 では認識されない項目で、エラーにならずに捨てられる（`lib/consts/client_attributes.js` の RECOGNIZED_METADATA にない。client_schema.js の ensureStripUnrecognized）。認識されない項目は、どれも黙って捨てられる。設定の誤りを見つけるためにも、1の事前検査が要る。
- 静的なクライアントは、最初に使われたときに検証される（`lib/models/client.js` の Client.find）。起動時に全部を読み込み、誤りを起動の時点で見つけるようにした。
- Client.find は、静的なクライアントに見つからない client_id を、保存アダプタから探す。アダプタは、Client については常に「見つからない」を返し、保存も拒否する。
- devInteractions、PAR、dPoP、rpInitiatedLogout、userinfo、resourceIndicators は既定で有効なので、明示的に無効にした。dPoP は、P1 で全面適用するときに決める。

### 不変条件9（暗号）

- `clientAuthMethods: ['private_key_jwt']` にし、`enabledJWA` の署名の項目をすべて `['ES256']`、暗号化の項目をすべて空にした。discovery は、認証方式が private_key_jwt だけ、署名が ES256 だけと示す。
- HS256、RS256、alg なし、登録されていない ES256 の鍵の client assertion は、どれも 401 invalid_client になる。client_secret_basic も 401 になる。トークンエンドポイントでも確かめた。
- aud について、oidc-provider は issuer、トークンエンドポイント、今のエンドポイントの URL のどれでも受け付ける（`lib/helpers/oidc_context.js` の clientJwtAuthExpectedAudience）。`assertJwtClientAuthClaimsAndHeader` で issuer だけに絞り、alg も重ねて確かめた（aud の取り違えを使う攻撃への備え）。
- クライアントの既定値は、id_token_signed_response_alg が RS256、token_endpoint_auth_method が client_secret_basic である（`lib/consts/client_attributes.js`）。`clientDefaults` で ES256 と private_key_jwt にした。
- Provider の署名鍵は、jose で作った ES256 の鍵にした。
- client assertion の jti は、oidc-provider が内部で sha256(iss + jti) にしてから保存する（`lib/models/replay_detection.js`）。ライブラリの内部の処理で、自前のコードの暗号の呼び出しではない。

### 不変条件4（平文を残さない）

- 不透明なトークンの値は、そのまま保存の id（jti）になり、payload にも jti として入る（`lib/models/formats/opaque.js` の getValueAndPayload、`lib/models/base_model.js` の save）。アダプタは次のようにする。
  - 保存キーを HMAC-SHA-256(鍵, model + ':' + id) にする。
  - payload から jti を取り除き、find のときに、受け取った id を戻す。
- CIBA の要求は、`params: ctx.oidc.params.toPlainObject()` をそのまま保存する（`lib/actions/authorization/ciba.js` の backchannelRequestResponse）。窓口コード（login_hint_token）と binding_message が平文で入るので、アダプタで取り除く。
- 1往復の後、保存先、受信箱、窓口コードの保管のどれにも、次のものが平文で残っていないことを確かめた：窓口コード、auth_req_id、アクセストークン、ID トークン、client assertion、企業の binding_message。
- 承認の経路では、auth_req_id の平文を持たずに、CIBA の要求を更新する必要がある。
  - idp は decrypt の権限を持たない（不変条件3）ので、auth_req_id を暗号化して受信箱に置く案は取れない。
  - そこで、受信箱には保存キー（HMAC）を置く。承認のときは、保存キーから要求を作り直して `backchannelResult` に渡す。
  - 作り直した要求の jti には、文字列でない「保存キーの参照」（`StorageKeyRef`）を入れる。oidc-provider の save は、これをアダプタの upsert にそのまま渡すので、アダプタは保存キーとして扱う。外から届く値は文字列なので、この参照にはならない（`lib/models/base_model.js` の find は、文字列以外を受け付けない）。
  - これは oidc-provider の内部の振る舞いに頼っている。版を固定し、テストで守る。
- oidc-provider は、`DEBUG=oidc-provider:*` のときに、`debug` でエラーを出す（`lib/shared/error_handler.js`）。本番では有効にしない。フックで投げるエラーの説明には値を入れない。error_description は RFC 6749 で ASCII に限られるので、英語にした。

### 不変条件8（DB の境界）について調べたこと

- アダプタの中から、`Provider.ctx`（AsyncLocalStorage。`lib/provider.js` の static get ctx）で今の要求の ctx が取れる。poll のとき、認証済みのクライアントの client_id が見えることを確かめた。M3 で Postgres のアダプタを作るとき、これで withTenant に入れられる見込み。
- 承認の経路（要求の外で `backchannelResult` を呼ぶとき）では、Provider.ctx がない。受信箱の持ち主（withWarifuUser）と、payload の clientId から決める必要がある。

## 決定

スパイクのコードは捨てる。M7 の実装には、次の方針を持ち込む。

1. CIBA のクライアントは public にし、`processLoginHintToken` で導出済みの sub を accountId として渡す。sub の導出関数は1つにまとめる。
2. hint の検査は `validateRequestContext` に置き、`processLoginHint` と `verifyUserCode` でも拒否する。discovery の `backchannel_user_code_parameter_supported` を false に書き換える。
3. 企業の binding_message は無視し、表示も保存もしない。承認画面には、割符が生成した文言だけを出す。
4. 外向きの通信は、fetch の差し替え、静的なクライアントの肯定リスト、`extraClientMetadata.validator` の3つで防ぐ。起動時に静的なクライアントを全部読み込む。
5. クライアント認証は ES256 の private_key_jwt だけにし、aud は issuer だけにする。
6. acr は割符が決める値にし、窓口（CIBA）の結果であることを企業に示す（スパイクでは `urn:warifu:acr:desk`）。acr と auth_time は、要求されたときだけ ID トークンに入る（`lib/actions/authorization/claims.js` の assignClaims）。そこで、割符の側でクライアントに `default_acr_values` と `require_auth_time` を付ける。
7. 保存アダプタは、id を HMAC にし、CIBA の要求の params から窓口コードなどを外し、Client を保存しない。承認の経路は、保存キーで要求を引く。
8. 窓口コードの失敗は、理由を問わず `unknown_user_id` の同じ応答にする。一度照合したコードは失効させる。

## 自作が必要な範囲

スパイクで形を確かめたもの：

1. 窓口コードの発行と照合（HMAC の索引、client_id への結び付け、有効期間、一度で失効）
2. 端末の受信箱（所有者の照合、保存キーでの要求の参照）
3. binding message の生成（割符の登録簿の企業名と、窓口の種類）
4. hint の拒否と、discovery の書き換え
5. 保存アダプタ（id の HMAC、jti と params の除去、Client を保存しないこと）
6. 静的なクライアントの肯定リストの検査と、起動時の読み込み
7. 発行済みの sub の表（findAccount 用）

スパイクで作っていないもの：

- 窓口コードの DB 化。照合と失効は1つの文（DELETE … RETURNING など）で行い、同時に届いた2つの要求の両方を通さない（メモリ上の実装は同期処理なので、この競合が起きない）。桁数と、テナントごとの試行上限（M7 で ADR に記録する）。
- 窓口コードの2段階の発行画面と、UV 付きパスキーでの発行（plan 3-1、DESIGN.md 2章）。
- 承認画面。DESIGN.md 2章の要素、警告文 A-1、承認用の別オリジン、UV 付きパスキーでの承認と拒否、「心当たりがない」（拒否と同時に、その企業あての窓口コードを失効させる）。
- 受信箱の DB 化と、端末への通知（M6 の共通基盤）。
- 保存アダプタの Postgres 化。grantId での取り消しの索引、期限での削除、withTenant と withWarifuUser への載せ方。
- レート制限。oidc-provider は、CIBA の要求の応答に interval を付けず、poll が速すぎても slow_down を返さない（`lib/actions/grants/ciba.js`）。窓口コードの試行、CIBA の要求、poll の上限は自作する（plan 2章）。
- 窓口での変更の事後通知と、24時間の取り消し（plan 3-1）。oidc-provider とは関係しない。
- 利用者の凍結などを、トークンの発行のときに確かめること（findAccount）。
- 企業の窓口画面にも、割符が生成した文言を出すかどうか。`triggerAuthenticationDevice` の時点で応答の本文はできているので、項目を足すことはできる。M7 で決める。

## 注意（gotchas）

- pairwise の CIBA クライアントには jwks_uri が必須（上記）。コードフローでも、redirect_uris のホストが2つ以上あると sector_identifier_uri が必須になる（client_schema.js の required()）。M3 では、コードフローのクライアントごとに、redirect_uris のホストを1つにする必要がある。
- 認識されないクライアントの項目は、エラーにならずに捨てられる。
- acr と auth_time は、要求されたときだけ ID トークンに入る。
- 拒否のとき、`backchannelResult` に渡した説明は企業に届かない。`lib/provider.js` は説明を error_description に入れるが、保存する項目は errorDescription である（`lib/models/backchannel_authentication_request.js`）。応答は `access_denied` だけになる。
- `ttl.BackchannelAuthenticationRequest` を数値にすると、企業の requested_expiry は検査だけされて使われない。既定の関数だけが requested_expiry を見る（`lib/helpers/defaults.js`）。
- `triggerAuthenticationDevice` は、要求を保存し、応答の本文を作った後に呼ばれる（`lib/actions/authorization/ciba.js` の backchannelRequestResponse）。ここで失敗すると、保存済みの要求が残る。
- CIBA だけの構成でも、GET /auth、GET /auth/:uid、POST /token、GET /jwks、discovery の2つ、POST /session/end/confirm と、/token・/jwks・discovery の OPTIONS（CORS）は登録され、設定では消せない（`lib/helpers/initialize_app.js`）。ルート一覧の固定（plan 2章）には、これらを含める。
- **public と導出済みの accountId は、コードフローには使えない**（M3 への申し送り）。コードフローでは、セッションの accountId を、別のクライアントの認可にもそのまま使う（`lib/actions/authorization/session.js` の loadAccount）。テナント単位の値を accountId にすると、A社で作ったセッションから、B社のクライアントにもA社の sub が渡る。コードフローのクライアントは pairwise と `pairwiseIdentifier` にする。逆に、public のコードフローのクライアントが1つでもあると、内部の利用者 ID がそのまま sub になる（不変条件5に反する）。静的なクライアントの検査で、「コードフローは pairwise、CIBA だけは public」を強制する。
- 同じ auth_req_id で、トークンを受け取った後にもう一度 poll すると、`invalid_grant` になるだけでなく、その Grant から出したトークンも取り消される（`lib/helpers/grant_source.js` の consumeGrantSource）。rp-kit の SDK は、受け取った後に poll しない。
- oidc-provider は、エラーのときに `server_error`、`grant.error`、`backchannel_authentication.error` などのイベントを、Koa の ctx と一緒に出す（`lib/shared/error_handler.js`）。割符がこれらをログに出すときは、ctx や params を渡さず、エラーの種類だけを構造化したフィールドで残す（不変条件4）。
- CIBA の応答には、access_token が必ず付く。userinfo を無効にした構成では、使い道がない。企業が根拠にしてよいのは、ID トークンの iss・sub・acr・auth_time だけ（不変条件1(a)）。
- `provider.use` で入れる Koa のミドルウェアは、本文の解析より前に走る（`lib/provider.js` の use は、ルーターの前に差し込む）。後処理（discovery の書き換え）には使えるが、パラメータの検査には向かない。
- **承認と拒否の競合**：同じ承認待ちへの承認と拒否が、どちらも受信箱の検査を通ってから await で入れ替わると、両方が成功しうる（Grant が作られ、poll には ID トークンが出る）。`backchannelResult` は、要求に結果がもう入っているかを確かめずに上書きする（`lib/provider.js`）。スパイクでは、最初の await より前に受信箱の状態を resolving に変え、grantId、error、consumed のどれかがもう入っている要求を拒否した（`spikes/ciba-poll/provider.ts` の settle と loadRequest）。M6 と M7 では、この状態の変更を DB の1つの文で行う（例：`UPDATE … SET state = $2 WHERE id = $1 AND state = 'pending' RETURNING …`）。
- **クッキーの署名**：`cookies.keys` に配列を渡すと、Koa の cookies が Keygrip の既定の HMAC-SHA1 で署名する。HMAC-SHA1 は、不変条件9の許可リストにない。oidc-provider は、配列でない keys をそのまま Koa に渡す（`lib/provider.js`）。スパイクでは、Keygrip と同じ形（sign、verify、index）で HMAC-SHA-256 を使うオブジェクトを渡した（`spikes/ciba-poll/provider.ts` の cookieKeys）。CIBA だけの構成ではクッキーを使わないが、M3 の画面とセッションはこの設定の上に作るので、M3 でもこの形を保つ。→ M3 では、クッキーを署名しないことにした（ADR 0018 の O-9。値は乱数の id で、署名の鍵を idp のプロセスに置かないため）。署名の鍵を渡さなければ、HMAC-SHA1 も使われない。
- `@types/oidc-provider` 9.12.1 は、BackchannelAuthenticationRequest のコンストラクタの型が狭く、Client の追加の項目（tenant_id）の型がない。スパイクでは、理由を書いた局所的な型の変換で済ませた。

## 採らなかった案

- **pairwise と jwks_uri**：jwks_uri を受け付けると、oidc-provider が企業の URL へつなぐ。fetch を差し替えて登録済みの鍵を返す案も、「jwks_uri を受け付けない」（不変条件7）に反する。
- **pairwise と sector_identifier_uri**：CIBA のクライアントでは、付けても jwks_uri の必須は外れない。sector_identifier_uri 自体も、取得が起きる。
- **内部の利用者 ID を accountId にし、claims() で sub を変える案**：public のクライアントでは、claims() の sub は accountId で上書きされる（`lib/helpers/account_claims.js`）。成り立たない。
- **hint の拒否を provider.use のミドルウェアで行う案**：本文の解析より前に走るので、本文を自分で読む必要があり、要求オブジェクトの中の値も見えない。
- **hint の拒否を extraParams の検査関数で行う案**：checkExtraParams は cibaLoadAccount より前に走るので、位置としては使える。ただし、authorization、PAR、デバイス認可でも呼ばれ、「追加のパラメータ」の仕組みを既存のパラメータに使うことになる。validateRequestContext のほうが、CIBA だけに効く。
- **企業の binding_message を拒否する案**：plan は「使わない」としている。無視して表示と保存から外せば足りる。拒否にするかは、M7 で接続要件と合わせて再検討する。
- **auth_req_id を暗号化して受信箱に置く案**：idp は decrypt を持たない（不変条件3）。
- **承認のとき、アダプタの行を直接書き換える案**（backchannelResult を使わない）：oidc-provider の保存形式に直接頼ることになり、ping の通知なども自前になる。StorageKeyRef の案も内部の振る舞いに頼るが、公開の API（backchannelResult）を通せる。

## 結果

- **plan 9章との差**：plan 9章の「`pairwiseIdentifier` を上書きし、sub を『テナント ID と HMAC』から導く」は、CIBA のクライアントには当てはまらない（jwks_uri が必須になり、不変条件7と両立しない）。不変条件5の結果（テナント単位の sub）は、public と導出済みの accountId で満たせる。plan 9章は、この ADR に合わせて直した（2026-10-20）。コードフローだけを使うクライアントは `subject_type: pairwise` と `pairwiseIdentifier`、CIBA だけを使うクライアントは `subject_type: public` と導出済みの accountId にする（クライアント認証は、どちらも private_key_jwt）。導出関数は共通にし、兼用のクライアントは静的なクライアントの検査で拒否する。接続要件にも RP-77（コードフローと CIBA は別のクライアントとして登録する）を足した。
- **ADR 0002 の見込み（800〜1,200 行）**：
  - スパイクの本体（テストを除く5ファイル）は、空行とコメントを除いて約710行だった。内訳は、静的なクライアントの検査 160、窓口コード 73、保存アダプタ 115、受信箱 44、Provider の組み立てとフック 321。メモリ上の実装で、画面、UV 付きパスキー、DB、レート制限、事後通知と取り消しを含まない。
  - サーバー側の CIBA の部分（設定とフック、窓口コード、アダプタの DB 化、レート制限）だけなら、800〜1,200 行に収まる見込み。
  - 承認画面と窓口コードの発行画面、受信箱の CIBA の分、事後通知と取り消しまで含めると、1,500〜2,500 行（テストを除く）と見る。画面と受信箱を含めるなら、ADR 0002 の見込みは少なすぎる。
  - どちらも根拠の弱い見積もりなので、M6 と M7 の実績で見直す。
- **M3 で確かめること**：
  - コードフローのクライアント（pairwise と pairwiseIdentifier）と、CIBA のクライアント（public と導出済みの accountId）で、sub が同じ値になること。M3 では導出関数の単体テストで固定し、M7 で CIBA のクライアントを含めて確かめる（テスト4。plan 10章）。
  - コードフローは pairwise にする（「注意」を参照）ので、セッションの accountId は内部の利用者 ID になる。CIBA とは accountId の意味が違うので、findAccount で取り違えないこと。
  - Postgres の保存アダプタを、Provider.ctx を使って withTenant に載せること。→ M3 では、保存物をメモリに置いた（ADR 0018 の O-10。Session と Interaction は境界が決まる前に引くため）。永続化は P1。
- **M7 で決めること**：窓口コードの桁数と試行上限、レート制限の値、binding_message を拒否するか、企業の窓口画面に割符の文言を出すか、acr の値。
