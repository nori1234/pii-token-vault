# ADR 0025：操作に結び付いた step-up の認可要求を PAR で受け取る

- 状態：提案。2026-10-29 に、オーナーが方式として PAR（下の「比べた方式」の A）を選んだ。細目の O-50〜O-55 は、オーナーの確認待ち
- 日付：2026-10-29

## 状況

M7 では、用途 `desk` の承認と高リスクの操作の step-up を作る。操作の内容は、RAR（RFC 9396）の `authorization_details` で送る（RP-11、DESIGN.md 2章）。仕様案 v0.7 の例では、その中に申請ID が入る。申請ID は、不変条件4で平文を残さないとした値である。

これまでの文書には、次のことが書かれていた。

- ADR 0019 と仕様案 v0.7 は、保護する値を URL に置かないことを求めた。そのうえで M7 の実装前に、RAR の扱いと、PAR・要求オブジェクトなしの POST の認可要求が成り立つかを確かめるとした。
- 仕様案 v0.7 は、「既存方針で拒否する `request_uri` や、無効化している PAR 等を、この案だけを根拠に有効化しない」とした。
- CLAUDE.md の不変条件7は、oidc-provider で `request_uri` を受け付けないとしている。ADR 0018 は、認可の要求を GET だけにし、`request_uri` を付けた要求を入口で 400 にした。

PAR を使うには、不変条件7の文言を変える必要がある。この ADR は、その根拠と、受け付ける範囲を決める。

## 確かめたこと（oidc-provider 9.12.2 のコード。2026-10-29）

コードを読んで確かめた。動かして確かめるのは M7 のテストで行う。

- **RAR**：`richAuthorizationRequests` は、安定した機能の一覧（`lib/helpers/features.js` の `STABLE`）に入っている。
  - 型ごとの `validate` で検査し、クライアントごとに使える型を絞れる（`authorizationDetailsTypes`）。
  - 使えるのは認可コードのフローだけ。
  - 要求の検査（`lib/shared/check_rar.js`）は、認可の入口と PAR の受け口の両方で走る。
  - `authorizationDetailsForGrantSource`、`authorizationDetailsForAccessToken`、`authorizationDetailsForIntrospection` は、こちらで実装しなければならない（既定の実装は例外を投げる）。
  - 型の検査は1件ずつで、「操作は1件だけ」はライブラリでは確かめない。
- **POST の認可要求**：`enableHttpPostMethods` を有効にすると、`cookies.long.sameSite` が `none` でない限り、設定の時点で例外になる（`lib/helpers/configuration.js` の `checkPostMethods`）。
- **PAR の受け口（既定のパスは `<issuer>/request`）**：
  - クライアントの認証が必須になる。
  - 要求オブジェクトの機能を無効にしてあれば、`request` は `request_not_supported` で拒否される。受け口に送られた `request_uri` は `request_uri_not_supported`、`registration` も拒否される。
  - 発行する値は `urn:ietf:params:oauth:request_uri:` に乱数の id を付けたもので、有効期間は最長60秒（`MAX_TTL`）。
- **認可の入口での `request_uri`**（`loadPushedAuthorizationRequest`）：
  - 受け付けるのは、上の接頭辞で始まり、自分の保存先にあって有効なものだけ。
  - それ以外の値は、`request_uri_not_supported` か `invalid_request_uri` で拒否される。外へ取りに行く処理はない。
- **企業をまたいだ流用**：PAR が作る要求は、`iss` を登録したクライアントにした要求オブジェクトになる。別の `client_id` で使うと、検証で拒否される（`process_request_object.js`）。
- **URL の他の項目**：`request_uri` を使った要求では、PAR で送られなかった項目は捨てられる。URL にほかの項目を付けても、混ざらない。
- **使い捨てになるタイミング**：保存先の値が消費されるのは、認可の応答を返すときである（`lib/actions/authorization/respond.js`）。読み込んでから応答するまでの間（最長60秒）は、同じ値で別のインタラクションを始められる。
- **受け付ける項目の一覧**（`getAuthorizationParams`）：
  - `claims` は、`claimsParameter` を無効にしてあれば一覧に入らず、エラーにならずに捨てられる。
  - `authorization_details` は、RAR を有効にすると、PAR の受け口だけでなく認可の入口（GET）でも受け付けられる。URL に載せた要求は、ライブラリでは止まらない。
- **PAR を必須にする設定**：全体の `requirePushedAuthorizationRequests` と、クライアントごとの `require_pushed_authorization_requests` がある。`allowUnregisteredRedirectUris` は既定で false。

RFC 9126（PAR）と FAPI 2.0 の原文は、この環境から照合できていない（`docs/standards.md`）。この ADR の判断は、上のライブラリの動きと、不変条件だけを根拠にする。

## 比べた方式

| 方式 | 申請に結び付く値が URL に載るか | 変えること | 欠点 |
|---|---|---|---|
| **A. PAR（採る）** | 載らない。URL に載るのは urn と `client_id` だけ | PAR を有効にする。不変条件7の `request_uri` の文言を直す | 企業は、サーバーから PAR を1回呼ぶ必要がある |
| B. POST の認可要求 | 載らない | OIDC のクッキーを `SameSite=None` にする | 他のサイトからの POST にもクッキーが付き、CSRF の守りが弱まる。`Secure` も必須になり、ローカルの http で動かない |
| C. GET のまま | 載る | なし | 申請に結び付く値が、履歴、Referer、ログに残る。ADR 0019 と不変条件4に反する |

A を採る。不変条件7が防ごうとしているのは、割符に外の URL を取りに行かせる SSRF である。PAR の `request_uri` は、割符の保存先の中だけを引き、外へはつながない。

## 決定

### 方式（O-50）

- `authorization_details` を付けた認可の要求は、PAR だけで受け取る。認可の入口（GET）の URL に `authorization_details` を付けた要求は、`request_uri` の有無にかかわらず、入口で 400 にする。RAR を有効にすると、ライブラリは URL の `authorization_details` も受け付けるので（上の「確かめたこと」）、この入口の検査がないと、申請に結び付く値が URL に載る要求が通ってしまう。
- ログインの要求（`authorization_details` なし）は、いまの GET のままでよい。PAR で送ってもよい。すべての要求に PAR を必須にするかは、P1 で FAPI 2.0 への対応と一緒に決める。
- POST の認可要求は使わない。OIDC のクッキーは `SameSite=Lax` のままにする。
- 要求オブジェクト（`request`）は、これまでどおり無効にする（ADR 0018）。

### 受け付ける `request_uri`（O-51）

- 受け付けるのは、割符の PAR の受け口が発行した `urn:ietf:params:oauth:request_uri:` の値だけ。どの値も、外へ取りに行かない（不変条件7）。
- 入口の検査（`REJECTED_AUTHORIZATION_PARAMS`）を変える。`request_uri` は、接頭辞が上の urn で、残りの部分が割符の発行する形（文字の種類と長さ）に合うときだけ、oidc-provider に渡す。それ以外は、渡す前に 400 にする。
- クライアントの登録で `request_uris` を受け付けない（いまのまま。ADR 0018）。
- `request_uri` は、不変条件4の「トークン」に加える。DB、ログ、エラー報告に平文で書かない。
  - `req.url` のクエリは、もともと伏せている。
  - 保存の鍵は、ほかの oidc-provider の保存物と同じく MAC にする（ADR 0018）。
  - 割符の画面は、もともと `Referrer-Policy: no-referrer` を返す。

### PAR の受け口（O-52）

- パスは、oidc-provider の既定の `<issuer>/request`（`/oidc/request`）にする。ルートが1つ増えるので、`test/leak/x-idp-routes` の一覧に足し、`test/leak/` にテストを足す（不変条件12）。
- クライアントの認証は `private_key_jwt`（ES256）だけ。client assertion の `aud` は issuer だけにする（ADR 0006、ADR 0018）。
- 認可の入口で拒否しているもののうち、`id_token_hint`、`request`、`request_uri`、`registration` は、PAR の受け口でも拒否する。`claims` は、`claimsParameter` を無効にしてあるので、受け口では捨てられ、効き目がない（拒否はされない）。
  - この受け口では、oidc-provider が中で本文を読む（Fastify のボディ解析を通さない）。そのため、oidc-provider の検査と設定で止める。
  - 割符は自分の ID トークンを検証する鍵を持たない（ADR 0018）。`id_token_hint` が 500 にならずに 400 になることを、M7 のテストで固定する。
- 有効期間は60秒（oidc-provider の上限のまま）にする。
- `authorization_details` は、割符が定めた型だけを受け付け、1件だけにする。未知の項目は拒否する（RP-11、仕様案 v0.7）。申請との照合（クライアント、主体、期限、操作）は、M7 の ADR で決める。
- レート制限は、企業ごとに置く。値は、M7 で仮置きする。

### 読み込みから応答までの再利用（O-53）

- oidc-provider は、`request_uri` を応答のときに消費する。漏れた `request_uri` を60秒のうちに別のブラウザで開くと、別のインタラクションを始められる。
- これは、申請に結び付いた主体の照合で止める。ログインした利用者が申請の主体と違えば、承認画面を出さずに拒否する（ADR 0019、仕様案 v0.7）。
- 最初に読み込んだ時点で消費するには oidc-provider の中を書き換える必要があるので、そうはしない。
- テスト：漏れた `request_uri` を別の利用者が開いても承認できないこと、別の企業の `client_id` で使えないこと、期限の後と応答の後に使えないこと（plan 11章 テスト1・2）。

### 保存（O-54）

- PAR の保存物（`authorization_details` を含む）は、ほかの oidc-provider の保存物と同じく、プロセスのメモリに置き、鍵を MAC にする（ADR 0018 の O-10）。DB には置かない。
- P1 で保存先を永続化するときは、`authorization_details` に申請ID などの不変条件4の値が入ることを踏まえて決める。

### 企業の手順（O-55）

- 企業は、自社のサーバーから PAR の受け口に `authorization_details` を送る。受け取った `request_uri` と `client_id` だけを付けて、利用者のブラウザを認可の入口に送る。
- rp-kit の参照実装（M9）は、この手順で作る。接続要件では RP-11 に書く。

## 不変条件と文書の変更

- CLAUDE.md の不変条件7を、「`request_uri` は、割符の PAR の受け口が発行した urn の値だけを受け付ける。どの値も外へ取りに行かない」に直す。`jwks_uri`、`sector_identifier_uri`、動的クライアント登録の扱いは変えない。
- CLAUDE.md の不変条件4の「トークン」に、`request_uri` を加える（制限を強める方向の変更）。
- principle-review の観点4と7、plan 2章と10章の M7、spec 02 の RP-11 と RP-71、spec 03 の TH-34、spec 04 の CAP-25 と5章、spec の用語、`docs/standards.md`、ADR 0018 と ADR 0019 の注記を、同じ PR で直す。
- コード（`provider.ts` の PAR と RAR の設定、入口の検査、テスト）は、M7 の PR で変える。それまでの間、コードは `request_uri` をすべて拒否する。これは新しい不変条件より厳しいので、食い違いにはならない。

## 採らなかった案

- **B と C**：上の表のとおり。
- **すべての要求に PAR を必須にする**：FAPI 2.0 と同じ形になり、決まりも単純になる。ただし、M3 のログインの流れとテストを作り直すことになり、ログインの要求には守るべき値が載らない。P1 で FAPI 2.0 への対応と一緒に決める。
- **最初の読み込みで `request_uri` を消費する**：O-53 のとおり、ライブラリの中を書き換えることになる。主体の照合で止められる。

## 残るリスク

- `request_uri` は、60秒の間、ブラウザの履歴と、企業から割符へ移るときの Referer に残る。持っているだけでは承認できない（O-53）。企業の画面の Referrer-Policy は、企業の側の設定になる。
- 企業が、`authorization_details` に自由文を入れたり、内容を偽ったりすることは止められない。割符は、型にない項目を拒否し、固定のラベルだけを出す（DESIGN.md 2章、仕様案 v0.7）。
- RFC 9126 と FAPI 2.0 の原文は未照合である。照合して食い違いがあれば、この ADR を直す。

## オーナーの確認

| ID | 判断すること | 既定の案 |
|---|---|---|
| O-50 | 方式 | `authorization_details` を付けた要求は PAR だけ。ログインは GET のままでよい。POST の認可要求と要求オブジェクトは使わない |
| O-51 | 受け付ける `request_uri` | 割符の PAR が発行した urn だけ。入口で形を確かめる。不変条件4のトークンに加える |
| O-52 | PAR の受け口 | `/oidc/request`。`private_key_jwt` だけ。`id_token_hint`・`request`・`request_uri`・`registration` を拒否する（`claims` は捨てられる）。60秒。型は1件だけ。企業ごとのレート制限 |
| O-53 | 応答までの再利用 | 主体の照合で止める。ライブラリは書き換えない |
| O-54 | 保存 | メモリだけ。鍵は MAC。永続化は P1 |
| O-55 | 企業の手順 | サーバーから PAR を送り、ブラウザには `request_uri` と `client_id` だけを渡す |
