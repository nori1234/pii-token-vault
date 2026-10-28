# 漏えいシナリオのテスト

漏れた連絡先や属性（と、割符が企業に渡す別名や sub）を持つ攻撃者が、割符と、接続要件を守る企業（完全な参加の企業。ADR 0010）での本人確認を突破できないことを、攻撃者の立場で確かめるテストを置く（CLAUDE.md の不変条件12、plan 11章）。

M2 で、テスト8（`t08-*`）と、RLS の固定テストなど番号のない横断のテスト（`x-*`）を足した。

| ファイル | 確かめること |
|---|---|
| `t08-keysvc-acl` | 鍵サービスの能力の表（全組み合わせ、表にない操作と対象、資格情報を持たないサービス） |
| `t08-keysvc-auth` | 資格情報のなりすましと壊れた形、403 の一律、decrypt の資格情報を増やす設定での起動の拒否 |
| `t08-keysvc-isolation` | TCP と UDP で待ち受けないこと、ソケットとディレクトリの権限、出力に値が出ないこと |
| `t08-ciphertext-binding` | 暗号文の文脈（利用者 ID）への結び付き、書き換えと別の鍵での復号の拒否 |
| `t08-crypto-allowlist` | `node:crypto` を import するファイルと名前、方式の文字列、実際の方式 |
| `t08-key-client-surface` | 鍵のクライアントのメソッド、relay の部品の import、UDS のクライアントと lint の例外 |
| `t08-audit-chain` | 監査ログのチェーンの検証、書き換えの拒否、改ざんの検出 |
| `x-rls-fixed` | RLS の ENABLE と FORCE、ロール、ポリシーと列単位の GRANT の一覧、SECURITY DEFINER が1つだけ |
| `x-db-boundary` | テナントと利用者の境界、境界なしの生の接続、権限の昇格、`sql` タグ |
| `x-relay-resolver` | relay の解決関数（2つの ID だけを返す、廃番の区別がない、relay だけが呼べる） |

M3 で、idp のテストを足した（ADR 0018）。

| ファイル | 確かめること |
|---|---|
| `t04-pairwise` | テスト4の前半（A社とB社で sub と別名が違い、同じテナントの2つのクライアントで sub が同じ。企業に渡る値の一覧。別名から relay の解決関数で戻ること） |
| `t10-email-registration` | テスト10（メールの登録の応答が、登録済みかどうかで変わらない）。宛先確認、DB に暗号文だけが残ること、試行の上限、旧アドレスへの知らせ、step-up |
| `x-webauthn-guards` | ADR 0007 の決定1〜5（attestation、アルゴリズム、userHandle、UV、理由を出さない）とチャレンジの結び付き |
| `x-webauthn-algorithms` | 受け付けるアルゴリズム（ES256、EdDSA、RS256）と、登録した公開鍵の種類・曲線・RSA の鍵長（ADR 0012 の決定6・10） |
| `x-idp-oidc` | discovery の方式、step-up（max_age=0、prompt=login）、受け付けない項目、PKCE、クライアント認証、接続しない、別のテナントの同意 |
| `x-idp-routes` | idp のルート一覧、Host と Origin、CSP と Trusted Types、PWA のクッキー |
| `x-idp-passkeys` | パスキーの追加と削除の step-up、削除でセッションが消えること、最後の1つは消せないこと |
| `x-idp-browser`（E2E） | CDP の仮想認証器で、企業の認可から ID トークンまで、PWA のメールの登録、UV のないログインの拒否。CSP の違反がないこと |

M4 で、relay のテストを足した（ADR 0021）。

| ファイル | 確かめること |
|---|---|
| `t05-relay-sender-lock` | テスト5の送信元ロック（条件を1つずつ外したメールの拒否と理由、リプレイ、知らない別名、受信側での DKIM・ARC・DMARC の pass） |
| `t05-relay-hygiene` | テスト5の中継の衛生（開封通知、Cc、Bcc、Sender の削除、To を別名だけに、List-Unsubscribe の書き換え、本文のバイト列、ログに値を出さない） |
| `t05-relay-reply` | テスト5の返信の中継（DMARC が pass した本物のアドレスからの返信だけ、詐称の拒否、件名と本文の本物のアドレスの差し戻し（文字参照、タグ、%xx、全角、ISO-2022-JP、encoded-word など）、確かめられない部分を含む返信の差し戻し、署名の外の Reply-To、References、テナントと期限） |
| `t10-relay-rcpt` | テスト10（SMTP の RCPT、VRFY、DATA の応答が、別名の状態によらず同じ。relay のドメインでない宛先。同じ接続の次のトランザクションと RSET） |
| `x-relay-internal-api` | relay の内部配送 API（idp の資格情報だけ、受け付ける入力、知らない利用者でも 202、ソケットの権限、idp から relay を経た宛先確認と旧アドレスへの知らせ） |

M5 で、company-api と送信サービスのテストを足した（ADR 0022）。

| ファイル | 確かめること |
|---|---|
| `t04-alias-rotation` | テスト4の後半（入れ替えの後、前の別名あては届かず新しい別名あてだけが届く。ID トークンの sub で入れ替えると次の ID トークンの別名が変わる。一意制約で前の値が戻らない。企業に渡る値の一覧） |
| `t11-sender-ssrf` | テスト11（公開でないアドレスの拒否、URL の形、内部を指す名前、DNS rebinding、リダイレクト、証明書の名前、内部を指す MX と null MX、ログに宛先を出さない） |
| `x-company-api-tenant` | テスト6（A社のトークンでB社に触れない、トークンと client assertion の書き換えが同じ 401、緊急停止、レート制限、境界の外で行が見えない、参加の状態の列がない） |
| `x-company-api-routes` | テスト6（company-api のルート一覧、知らないパスと違う Host の固定の本文） |
| `x-company-api-set` | SET の署名、aud、jti、events、同じ jti での送り直しと諦め、ログと DB に SET を残さない |
| `x-sender-internal-api` | 送信サービスの内部 API（呼び出し元ごとの資格情報と口、パスとメソッド、本文の形、名前解決の口、ソケットの権限） |
| `x-relay-sender` | relay から送信サービスを通った配送、内部を指す MX への配送を止めること、名前解決の口 |

## いつ足すか

- 新しいルートを足したとき。
- 認証・回復・承認・窓口・中継の分岐を変えたとき。
- マイルストーンに割り当てたテスト（下の表）を作るとき。

## 置き場所と名前

- Vitest のテストは `test/leak/*.test.ts`、Playwright のテストは `test/leak/*.e2e.ts` に置く。どちらも、ルートの設定（`vitest.config.ts`、`playwright.config.ts`）がそのまま拾う。
- ファイル名は `tNN-<短い名前>`。NN は plan 11章のテスト番号を2桁で書く（例：`t02-ciba-hints.test.ts`）。番号のない横断のテスト（SSRF、利用者どうしの BOLA など）は、番号の代わりに `x-` を付ける。
- DB を使うテストは、`test/setup/db.ts` を使う。
  - `serviceDb('idp' | 'company-api')`、`relayDb()`：アプリと同じ境界（`withTenant`、`withWarifuUser`）を通る。
  - `rawRoleClient(role)`：境界を設定しない、アプリのロールの生の接続。盗んだ資格情報や SQL インジェクションを模すときに使う（権限はアプリのロールと同じ）。
  - ワーカーの DB は、同じワーカーのファイルの間で共有する。偽の行を足すテストは、境界の中で足して、例外を投げて ROLLBACK する（DB を汚さない）。値は、テストごとの乱数のテナント ID と利用者 ID で分ける。
  - ブートストラップのロール（`workerDatabase()`）で、DB の中身を読み書きしない（不変条件8の例外は、マイグレーションとテスト用の DB の作成だけ）。
- idp を使うテストは、`test/setup/idp.ts` を使う。
  - `startTestIdp`：ワーカーの DB と globalSetup の鍵サービスで、idp をファイルの中に起動する（テナントとクライアントは乱数）。時計を渡せる。
  - `Browser`：クッキーを持つブラウザ役。`registerAccount`、`stepUp`。認証器は `test/setup/soft-authenticator.ts` のソフトウェアの認証器（わざと違えた応答も作れる）。
  - `codeFlow`：企業の役。認可コード、PKCE、private_key_jwt で ID トークンを受け取り、`/oidc/jwks` の鍵で検証する。
  - E2E（`*.e2e.ts`）は、一時的なクラスタ、鍵サービス、idp を、そのファイルのワーカーの中で起動する（`x-idp-browser.e2e.ts`）。
- relay を使うテストは、`test/setup/relay.ts` を使う。
  - `startTestRelay`：ワーカーの DB と globalSetup の鍵サービスで、relay をファイルの中に起動する（テナントと企業の DKIM の鍵は乱数。外への配送はメモリの送信箱）。返信の DMARC の判定に使う DNS の記録と、時計を渡せる。`dns()` は、受信側の検証に使う模擬の DNS。
  - `addUser`、`rotateAlias`：idp と company-api と同じ境界で、利用者、暗号化した本物のメール、別名の世代を作る。
  - `signCompanyMail`、`companyMail`：企業の送信サーバーの代わりに、登録した鍵で署名したメールを作る（条件を外した署名も作れる）。
  - `SmtpSession`、`sendMail`：生の SMTP の会話（応答とその所要時間をそのまま見る）。宛先はテストの中で立てた relay だけ。
  - idp から relay の内部配送 API を呼ぶテストは、`startTestIdp` に `RelayMailer` を渡す。
- 鍵サービスを使うテストは、`test/setup/keys.ts` を使う。
  - `keysvcConnection(service)`：globalSetup の鍵サービスへの接続。DB を使うテストは、これを使う（監査ログのチェーンを、実行全体で同じ鍵で検証するため）。
  - `rawKeysvcCall`：型を通さない生の要求。攻撃の段で使う。
  - 鍵サービスの出力や起動を調べるテストは、`scripts/keysvc-up.ts` の `startKeysvc()` でファイルの中に自分の鍵サービスを起動する。起動に失敗するはずの設定は `startKeysvcExpectingFailure` で試す。

## 先頭のコメント（必須）

各テスト（`it` または `test`）の先頭に、次の4つを書く。1つのファイルに複数のシナリオがあるときは、`it` ごとに書く。

| 項目 | 書くこと |
|---|---|
| 攻撃者が持っている情報 | 漏れた値、企業から受け取った値、奪った端末など。「なし」のときは、そう書いて理由を添える |
| 試す経路 | 呼ぶルートやプロトコルの手順。攻撃者がその情報で何を試すか |
| 期待する結果 | 拒否と、そのステータス（例：400 invalid_request）。副作用がないこと（受信箱、監査ログ、DB） |
| plan 11章のテスト番号 | 例：テスト2。番号のないものは、plan のどの項目かを書く |

## ひな形

```ts
// 攻撃者が持っている情報：利用者の A社での sub と、A社が受け取った本物の ID トークン（A社が侵害された場面）
// 試す経路：A社の資格情報で CIBA を始め、login_hint に sub を、id_token_hint に ID トークンを入れる
// 期待する結果：どちらも 400 invalid_request で拒否する。利用者の端末の受信箱には何も届かない
// plan 11章：テスト2
import { describe, expect, it } from 'vitest';

describe('漏えい：CIBA の hint（plan 11章 テスト2）', () => {
  it('sub を login_hint に入れた要求を、400 invalid_request で拒否する', async () => {
    // 準備：テナント、クライアント、利用者を作る。値は、テストの中で乱数から作る。
    // 攻撃：攻撃者が持っている情報だけを使って、試す経路を呼ぶ。
    const response = await startCiba({ login_hint: leakedSub });
    // 拒否：ステータスと本文を確かめる。
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_request');
    // 副作用：受信箱、監査ログ、DB に、攻撃の結果が残っていないことを確かめる。
    expect(await inboxCount(user)).toBe(0);
  });
});
```

`startCiba`、`leakedSub`、`inboxCount`、`user` は、説明のための仮の名前。

## 書き方の決まり

- 攻撃の段では、攻撃者が持っている情報だけを使う。準備で作った内部の利用者 ID や鍵を、攻撃の呼び出しに渡さない。
- 拒否されたことだけでなく、副作用がないことも確かめる。
- 列挙の防止（不変条件10）に関わるものは、登録済みと未登録の両方で、本文とステータスが同じことを比べる。
- テストの値は、テストの中で乱数から作る。本物らしい連絡先、氏名、番号を書かない。どうしても形式が要るときは、乱数と予約済みのドメイン（`example.com` など）を組み合わせる。
- 時刻を進めるときは、時刻を進めるハーネスを使う（不変条件8の例外）。アプリのコードは、`withTenant` か `withWarifuUser` を通して DB に触れる。
- 不安定なテストを、再試行で通さない（Playwright の `retries` は 0）。

## マイルストーンごとの割り当て

各マイルストーンの PR で、そのマイルストーンに割り当てたテストを足して通す。ゲートでは、それまでに割り当てたテストもすべて通す。正は plan 10章と11章で、この表はその写し。

| マイルストーン | plan 11章のテスト |
|---|---|
| M2 | テスト8、RLS の固定テスト |
| M3 | テスト4の前半、テスト10（登録時の応答） |
| M4（Gate A） | テスト5、テスト10（SMTP の RCPT への応答） |
| M5 | テスト4の後半、テスト6、テスト11 |
| M7（Gate B） | テスト1、テスト2、テスト4（CIBA のクライアントの sub）、テスト6（窓口コードと CIBA のレート制限） |
| M8（Gate C） | テスト3、テスト6（回復のレート制限）、テスト10（回復時の応答） |
| M9 | テスト9（移行中の参加の表示と、検査の分け方を含む。ADR 0010）、テスト12 |
| M10（Gate D） | テスト7、SSRF、利用者どうしの BOLA |

M1 の捨てスパイク（`spikes/`）のテストも、先頭に同じ形式のコメントを書いている。ただし、本実装のテストではないので、ここには置かない。
