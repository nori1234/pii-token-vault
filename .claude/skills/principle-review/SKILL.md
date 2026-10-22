---
name: principle-review
description: 差分が CLAUDE.md の不変条件に反していないかを点検する。点検するのは、肯定リスト（連絡先を本人確認に使わない）、逆引きの禁止、復号は relay だけ、平文を残さない、企業をまたいだ突き合わせの防止、CIBA の hint、SSRF、DB の境界、暗号の許可リスト、列挙の防止、電話、漏えいシナリオのテスト、画面と文言。認証・回復・窓口・中継・ログ・DB・外向きの通信・画面に触れる変更をしたとき、PR を出す前、レビューを頼まれたときに使う。
---

# principle-review

`CLAUDE.md` の不変条件に照らして、差分を点検する。目的は、漏れた連絡先や属性が本人確認として通用する経路を、コードに入れないこと。

## 1. 範囲を決める

指定がなければ、PR のベースブランチ（分からなければ `origin/main`）と比べる。新しいファイルは差分に出ないので、別に一覧を取り、全文を読む。

```sh
git fetch origin
git diff --merge-base origin/main          # 追跡中のファイル（ステージ済みと未ステージ）
git ls-files --others --exclude-standard   # 未追跡の新しいファイル
```

## 2. 観点ごとに点検する

下の検索は手がかりにすぎない。最終的にはコードを読み、値の出どころをたどって判断する。

| # | 観点（CLAUDE.md の番号） | 違反の例 |
|---|---|---|
| 1 | 肯定リスト（1） | メール、電話、氏名、住所、注文番号、決済情報、別名、email クレーム、中継した返信で、アカウントを探す・本人と見なす・操作を許可する。CIBA の結果だけで高リスクの操作を通す。回復を、回復コード・協力者・待機のうち一部だけで成立させる |
| 2 | 逆引きの禁止（2） | sub・別名・窓口コードから、本物の連絡先や本人の属性を返すルート。管理 API に、連絡先・認証器・協力者・回復設定の変更がある |
| 3 | 復号は relay だけ（3） | relay と keysvc 以外で decrypt を呼ぶ。鍵サービスの ACL を広げる |
| 4 | 平文を残さない（4） | 連絡先、別名、トークン、回復コード、窓口コード、招待コード、協力者の表示名を、ログ、例外のメッセージ、DB の平文列、配送ログに書く。テンプレート文字列でログに値を埋め込む。別名を URL に載せる |
| 5 | 突き合わせの防止（5） | sub の導出にテナント ID を使っていない。SET の jti に全体の通番や時刻を使う。email_verified を true にする。別名の世代を戻す |
| 6 | CIBA（6） | `login_hint`、`id_token_hint`、`user_code` を受け付ける。企業が送った binding_message を表示する |
| 7 | SSRF（7） | sender 以外から外部へつなぐ。oidc-provider で jwks_uri・sector_identifier_uri・request_uri を有効にする。動的クライアント登録を有効にする |
| 8 | DB の境界（8） | `withTenant` / `withWarifuUser` を通らない DB アクセス。`set_config` の第3引数が true でない。FORCE の付け忘れ。SECURITY DEFINER 関数を新たに足す |
| 9 | 暗号の許可リスト（9） | 許可リスト以外の方式。96ビット以外の IV。ES256 以外の JWS。WebAuthn で ES256 と RS256 以外を受け付ける |
| 10 | 列挙の防止（10） | 登録済みかどうかで、本文・ステータス・所要時間が変わる分岐（already、exists、409、早めの return） |
| 11 | 電話（11） | 電話番号の入力欄、列、クレームを足す。電話の中継に手を付ける |
| 12 | 漏えいシナリオ（12） | 新しいルートや認証まわりの分岐を足したのに、`test/leak/` にテストがない。テストに「攻撃者が持っている情報、試す経路、期待する結果」と plan 11章のテスト番号が書かれていない（形式は `test/leak/README.md`） |
| 13 | 画面と文言 | DESIGN.md の2章の必須要素が欠けている、または置いてはならないものがある。3章の固定の警告文を変えた。テナント由来の文字列を HTML として描画している |
| 14 | 主張の誇張 | 「漏れても無害」「安全です」「個人情報保護法の対象外」のような断定 |

観点1は、キーワード検索では足りない。差分の中から、アカウントを特定する処理と、許可するか拒否するかを決める分岐（`find*`、`resolve*`、`authorize*`、`verify*` の関数、WHERE 句、if の条件）をすべて挙げる。そのうえで、それぞれの入力が CLAUDE.md 1(a)(b) で許した値だけから来ていることを、出どころまでさかのぼって確かめる。対象には、idp、relay、rp-kit、demo-rp を含める。

補助の検索（`<files>` は、1で挙げたファイル）。`packages/` だけでなく、捨てスパイクの `spikes/` も対象にする（スパイクにも不変条件は適用する）：

```sh
# 観点1：連絡先や属性らしい名前（name、address、alias はノイズが多いので、出どころをたどって見る）
grep -rniE '\b(e-?mail|phone|telephone|msisdn|postal|zip|birth|dob|kana|order_?(id|no|number)|reservation|card|payment)' <files>

# 観点3：relay と keysvc 以外の復号
grep -rniE 'decrypt|decipher' packages/ spikes/ | grep -vE '^packages/(relay|keysvc)/'

# 観点6：受け付けてはならない hint（login_hint_token は許可。拒否を確かめるテストもヒットする）
grep -rnE 'login_hint([^_]|$)|id_token_hint|user_code' packages/ spikes/

# 観点7：sender 以外からの外向きの通信
grep -rnE "fetch\(|https?\.(request|get)\(|net\.connect|tls\.connect|dns\.|from ['\"](undici|got|axios|node-fetch|ky|web-push)['\"]|createTransport" packages/ spikes/ | grep -v '^packages/sender/'

# 観点9：暗号の呼び出し
grep -rnE 'createCipheriv|createDecipheriv|createHash|createHmac|createSign|generateKeyPair' packages/ spikes/

# 観点7と9：lint を黙って外せる書き方（CI の「lint をすり抜ける書き方がないことを確かめる」と同じ検査に、
# 未追跡のファイルを足したもの）。どちらも何も出なければよい。
git grep --untracked -nE 'biome-ignore|getBuiltinModule' -- packages spikes ':(exclude)*.md'
git ls-files --cached --others --exclude-standard | grep -E '(^|/)\.?biome\.jsonc?$' | grep -vx 'biome.json'
```

`npm run lint`（Biome）は、観点7と9の一部をすでに止める。対象は次のとおり。

- `packages/sender` 以外での、外向きの通信のモジュール（`node:net`、`node:dns`、`node:https`、`undici` など）と `node:child_process` の import。`node:http` は、`createServer`、`Server`、`IncomingMessage`、`ServerResponse`、`STATUS_CODES` だけを許す。
- `packages/sender` 以外での、`fetch` などのグローバル。
- `packages/sender` も含めて、`node:module` の import（`createRequire` などで import の制限を回避させない）と、グローバルの `crypto`（Web Crypto）、`globalThis`、`global`。
- `packages/warifu-core`・`packages/keysvc`・`spikes/` 以外での、`node:crypto` の import。

ただし、テスト（`*.test.ts`、`*.e2e.ts`）、`scripts/`、`test/`、ルートの `*.config.ts` は対象外で、`public/` の中ではグローバルの制限（`fetch` など）を外している。CI は、lint に加えて、`packages/` と `spikes/` の中（Markdown を除く）の `biome-ignore` と `getBuiltinModule`（`process.getBuiltinModule` を含む）と、ルートの `biome.json` 以外の Biome の設定ファイル（入れ子のものと、ルートの `biome.jsonc`、`.biome.json`、`.biome.jsonc`）を拒否する。lint と CI が通っても、次の4つは点検する。

- `biome.json` の差分。`overrides` の `includes` が広がっていないか、ルールを `off` にする箇所や、制限するモジュールとグローバルの一覧が減っていないか。広げるなら、理由が PR に書かれているか。
- `.github/workflows/ci.yml` の差分。lint をすり抜ける書き方の検査が、弱められたり消されたりしていないか。
- 制限を外しているファイル（テスト、`scripts/`、`test/`、ルートの `*.config.ts`。`public/` の中ではグローバルの制限）に、上の検索がヒットしないか。ヒットしたら、宛先がテストの中で立てたローカルのサーバーだけかを確かめる。
- `CLAUDE.md`、`.claude/`（settings.json、hooks、skills）、`.npmrc`、`package.json` の scripts、ルートの `*.config.ts`、テストと `scripts/`・`test/` のコード、`.github/`（workflows、dependabot.yml、CODEOWNERS）の差分。フックや設定は、Claude Code でそのブランチを開いただけで動き、テストと設定は `npm test` で動く。メンテナー以外が作った PR は、GitHub の上で読むだけにし、checkout も、セッションでの実行もしない（CLAUDE.md「進め方」）。

観点2は、ルート一覧のスナップショットのテストの差分を必ず読む。観点8は、全テーブルが RLS の ENABLE と FORCE の両方を持つことを `pg_class` の `relrowsecurity` と `relforcerowsecurity` で確かめる固定テストが通っていることを見る。

## 3. 報告する

次の形で報告する。違反がなければ「違反なし」と書き、どの観点をどこまで見たかを添える。

```
## principle-review の結果
- [違反] 観点1 packages/idp/src/recovery.ts:42 — 回復の開始でメールアドレスを受け取っている。回復コードのハンドルで特定する形に直す（ADR 0003）。
- [要確認] 観点7 packages/company-api/src/webhook.ts:18 — fetch を直接呼んでいる。sender 経由に変える必要がないか確認する。
- 見た範囲：観点1〜14。テストは実行していない。
```

## 判断に迷ったら

- 不変条件を破る必要がありそうなら、実装しない。理由を書いて、オーナーに確認する。
- 根拠は `docs/plan.md`、`docs/adr/`、`DESIGN.md` を引く。
- 配置（`packages/` と `spikes/` の名前、CLAUDE.md の「配置」）が変わったら、この skill の検索も同じ PR で直す。
