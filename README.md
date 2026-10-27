# 割符（Warifu）

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Status: PoC](https://img.shields.io/badge/status-PoC%20%2F%20pre--alpha-orange.svg)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> [!WARNING]
> **本番では使わないでください。** PoC の実装の初期段階です（M1：雛形、捨てスパイク、仕様書の骨子まで）。本物の連絡先や個人情報を入れないでください。
>
> 割符という名前のサービスは、どこでも運用していません。接続している企業もありません。割符を名乗って連絡先やコードを求める連絡は、このプロジェクトとは関係がありません。
>
> 法令についての記述（[docs/plan.md](docs/plan.md) の7章など）は、このプロジェクトの作業上の前提で、法的な助言ではありません。弁護士や官庁の確認はまだで、引用している基準や資料は、多くを原文で照合しましたが、接続できずに検索の抜粋でしか確かめていないものも残っています（[docs/standards.md](docs/standards.md)）。

企業が利用者の本物の連絡先を本人確認に使わず、持たずに済む状態をつくる基盤「割符」の PoC と、設計の仕様書です。

名前の「割符」は、1枚の札を2つに割り、両方の片割れを突き合わせて相手を確かめる昔の道具から取りました。連絡先ではなく、手元にある片割れ（パスキー）で本人を確かめる、という考え方を表しています。npm のパッケージ名は `@pii-token-vault/*` です（npm にはまだ何も出していません）。ほかのスコープ（`@warifu` など）や、スコープのない `warifu` などのパッケージ、同じ名前のほかのプロジェクト、秘密分散の「電子割符」の製品とは関係がありません。

> **English summary**: **Warifu** (割符, a Japanese tally split in two whose halves are matched to confirm the other party) is an open design and early-stage proof of concept for a service that aims to let companies stop relying on customers' email addresses, phone numbers, postal addresses, and other personal attributes for identity verification. **It is not production-ready: do not use it in production or with real personal data.** Companies connected to Warifu may base identification and approval only on Warifu-issued ID token claims (`iss`, `sub`, `acr`, `auth_time`), CIBA results (for inquiries and low-risk requests only), and transaction-bound step-up approvals; users sign in to Warifu with passkeys. Instead of real email addresses, companies receive per-company email aliases and pairwise subject IDs. In P0 this covers email only, and only what a company receives after a customer's account is linked; real addresses a company already holds remain unless it deletes them. Phone numbers (pending legal review) and postal addresses are not yet covered, and correlation across companies through name and delivery address is not prevented. The project is designed so that merely knowing, or being able to receive, leaked contact details or attributes is not enough to pass identity verification at Warifu or at companies that meet its connection requirements. It does not prevent leaks; known residual risks are listed in [docs/plan.md section 1-2](docs/plan.md#1-2-主張できる範囲と残るリスク). No Warifu service is operated anywhere and no company is connected; the project is not affiliated with or endorsed by any organization it cites. Statements about Japanese law are the project's working assumptions pending legal review, not legal advice, and most of the cited standards and advisories have been checked against their original text, but a few that could not be fetched have been checked only against search excerpts. The npm package names use the `@pii-token-vault` scope; nothing has been published to npm yet. Documentation is in Japanese. Licensed under MIT.

## 目次

- [なぜ作るのか](#なぜ作るのか)
- [3つの原則](#3つの原則)
- [いまの状態とロードマップ](#いまの状態とロードマップ)
- [ドキュメント](#ドキュメント)
- [はじめかた（開発者向け）](#はじめかた開発者向け)
- [コントリビュート](#コントリビュート)
- [セキュリティ](#セキュリティ)
- [ライセンス](#ライセンス)

## なぜ作るのか

個人情報の漏えいは防ぎきれません。2026年10月には、公開アプリを解析してサーバー側の不備を突く攻撃について、NICT（「A2B攻撃」と名付けた）と総務省が注意を促しました（資料と確認状況は [docs/standards.md](docs/standards.md)）。

被害が広がる大きな理由の一つは、漏れた連絡先や属性が、どこかで本人確認として通用してしまうことにあります。メールで再設定できる、SMS のコードで通る、電話で生年月日を言えば本人として扱われる、といった仕組みです。

割符は、この「通用する」経路を断つことを目指します。

## 3つの原則

1. **使わせない**：企業が本人確認・承認・識別の根拠にしてよいのは、次の3つだけにする。連絡先や属性は根拠にしない（移行中の参加の企業には、決まった3つの入り口（パスワードなどの再設定、企業独自のパスワードでのログイン、予約番号などでの確認・変更・取り消し）の中に限って、期限付きの例外がある。高リスクの操作には、例外はない。その企業は、下の主張の対象に含めない。[ADR 0010](docs/adr/0010-staged-participation.md)）。
   - 割符が発行する ID トークンの `iss`・`sub`・`acr`・`auth_time`
   - CIBA の結果（照会と軽い手続きだけ）
   - 操作に結び付いた step-up の結果
2. **持たせない**：企業には、本物のメールアドレスの代わりに、企業ごとの別名と企業別ID（pairwise sub）を渡す。P0 で達成できるのはメールだけで、それも割符に参加した後に企業へ渡すものに限る（紐付けの前から企業が持っているものは、企業が消さない限り残る）。電話は未達（法務の判断待ち）。住所は、受け取り場所の指定などで段階的に減らす。
3. **つなげさせない・届けさせない**：企業ごとに別の sub と別名を使い、別名あてのメールは送信元ロックを通ったものだけを届ける。ただし、氏名と受け取り場所を企業に渡す限り、企業をまたいだ突き合わせは防げない。

主張できるのは「漏れた連絡先や属性を知っている・受け取れるだけでは、割符と、接続要件を守る企業での本人確認は突破できない」までです。ここでの「接続要件を守る企業」には、移行中の参加の企業（期限まで一部の旧経路を残してよい企業。[ADR 0010](docs/adr/0010-staged-participation.md)）を含みません。分かっている残るリスクは、[docs/plan.md](docs/plan.md) の 1-2 に一覧にしています。

## いまの状態とロードマップ

設計の文書がそろい、PoC の実装の最初の段階（M1：雛形と捨てスパイク、仕様書の骨子）を終えました。いまは M2（暗号、鍵サービス、DB の境界）を進めています。各マイルストーンはイシューで管理しています。

| マイルストーン | 内容 | ゲート | 状態 |
|---|---|---|---|
| M0 | 一次資料の原文照合（実装と並行） | | 接続できた資料は照合済み（ADR 0012） |
| M1 | 雛形、パスキーと CIBA の試作、仕様書の骨子 | | 完了 |
| M2 | 暗号、鍵サービス、DB の境界 | | 進行中 |
| M3 | ログイン（idp） | | 未着手 |
| M4 | メール中継（relay） | Gate A | 未着手 |
| M5 | 企業向け API と送信サービス | | 未着手 |
| M6 | 端末承認の共通基盤 | | 未着手 |
| M7 | 窓口での本人確認（CIBA と窓口コード） | Gate B | 未着手 |
| M8 | 回復（連絡先を使わない） | Gate C | 未着手 |
| M9 | 企業向け SDK、適合テスト、デモ | | 未着手 |
| M10 | 横断テストと仕様書の確定 | Gate D | 未着手 |

電話の中継は、法令（犯罪収益移転防止法など）の判断が出るまで保留しています。

## ドキュメント

| ファイル | 内容 |
|---|---|
| [docs/plan.md](docs/plan.md) | 実装計画（原則、設計、法規制、マイルストーン、受け入れ基準） |
| [DESIGN.md](DESIGN.md) | 画面と文言の規則、デザイントークン |
| [CLAUDE.md](CLAUDE.md) | 開発者と AI エージェントが守る不変条件、環境の注意 |
| [docs/adr/](docs/adr/) | 設計判断の記録 |
| [docs/spec/](docs/spec/README.md) | 外注向けの仕様書（原則と肯定リスト、接続要件、脅威モデル、能力の表。M1 時点の骨子で、M10 で確定する） |
| [docs/standards.md](docs/standards.md) | 設計の根拠にしている基準と一次資料、その確認状況 |

文書の誤りに気づいたら、GitHub でそのファイルを開き、右上の鉛筆アイコンから直接直せます（フォークと PR が自動で作られます）。

## はじめかた（開発者向け）

### 前提

- **Node 22.18 以上**と npm。`.ts` のファイルは、ビルドせずに Node の型の除去（type stripping）でそのまま動かします。
- **Postgres 16 のバイナリ**。既定では `/usr/lib/postgresql/16/bin` を使います。別の場所にあるときは、環境変数 `PG_BIN` で指定します。システムのクラスタ（5432 番）は使いません。
- **Playwright 用の Chromium**。下の「コマンド」のとおり、`npm ci` の後に入れます（ブラウザがすでに入っている環境では不要です）。`@playwright/test` は 1.56.1 に固定しています。

### コマンド

```sh
npm ci
npx --no playwright install --with-deps chromium   # 初回だけ。--no で、npm ci で入れた版だけを使う
npm run lint        # Biome。不変条件7と9に反する import も止める
npm run typecheck   # tsc --noEmit
npm test            # Vitest（一時的な Postgres と鍵サービスを自動で起動して止める）
npm run e2e         # Playwright（パスキーは CDP の仮想認証器で試す）
npm run pg-up       # 一時的な Postgres を手で起動する
npm run migrate     # pg-up で起動した Postgres に、マイグレーションを流す（PGDATABASE も指定する）
```

- PR では、上の4つ（lint、typecheck、test、e2e）がすべて通ることを求めます。CI（[.github/workflows/ci.yml](.github/workflows/ci.yml)）でも同じものを実行します。
- `npm run pg-up` は、一時的なディレクトリにクラスタを作って起動し、接続先（`PGHOST`、`PGPORT`、`PGUSER`）を表示します。TCP では待ち受けず、Unix ソケットだけを使います。Ctrl-C で止めると、ディレクトリごと消えます。

### いまあるコード

- `packages/`：本実装の置き場所です。M2 で、`warifu-core`（ID、符号化、鍵サービスのクライアント、DB の境界、監査ログ、ログの伏せ字）と `keysvc`（鍵サービス）を作りました。ほかのパッケージは、まだ空です。
- `spikes/`：M1 の捨てスパイクです。本実装に置き換えたら消します。詳しくは [spikes/README.md](spikes/README.md) を参照してください。
  - `spikes/passkey`：仮想認証器で、パスキーの登録とログインを通します（`npm run e2e` で動きます）。
  - `spikes/ciba-poll`：oidc-provider の CIBA を poll で1往復させます（`npm test` で動きます）。
- `test/leak/`：漏えいシナリオのテストの置き場所です。M2 で、テスト8（鍵サービスの能力の表、暗号の許可リスト、監査ログのチェーン）と、RLS の固定テストを足しました。書き方は [test/leak/README.md](test/leak/README.md) にあります。

[CLAUDE.md](CLAUDE.md) の「環境の注意」は、メンテナーが使う Claude Code のクラウド環境での注意です（例：その環境では `npx playwright install` を実行しない）。手元では、上の「前提」に従ってください。

## コントリビュート

指摘や提案を歓迎します。とくに歓迎するのは、**連絡先や属性で本人確認を突破できてしまう抜け道の指摘**です。

- 進め方は [CONTRIBUTING.md](CONTRIBUTING.md) を読んでください。
- このリポジトリを直接書き換えられるのはメンテナーだけです。それ以外の人は、フォークして PR を送り、メンテナーが確認してから取り込みます。
- 参加する人は [行動規範](CODE_OF_CONDUCT.md) を守ってください。

## セキュリティ

脆弱性は、公開のイシューや PR に書かないでください。報告の方法は [SECURITY.md](SECURITY.md) にあります。

## ライセンス

このリポジトリのコードと文書は、[MIT License](LICENSE) で公開しています。

- 商用利用、改変、再配布、フォークは自由です。
- 条件は、著作権表示とライセンス文を残すことだけです。
- 無保証です。利用によって生じた損害について、作者は責任を負いません。

Copyright (c) 2026 nori1234
