# rp-kit リリース情報

企業が自社の Node.js サーバーに組み込む `@pii-token-vault/rp-kit` の変更を記録します。割符のサービス本体の開発状況は [ロードマップ](README.md#いまの状態とロードマップ) にあります。

## 0.1.1（公開準備）

コード、型定義、依存（`jose@6.2.14`）は 0.1.0 と同じです。変えたのは、パッケージに入れる README と、公開の方法です。

- README：模擬 OP を試す手順を、空のディレクトリで npm から入れる形にしました。版ごとの変更（このリリース情報）へのリンクを足しました。
- 公開の方法：npm のトークンを使わずに、GitHub Actions から trusted publishing（OIDC）でつなぎます。GitHub Actions は版を仮置き（staged publishing）するだけで、メンテナーが npm で2段階認証をして承認したときに公開されます。provenance は、これまでどおり付けます。

## 0.1.0（2026-11-18 公開）

企業向け SDK と、自社の接続を手元で点検するための適合テストキットの初版です。Node.js 22.18 以上、ES Modules に対応します。PoC の検証にはテストデータを使ってください。

| 入口 | 初版で試せること |
|---|---|
| `@pii-token-vault/rp-kit` | 企業へのログイン、操作別承認・初回紐付けの検証、企業向け API とセキュリティイベント（SET）の処理。通信関数は企業が渡します。 |
| `@pii-token-vault/rp-kit/kit` | 模擬 OP を使い、企業自身のテスト環境でログイン、旧経路、初回紐付け、申告したルートを点検できます。 |

- npm：[@pii-token-vault/rp-kit@0.1.0](https://www.npmjs.com/package/@pii-token-vault/rp-kit/v/0.1.0)
- 公開の記録：GitHub Actions のワークフロー「rp-kit を npm に公開」の[実行](https://github.com/nori1234/pii-token-vault/actions/runs/44322803745)（`main` のコミット `0c58f5a`）。provenance を付けて公開したので、npm の版別ページで、どのリポジトリのどのコミットから作ったかを確かめられます。

npm からは次のように入れます。模擬 OP で試す手順は [SDK の手引き](packages/rp-kit/README.md#手元で模擬-op-を試す) にあります。

```sh
npm install --ignore-scripts @pii-token-vault/rp-kit@0.1.0
```
