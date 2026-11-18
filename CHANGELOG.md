# rp-kit リリース情報

企業が自社の Node.js サーバーに組み込む `@pii-token-vault/rp-kit` の変更を記録します。割符のサービス本体の開発状況は [ロードマップ](README.md#いまの状態とロードマップ) にあります。

## 0.1.0（公開準備）

企業向け SDK と、自社の接続を手元で点検するための適合テストキットの初版です。Node.js 22.18 以上、ES Modules に対応します。PoC の検証にはテストデータを使ってください。

| 入口 | 初版で試せること |
|---|---|
| `@pii-token-vault/rp-kit` | 企業へのログイン、操作別承認・初回紐付けの検証、企業向け API とセキュリティイベント（SET）の処理。通信関数は企業が渡します。 |
| `@pii-token-vault/rp-kit/kit` | 模擬 OP を使い、企業自身のテスト環境でログイン、旧経路、初回紐付け、申告したルートを点検できます。 |

この版が公開済みかは次のコマンドで確認できます。`0.1.0` が返れば npm から取得できます。リポジトリから試す手順は [SDK の手引き](packages/rp-kit/README.md#手元で模擬-op-を試す) にあります。

```sh
npm view @pii-token-vault/rp-kit@0.1.0 version --registry=https://registry.npmjs.org
```
