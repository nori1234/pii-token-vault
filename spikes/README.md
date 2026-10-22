# 捨てスパイク

M1 で、ライブラリが不変条件を守れるかを、本実装の前に確かめるための実験（plan 10章）。本番のコードではない。

## 一覧

| ディレクトリ | 確かめること | 動かし方 | 分かったこと | 置き換え先 |
|---|---|---|---|---|
| `passkey/` | CDP の仮想認証器で、パスキーの登録とログインを通す（Fastify と `@simplewebauthn`） | `npm run e2e`（サーバーは 4101 番。[passkey/README.md](passkey/README.md)） | [ADR 0007](../docs/adr/0007-webauthn-library-guards.md) | M3 の `packages/idp` |
| `ciba-poll/` | oidc-provider の CIBA を poll で1往復させる | `npm test`（単独では `npx vitest run spikes/ciba-poll`） | [ADR 0006](../docs/adr/0006-ciba-spike-findings.md) | M7 の `packages/idp` |

## 本番で使わない（DO NOT USE IN PRODUCTION）

ここのコードは捨てスパイクで、参照実装ではない。These are throwaway spikes: do not use them in production or copy them as reference code.

意図して省いた守り：

- 鍵は起動ごとに乱数で作り、メモリだけに置く。sub、窓口コードの索引、保存のキーは、再起動で変わる（本番は keysvc と KMS。plan 8章）。
- ciba-poll の approve と deny は、テストから呼ぶための関数で、利用者を認証しない（本番は、UV 付きのパスキーで要求に結び付けて承認する。M6、M7）。HTTP のルートにつながない。
- 窓口コードの発行では、UV 付きのパスキーを省いている。試行の上限とレート制限もない（M7）。
- 保存はメモリだけ。`dump()` は漏えいの確認のために、保存した内容をそのまま返す。
- passkey は http://localhost だけを想定する。セッション、レート制限、複数のパスキーはない（M3）。

## 決まり

- **不変条件は、すべて適用する**。捨てるコードでも、本物の連絡先を使わない、値をログに出さない、外へつながない、許可リストにない暗号を使わない。
- **本実装から import しない**。`packages/` から `spikes/` のコードを使わない。持ち込むのは、ADR に書いた方針だけ。
- **分かったことは文書に残す**。ADR か plan に書き、コードのコメントだけに残さない。
- **置き換えたら消す**。本実装とそのテストが入る PR で、ディレクトリごと消す。消したら `package-lock.json` を更新し、この表の行も消す。
- 依存は、各スパイクの `package.json` に、版を固定して書く。

## lint の違い

`biome.json` では、`spikes/` を次のように扱う。

- `node:crypto` の import を許す。`packages/warifu-core` と `packages/keysvc` を通さずに試すため。ただし、使ってよい方式は不変条件9の許可リストのままで、lint は方式までは確かめない。グローバルの `crypto`（Web Crypto）は、`packages/` と同じく禁止する。
- 外向きの通信のモジュール（`node:net`、`node:dns`、`node:http` の `request`、`node:child_process`、`undici` など）の import と、`fetch`、`globalThis` などのグローバルは、`packages/` と同じく禁止する。`node:http` は、サーバーを立てる `createServer` などだけを許す。
- テスト（`*.test.ts`、`*.e2e.ts`）は lint の対象外。テストからつなぐのは、テストか `playwright.config.ts` の webServer が立てたローカルのサーバー（127.0.0.1）だけにする。
- `public/` の中（ブラウザで動くコード）では、同じオリジンのサーバーを呼ぶために `fetch` などのグローバルを許す。
