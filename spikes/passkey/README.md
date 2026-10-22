# 捨てスパイク1：仮想認証器でパスキーを通す

M1 の捨てスパイク（plan 10章）。CDP の仮想認証器で、パスキーの登録とログインを通す最小の E2E。
M3 で `packages/idp` の本実装と、そのテストに置き換える。本実装から、ここのコードを import しない。

## 中身

- `server.ts`：Fastify 5 のサーバー。保存はメモリだけ。連絡先も氏名も聞かない。
- `public/index.html`、`public/app.js`：ボタン2つと、結果を出す欄（`role="status"`）だけのページ。
- `passkey.e2e.ts`：Playwright のテスト。各テストの先頭に、漏えいシナリオの形式で狙いを書いた。

## 動かし方

```
npm run e2e                      # リポジトリのルートで。webServer がサーバーを起動する
node spikes/passkey/server.ts    # 手で起動するとき。http://localhost:4101/ を開く
```

ポートは環境変数 `SPIKE_PASSKEY_PORT` で変えられる（既定は 4101）。サーバーは 127.0.0.1 で待ち受け、
Host が `localhost:<port>` でない要求は断る。RP ID は `localhost`、`expectedOrigin` はポート込みで固定している。

## 形にした不変条件

- user.name と displayName は乱数のラベル。ユーザーハンドルも乱数（不変条件1(d)）。
- 登録もログインも `userVerification: 'required'`。検証でも UV を必須にする（不変条件1(b)）。
- 発見可能な資格情報を必須にし、ログインでは `allowCredentials` を出さない。アカウントは資格情報 ID で引き、
  userHandle が持ち主と一致することを確かめる。見つからなければ、ほかの手がかりでは探さない。
- アルゴリズムは ES256 と RS256 だけ（不変条件9）。アテステーションは `none` だけを受け付ける（不変条件7）。
- ログは出さない。チャレンジは使い捨てで、儀式の ID に結び付ける。
- すべての応答に、Trusted Types を必須にした CSP、nosniff、no-referrer、no-store を付ける。

## 分かったこと（ADR と plan に書く材料）

- `@simplewebauthn/server` 14.0.3
  - `supportedAlgorithmIDs` の既定は EdDSA・ES256・RS256（PQC に対応した実行環境では ML-DSA-44 も）。
    `generateRegistrationOptions` と `verifyRegistrationResponse` の**両方**に `[-7, -257]` を渡す必要がある。
  - `verifyAuthenticationResponse` は、応答の資格情報 ID が渡した資格情報と同じかも、userHandle も確かめない。
    呼ぶ側で、ID で引いて userHandle を比べる。
  - 要求した attestation と、届いた fmt が合っているかは確かめない。x5c の検証では、証明書の CRL 配布点へ
    `fetch` する（`helpers/isCertRevoked.js`）。android-key では、送られたチェーンの末尾を信頼の起点にして
    経路を組み、そのあとで Google のルートかどうかを確かめるので、送り手が決めた URL へつながりうる
    （コードを読んで確かめた。再現はしていない）。そのため、検証に渡す前に fmt が `none` であることを確かめる。
  - エラーのメッセージには、チャレンジやオリジンの値が入る。ログにも応答にも出さない。
- `@simplewebauthn/browser` 14.0.0
  - `esm/` は21個のファイルに分かれる。ここでは、グローバルの `SimpleWebAuthnBrowser` を定義する UMD 版
    （`dist/bundle/index.umd.min.js`、1ファイル）を `/vendor/simplewebauthn-browser.js` で配った。
    `exports` に `dist/` がないので、`import.meta.resolve` で入口を引き、相対で求めた。
  - Trusted Types を必須にした CSP（`trusted-types 'none'`）の下で、違反なく動く。
- Chromium 141（revision 1194）の仮想認証器
  - `attestation: 'none'` では fmt は `none` になるが、AAGUID は 0 にならない（`01020304-0506-0708-0102-030405060708`）。
  - ES256 と RS256 を出すと ES256 を選ぶ。EdDSA と RS256 だけを出しても作れる。
  - フラグは UP・UV が立ち、BE・BS は立たない（`defaultBackupEligibility` と `defaultBackupState` の既定）。
    カウンターは登録で 1、最初のログインで 2。`credProps.rk` は true。
  - `setUserVerified` を false にすると、ブラウザが NotAllowedError で止め、サーバーには何も届かない。
    サーバー側の UV の検査は、`setResponseOverrideBits` の `isBadUV` で確かめられる（署名は正しいまま UV が 0 になる）。
  - `addCredential` で、任意の鍵と userHandle を持つ資格情報を入れられる。漏えいシナリオのテストに使える。

## 範囲の外

セッション、OIDC、step-up、複数のパスキー、パスキーの削除、BE/BS の変化の扱い、レート制限は作らない（M3）。
