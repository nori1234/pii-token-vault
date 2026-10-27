# ADR 0007：パスキーの検証で、ライブラリの手前に置く検査

- 状態：採用
- 日付：2026-10-17

## 状況

M1 の捨てスパイク1（`spikes/passkey`）で、`@simplewebauthn/server` 14.0.3 を CDP の仮想認証器と組み合わせて動かし、ライブラリのソースを読んだ。その結果、ライブラリの既定のままでは、不変条件のいくつかを満たせないことが分かった。

- **外向きの通信（不変条件7）**：要求した attestation と、届いた応答の fmt が合っているかを確かめない。x5c の証明書チェーンを検証するときは、証明書の CRL 配布点へ `fetch` する（`helpers/isCertRevoked.js`）。android-key の検証では、送られてきたチェーンの末尾を信頼の起点にして経路を組み、そのあとで Google のルートかどうかを確かめる。そのため、送り手が決めた URL へつながりうる（ソースを読んで確かめた。再現はしていない）。`MetadataService` は、初期化すると `mds.fidoalliance.org` へ取りに行く。
- **暗号の許可リスト（不変条件9）**：`supportedAlgorithmIDs` の既定は EdDSA・ES256・RS256 で、PQC に対応した実行環境では ML-DSA-44 も加わる。登録の選択肢と検証の両方に、同じ既定が使われる。
- **本人の特定（不変条件1(b)）**：`verifyAuthenticationResponse` は、応答の資格情報 ID が渡した資格情報と同じかどうかを確かめない。userHandle も確かめない（WebAuthn L3 7.2 の手順6）。
- **平文を残さない（不変条件4）**：エラーのメッセージに、チャレンジやオリジンの値が入る。

## 決定

idp（M3）では、`@simplewebauthn/server` を呼ぶ前と後に、次の検査を自前で置く。

1. **attestation は受け取らない**
   - 登録の選択肢では `attestationType: 'none'` を求める。
   - 応答の attestationObject を先に読み、fmt が `none` で、attStmt が空でなければ、ライブラリに渡さずに拒否する。
   - `MetadataService` は使わない。
2. **アルゴリズムは ES256 と RS256 だけ**：`[-7, -257]` を、`generateRegistrationOptions` と `verifyRegistrationResponse` の両方に渡す。片方だけに渡すことを、テストで検出する。
   - 2026-10-23 に、EdDSA（-8。曲線は Ed25519）を足した（ADR 0012 の決定10）。渡す値は、ES256、EdDSA、RS256 の順で `[-7, -8, -257]` になる。
3. **アカウントは資格情報 ID だけで引く**：ログインでは `allowCredentials` を出さず、応答の資格情報 ID で保存済みの資格情報を引く。そのうえで、userHandle が持ち主と一致することを確かめる。見つからなければ、ほかの手がかりでは探さない。
4. **UV はサーバーで確かめる**：ブラウザが止める場合もあるが、それに頼らない。`requireUserVerification: true` を渡し、結果の `userVerified` も確かめる。
5. **理由を外に出さない**：ライブラリの例外は、応答にもログにも載せない。応答は、失敗の種類によらず同じ形にする。
6. **AAGUID は保存しない**：attestation が `none` でも、認証器の型番を示す AAGUID は届く（仮想認証器でも 0 にならない）。P0 では使い道がないので保存しない。使うときは ADR で決める。BE と BS のフラグは、plan 4章のとおり記録する。
7. **外への通信を二重に塞ぐ**：
   - idp のテストでは `globalThis.fetch` を、呼ばれたら失敗する関数に差し替える。ライブラリの更新で新しい外向きの呼び出しが入っても、テストで気付けるようにする。
   - 本番では、idp のコンテナから外へ出る経路を、ネットワークの設定で塞ぐ。外へ出られるのは sender だけにする。

## 採らなかった案

- **attestation を受け取り、証明書を検証する**：認証器の型番による制限は、P0 では要件にない。証明書の失効を確かめるには外への通信が要るので、不変条件7と衝突する。
- **ライブラリを使わず自作する**：CBOR、COSE、署名の検証を自前で持つことになり、誤りが入る余地のほうが大きい。手前に検査を置けば足りる。

## 結果

- 1〜5を、M3 で `test/leak/x-webauthn-guards.test.ts` にした（ADR 0018）。ブラウザの仮想認証器の代わりに、テストの中のソフトウェアの認証器（`test/setup/soft-authenticator.ts`）で、x5c 付きの packed、Ed25519 の鍵、UV が 0 の応答、持ち主と違う userHandle を作る。4（UV）は、E2E（`test/leak/x-idp-browser.e2e.ts`）でも CDP の仮想認証器で確かめる。捨てスパイク1（`spikes/passkey`）は消した。
- 3 の実装：userHandle は利用者 ID の16バイトにし、その利用者の範囲（withWarifuUser）の中で資格情報 ID が一致するものだけを使う（ADR 0018）。資格情報 ID で引き、userHandle が持ち主と一致することを確かめるのと、結果は同じになる。
- ライブラリを更新するときは、`fetch` の呼び出しが増えていないかを点検する（`grep -rn "fetch(" node_modules/@simplewebauthn/server/esm`）。
