# ADR 0014：署名の鍵を鍵サービスに置く（sign と public_keys）

- 状態：提案（オーナーの確認待ち。既定の案で実装した）
- 日付：2026-10-22

## 状況

ES256 の署名の鍵（ID トークン、SET、操作ごとの承認、テナントの JWT）は、plan 8章の能力の表になかった（plan 8章「能力の表にまだないもの」、spec 04 の2章の未定）。置き場所と、鍵サービスの操作にするかを M2 で決める必要があった。CAP-04 は「鍵は、鍵サービス（ローカル）か KMS（本番）の外に出さない」としている。

oidc-provider 9.12.2 には、`ExternalSigningKey`（`keyObject()` と `sign(data)` を持つクラス）と `features.externalSigningSupport`（実験的な機能 `experimental-01`）がある。`sign` の戻り値は、そのまま JWS の署名部になる（ES256 なら r‖s の64バイト。M2 の設計の段階で、ライブラリのソースで確かめた）。

## 決定

- ES256 の ID トークンの署名の鍵（`id_token`）を、鍵サービスの中で作り、`sign` と `public_keys` の2つの操作を足す。呼べるのは idp だけ（ADR 0013 の能力の表）。
  - `sign`：`{ keyId: 'id_token', message }` → `{ kid, signature }`。署名は JWS の形（ieee-p1363、64バイト）。入力は 8192 バイトまで。
  - `public_keys`：`{ keyId: 'id_token' }` → `{ keys: Es256PublicJwk[] }`。秘密鍵の項目は持たない。入れ替えの間は、有効な鍵をすべて返す。
- M3 で、oidc-provider の `ExternalSigningKey` を継いだクラスで、`sign` を鍵サービスに、公開鍵の座標を `public_keys` から返す（ADR 0018。`keyObject()` は node:crypto が要るので使わない）。実験的な機能に頼るので、oidc-provider の版を固定し、M3 のテストで署名の往復を確かめる。
- SET（M5）、操作ごとの承認（M7）、テナントの JWT（M5）の鍵は、同じ操作の keyId として、各マイルストーンで足す。DKIM と ARC の鍵（rsa-sha256）の置き場所は M4 で決める。→ 同じ操作の keyId `dkim`（RSA 2048）として鍵サービスに置いた（ADR 0021）。SET とテナントの JWT の鍵は、company-api の keyId `set` と `tenant_jwt`（ES256。用途ごとに別の鍵）として置いた（ADR 0022）。
- 入れ替え：新しい鍵を作り、古い公開鍵を、発行済みのトークンの期限まで `public_keys` に残す。

## 採らなかった案

- **idp が起動時にメモリの中で鍵を作る**：CAP-04（鍵を鍵サービスか KMS の外に出さない）の例外になる。idp の侵害で、署名の鍵そのものが取られる。
- **署名の鍵の置き場所を M3 まで決めない**：spec 04 が M2 で決めるとしていた。鍵サービスの操作と ACL の形を、M2 で一度に決めておく方が、表の食い違いが起きにくい。

## 結果

- t08-crypto-allowlist と t08-key-client-surface で、署名が64バイトで、公開鍵で検証できることを確かめる。
- M3 で、oidc-provider の実験的な機能が使えないと分かったら、idp が起動時にメモリの中で作る鍵に切り替える。その場合は CAP-04 の例外になるので、改めてオーナーに確認する。→ M3 で使えることを確かめた（ADR 0018。`test/leak/t04-pairwise` と `x-idp-oidc` で、鍵サービスが署名した ID トークンを `/oidc/jwks` の鍵で検証している）。鍵は oidc-provider を作るときに固定されるので、鍵を入れ替えたら idp を再起動する。

## オーナーの確認

- O-2：ES256 の ID トークンの署名の鍵を鍵サービスに置き、`sign` と `public_keys` を能力の表に足す。M3 で oidc-provider の実験的な機能に頼る。既定の案：置く。
