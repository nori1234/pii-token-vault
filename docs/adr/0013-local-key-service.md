# ADR 0013：鍵サービス（ローカル）の形：Unix ドメインソケット、サービスごとの資格情報、操作と対象ごとの ACL

- 状態：提案（オーナーの確認待ち。下の「オーナーの確認」の既定の案で実装した）
- 日付：2026-10-22

## 状況

plan 8章は、鍵サービス（`packages/keysvc`）を別プロセスで立て、サービスごとの資格情報と操作ごとの ACL で KMS の IAM を模すとしている。M2 では、次のことを決める必要があった（plan 2章「内部の API」「鍵と資格情報の入れ替え」、8章「サービスの資格情報」、spec 04 の2章の未定）。

- 鍵サービスへの通信路と、内部の接続の認証
- MAC の鍵の割り当て（どの値を、どの鍵で MAC にするか）
- エンベロープ暗号での分担（AES-256-GCM を warifu-core で行うか、鍵サービスで行うか）
- ローカルでのサービスの資格情報の渡し方（CAP-06）
- 保存用の鍵、照合用の HMAC 鍵、サービスの資格情報の、失効と入れ替えの手順（CAP-07）

## 決定

### 通信路と起動

- 鍵サービスは、`<socketDir>/keysvc.sock` の **Unix ドメインソケットだけ**で HTTP/1.1 を待ち受ける。TCP と UDP は開かない。ソケットは 0600、ディレクトリは 0700 で、持ち主は起動した利用者にする。
- 設定は、**標準入力の1行目**の JSON で受け取る（`{ version, socketDir, credentials: { idp, relay, company-api } }`）。環境変数、コマンドラインの引数、ファイルには置かない（`/proc/<pid>/environ` や `ps` から読めるため）。親の環境変数は引き継がない（`env: {}` で起動する）。
- 設定の `credentials` のキーは、ちょうど `idp`、`relay`、`company-api` の3つにする。知らないキー（`sender` など）、足りないキー、配列は拒否し、3つの値はどれも違うものにする。これで、不変条件3の「decrypt の ACL を持つ資格情報は relay の1つだけ」を、設定の形として強制する。違えば終了コード 2 で終わり、ソケットを作らない。
- 標準入力の EOF、SIGTERM、SIGINT で止まる。起動した側が終わるとパイプが閉じるので、孤児にならない。
- 鍵サービスは DB を使わない。外向きの通信もしない。

### 認証と能力の表

- 認証は、サービスごとに1つの bearer の資格情報（`Authorization: Bearer <service>.<32バイトの base64url>`）。定数時間で比べ、形が違うときもダミーと比べてから失敗にする。要求の署名、時刻、nonce は付けない（「採らなかった案」）。
- ACL は「サービス × 操作 × 対象（鍵か用途）」の1つの表にし、`packages/keysvc/src/acl.ts` の1か所だけに書く。

| 操作（対象） | idp | company-api | relay | 使い始める |
|---|---|---|---|---|
| encrypt（contact） | ○ | — | — | M3 |
| encrypt（relay_queue） | — | — | ○ | M4 |
| decrypt（contact、relay_queue） | — | — | ○ | M4 |
| mac（alias_lookup） | ○ | ○ | ○ | M3〜M5 |
| mac（audit_chain） | ○ | ○ | ○ | M2 |
| mac（pairwise_sub、oidc_storage_id、email_verify_code） | ○ | — | — | M3（ADR 0018） |
| derive_alias（alias_derive） | ○ | ○ | — | M3・M5 |
| sign（id_token）、public_keys（id_token） | ○ | — | — | M3（ADR 0014） |

- sender、rp-kit、demo-rp には資格情報を作らない。
- **MAC の鍵は用途ごとに独立**にする。KMS は入力の中身で ACL をかけられないので、用途ごとの鍵と ACL にしておけば、本番でも KMS の鍵ごとのポリシーに写せる。M2 で作った用途は `alias_lookup` と `audit_chain`。M3 で、idp だけの用途として `pairwise_sub`（sub の導出。操作ではなく用途にした）、`oidc_storage_id`（idp の保存の鍵）、`email_verify_code`（宛先確認のコード）を足した（ADR 0018）。今後の見込みは、`message_id`・`dkim_replay`・`reply_address`（M4。→ `relay_replay`、`relay_thread`、`message_id` の名前で足した。ADR 0021）、`desk_code`（M7）、`recovery_code`・`invite_code`（M8）。用途を足すときは、`MacPurpose` の型、`acl.ts`、各クライアントの型、t08-keysvc-acl と t08-key-client-surface の期待の表を同じ PR で直す。
- 別名を導く鍵（`alias_derive`）は、どの MAC の用途の鍵とも別にする（CAP-05、ADR 0005）。

### 検査の順番とエラー

1. メソッドが POST で、パスが `/v1/<小文字と _ の32文字まで>` → 違えば 404
2. 本文を 16 KiB まで読む → 超えれば 413
3. 資格情報 → **403**
4. (サービス, 操作) が表にある（本文を解析する前。未知の操作もここで落ちる）→ **403**
5. JSON として解析する → 400 `invalid_request`
6. (サービス, 操作, 対象) が表にある（未知の鍵や用途もここで落ちる）→ **403**
7. 残りの項目の検査 → 400 `invalid_request`
8. 実行。復号の失敗 → 400 `decrypt_failed`（relay にだけ届く）

403 の本文とヘッダーは、理由によらずバイト単位で同じにする（`Date` も付けない）。入力の値は、応答にもログにも入れない。ログは要求ごとに1行で、403 は `keysvc.denied`（plan 2章の検知の対象「鍵サービスの 403」）にする。

### 暗号

- **エンベロープにせず、鍵サービスの中で直接 AES-256-GCM にかける**（KMS の Encrypt と同じ形。4KB まで）。AES-GCM の処理は鍵サービスの中だけになり、データ鍵を各サービスに渡さない。
- 暗号文の形：`0x01`（形式の版）‖ 鍵の番号（1バイト。contact=1、relay_queue=2）‖ 鍵の版（u32 BE）‖ IV（12）‖ 暗号文 ‖ タグ（16）。IV は毎回乱数で作り、呼び出し側は渡せない。タグは16バイトだけを受け付ける。
- **暗号文は文脈（AAD）に結び付ける**（KMS の EncryptionContext に当たる）。`contact` の文脈は `{ field: 'email', user_id }`、`relay_queue` は `{ queue_item_id }`。AAD は「頭の6バイト ‖ キーで並べた [キー, 値, …] を長さ付きで連結したもの」。DB の行を入れ替えても、別の利用者の文脈では復号できない（spec 03 の TH-67）。
- `derive_alias`：`toBase32Lower(HMAC(k_alias, lp('warifu/alias/v1', テナント ID の16バイト, 利用者 ID の16バイト, 世代の u32 BE)) の先頭10バイト)`。16文字、80ビット（ADR 0005 の下限）。
- `node:crypto` を import するのは2つのファイルだけにする：鍵を使う処理のすべては `packages/keysvc/src/crypto.ts`、乱数と定数時間の比較だけは `packages/warifu-core/src/random.ts`。warifu-core には、復号の処理を置かない。

### クライアントと lint の例外

- warifu-core に、サービスごとのクライアント（`keys/idp`、`keys/company-api`、`keys/relay`）を置く。許した操作のメソッドだけを持つ凍結したオブジェクトにする（不変条件3）。汎用の呼び出し（`keys/transport.ts`）と UDS のクライアント（`internal/uds-client.ts`）は exports に載せない。
- `packages/warifu-core/src/internal/uds-client.ts` の1ファイルだけ、`node:http` の `request` を許す（`biome.json` の overrides。warifu-core と keysvc の override より後ろに置き、ルートの禁止の一覧をすべて写す）。理由：
  1. 不変条件7が塞ぐのは外部への接続で、割符の内部の接続（サービスから keysvc や DB へ）は当たらない（spec 04 4章）。DB への接続（pg）も、ライブラリの中で `node:net` を使っている。
  2. Unix ドメインソケットは、ファイルシステムの上のものにしかつながらない。IP も DNS も通らない。
  3. 例外は1ファイル、1つの名前だけ。`node:net`、`node:crypto`、名前空間の import、`fetch` は、このファイルでも禁止のまま。
  4. このファイルはソケットのパスしか受け取らず、`request` にホスト名やポートを渡す口がない。パスは起動時の設定から来る。名前は閉じた一覧（いまは `keysvc.sock` だけ）にあり、持ち主とディレクトリの権限も確かめる。
  5. t08-key-client-surface が、ファイルの中身、`request` を import するファイル、override の範囲と順番を固定する。
  6. relay の内部配送 API（M4）と sender（M5）も、このファイルの名前の一覧に足して呼ぶ。例外は増やさない。

### 鍵と資格情報（ローカル）

- **鍵**は、鍵サービスが起動のたびに中で作り、メモリの中だけに置く。ファイル、DB、ログ、応答のどれにも書かない。鍵を返す操作はない。そのため、鍵サービスを起動し直すと、前の暗号文と MAC は使えなくなる（ローカルの DB も一時的なクラスタなので、組み合わせとして成り立つ）。
- **サービスの資格情報**は、起動する側（`scripts/keysvc-up.ts`。M3 以降の開発用の起動スクリプトも）が実行のたびに乱数で作り、鍵サービスとそのサービスにメモリで渡す。
- テストで既知の値が要るのは、公開の試験ベクタ（RFC 4231 の HMAC、GCM の仕様の Test Case 16）だけ。鍵や資格情報の固定値をテストに書かない。
- ローカルの分離は、コードの経路を確かめるためのもので、同じ OS 利用者の侵害への隔離ではない。

### 入れ替え（手順。周期は P1）

| 対象 | 形式での備え | 漏えいが疑われるときの手順 |
|---|---|---|
| 保存用の鍵（contact、relay_queue） | 暗号文に鍵の版を持ち、復号は版で鍵を選ぶ | 新しい版で暗号化し、古い版の暗号文は relay の中で復号して書き直す（復号できるのは relay だけ。実装は P1）。本番は KMS の自動の入れ替え |
| 照合用の HMAC 鍵（用途ごと） | 用途ごとに独立 | 用途ごとに作り直す。`alias_lookup` は `derive_alias` から全世代の索引を作り直す（手順は M5 → 本番の運用の手順として P1 に移した。ADR 0022）。`audit_chain` は新しい鍵で新しい区間を始める（区間の記録は P1）。`pairwise_sub` は入れ替えない（全企業の sub が変わるため。付け替えのイベントと合わせて P1。ADR 0018）。`oidc_storage_id` と `email_verify_code` は、入れ替えると保存中のセッションと確認中のコードが無効になるだけ |
| 署名の鍵（id_token） | `kid` を持ち、`public_keys` は有効な鍵をすべて返す | ADR 0014 |
| サービスの資格情報 | サービスごとに1つ | 新しい資格情報で鍵サービスとそのサービスを起動し直す。新旧を重ねない（decrypt の資格情報を常に1つにするため。入れ替えの間は短く止まる） |
| 別名の導出鍵 | — | P1（ADR 0005） |

定期的な入れ替えの周期は、P0 では定めない（漏えいが疑われるときだけ入れ替える）。

### 本番（P1）への対応

| 鍵サービス | KMS |
|---|---|
| encrypt、decrypt（文脈つき） | Encrypt、Decrypt（EncryptionContext） |
| mac、derive_alias | GenerateMac（HMAC_256。用途ごとの鍵） |
| sign、public_keys | Sign（ECC_NIST_P256、ECDSA_SHA_256）、GetPublicKey |
| bearer と ACL | サービスごとの IAM ロールとキーポリシー、VPC エンドポイントのポリシー |

## 採らなかった案

- **要求の HMAC 署名、時刻、nonce、応答の署名**：ソケットは 0700 のディレクトリの中にあり、通信を盗み見られる者は、同じ OS 利用者としてプロセスのメモリも読める。署名は、その者に対して守りを足さない。本番は KMS の SigV4 と TLS に置き換わる。
- **サービスごとのソケット**：同じ OS 利用者の中では区別にならない。区別は資格情報で行い、本番ではネットワークの組の制限（CAP-27）で行う。
- **エンベロープ暗号を warifu-core で行う**：AES-GCM の処理が全サービスに入り、idp がデータ鍵を一時的に持つ。連絡先は 4KB に収まるので、直接の形で足りる。配送キューが 4KB を超えるなら、M4 で relay だけにデータ鍵の操作を足すかを決める。→ M4 では、受け取ったメールを DB に置かずにメモリで処理することにしたので、データ鍵の操作は足さない（ADR 0021）。
- **照合用の鍵1本と種類の引数**：KMS の鍵ポリシーに写せず、company-api が任意の種類の MAC を作れる。
- **1つの鍵から用途ごとの鍵を導く（HKDF など）**：不変条件9の許可リストにない。
- **`node:net` の `connect({ path })` と自前の枠組み**、**子プロセスの IPC**、**`worker_threads`**、**`fetch` の UDS の指定**、**TCP（127.0.0.1）で待ち受ける**、**sender を経由する**：例外の範囲が広がる、別プロセスにならない、同じホストのほかのプロセスや SSRF の踏み台から届く、sender に鍵の操作の経路ができる、のどれかに当たる。

## 結果

- テスト8：t08-keysvc-acl（全組み合わせ、表にない操作と対象、sender）、t08-keysvc-auth（なりすまし、壊れた資格情報、403 の一律、資格情報を増やす設定での起動の拒否、ゆるいディレクトリ）、t08-keysvc-isolation（TCP と UDP で待ち受けない、権限、出力に値が出ない。CAP-38 の鍵サービスの確かめ方）、t08-ciphertext-binding（文脈への結び付き、書き換え、別の鍵）、t08-crypto-allowlist、t08-key-client-surface。
- テストの間は、globalSetup が鍵サービスを1つ起動する。出力や起動を調べるテストだけ、ファイルの中で自分の鍵サービスを起動する。
- 残るリスク：鍵サービスのプロセスのメモリを読める者（同じ OS 利用者、root）は、鍵と資格情報を読める。ローカルではこれを防がない（本番は KMS）。

## オーナーの確認

- O-1：lint の例外を1つ足す（`uds-client.ts` の1ファイルで `node:http` の `request`）。既定の案：足す。
- O-5：定期的な入れ替えの周期。既定の案：手順は M2 で決め（上の表）、周期は P1。
- O-6：ローカルでは、鍵サービスの鍵を起動のたびに作り直す（DB を残して開発すると、前の暗号文が読めない）。既定の案：そのとおりにする。
