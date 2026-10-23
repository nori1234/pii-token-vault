# ADR 0015：DB の境界：ロール、スキーマ、ポリシー、SQL の書き方、マイグレーション

- 状態：提案（オーナーの確認待ち。下の「オーナーの確認」の既定の案で実装した）
- 日付：2026-10-23

## 状況

不変条件8は、アプリのコードが `withTenant` か `withWarifuUser` を通してだけ DB に触れること、全テーブルに RLS の ENABLE と FORCE を付けること、サービスごとにスキーマとログインロールを分けて列単位で GRANT すること、例外を5つに限ることを決めている。M2 では、その実装の形と、spec 03 の TH-35（クエリの書き方の規則）、spec 04 の3章の未定（暗号化した本物のメールと監査ログのスキーマ）を決める必要があった。

## 決定

### ロールとスキーマ

| ロール | LOGIN | 属性 | 役割 |
|---|---|---|---|
| `warifu_bootstrap` | ○ | SUPERUSER（initdb） | マイグレーションと、テスト用の DB の作成だけ（不変条件8の例外）。アプリは使わない |
| `warifu_owner` | — | NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT | 全スキーマ・全テーブル・全関数の所有者。アプリのロールに何も所有させない（所有者はポリシーを変えられ、FORCE を外せるため） |
| `warifu_alias_resolver` | — | 同上 | `relay.resolve_alias` の所有者（例外の SECURITY DEFINER 関数） |
| `warifu_idp`、`warifu_relay`、`warifu_company_api` | ○ | 同上。`search_path` は空、`statement_timeout` 5s、`lock_timeout` 3s、`idle_in_transaction_session_timeout` 10s | サービスごとのログインロール |

| スキーマ | 中身 | 使うロール |
|---|---|---|
| `warifu` | 境界の関数（`current_tenant_id()`、`current_user_id()`、`has_boundary()`、`service_of()`） | アプリのロール（USAGE と EXECUTE だけ） |
| `warifu_meta` | マイグレーションの記録 | なし（ブートストラップだけ） |
| `audit` | 監査ログ（ADR 0016） | アプリのロール |
| `aliases` | 別名の世代 | idp、company-api、`warifu_alias_resolver` |
| `idp`、`relay`、`company_api` | 各サービスの表（M3 以降）。`relay` には解決関数 | それぞれのサービスだけ |
| `contacts` | 暗号化した本物のメール（M3 で作る。下） | idp、relay |
| `public` | 使わない。PUBLIC の権限をすべて外す | — |

- sender のロールとスキーマは M5 で決める。鍵サービスは DB を使わない（ADR 0013）。BI ツールなどのロールは作らない（CAP-18）。
- `CREATE DATABASE … TEMPLATE` は DB の ACL を写さないので、マイグレーションとは別に、DB ごとに `REVOKE ALL ON DATABASE … FROM PUBLIC` と、アプリのロールへの `CONNECT` だけをかける（PUBLIC の TEMP を外し、一時テーブルや `pg_temp` の関数で名前を乗っ取らせない）。
- テナント ID と利用者 ID は、小文字の UUID にする。表示用のテナントの名前は M5 の登録簿で持つ。

### ポリシーと GRANT（M2 の分）

- 全テーブルに ENABLE と FORCE。ポリシーは、ロールを名指しする（PUBLIC 向けのポリシーを作らない）。
- 境界の値が未設定か空文字なら、`current_tenant_id()` と `current_user_id()` は NULL になり、どのポリシーにも一致しない（閉じる側に倒す）。
- 列単位の SELECT と INSERT だけを GRANT する。UPDATE、DELETE、TRUNCATE、REFERENCES、TRIGGER は M2 の表では誰にも与えない。
- `USING (true)` のポリシーは、解決関数の所有者の `resolver_select` だけ。
- 一覧は x-rls-fixed の期待の一覧を正とする。表、ポリシー、GRANT を足すときは、同じ PR でその一覧を直す。

### 別名の世代と、解決関数（spec 04 の「M3 で決める」を前倒しした）

- `aliases.generation(tenant_id, user_id, generation, lookup_mac, created_at)`。別名そのものは置かず、鍵サービスの `mac(alias_lookup)` の出力だけを置き、一意制約をかける（二度と割り当てない。不変条件5）。
- 世代は足すだけ。最新でない世代を廃番とする。UPDATE と DELETE は誰にも与えない。
- idp は第1世代だけを、company-api は自分のテナントの第2世代以降だけを書ける（M3・M5 で見直してよい）。アプリのロールは `lookup_mac` を書けるが読めない。
- `relay.resolve_alias(bytea)` は、最新の世代だけを `(user_id, tenant_id)` で返す。廃番、存在しない、長さが違う、NULL は、どれも同じ0行。所有者は `warifu_alias_resolver`、`search_path` は `pg_catalog, pg_temp` に固定、EXECUTE は `warifu_relay` だけ。relay の表を直接読む権限は与えない。

### 暗号化した本物のメールの置き場所（表は M3 で作る）

- `contacts.email(user_id uuid PRIMARY KEY, ciphertext bytea NOT NULL, updated_at timestamptz NOT NULL)`。M3 で、一意性の検査（不変条件1(e)）のための照合用の HMAC の列と合わせて作る。
- idp（`withWarifuUser`）：`INSERT (user_id, ciphertext, updated_at)`、`UPDATE (ciphertext, updated_at)`、`SELECT (user_id, updated_at)`。暗号文の列は読ませない（復号できないので要らない）。
- relay（`withWarifuUser`。解決関数で利用者 ID を得た後）：`SELECT (user_id, ciphertext)`。
- ポリシーはどちらも `user_id = warifu.current_user_id()`。暗号文は `{ field: 'email', user_id }` の文脈に結び付く（ADR 0013）ので、行を入れ替えられても別人のアドレスには届かない。

### 境界の実装（`withTenant` と `withWarifuUser`）

1. すでに境界の中なら `nested_boundary`（境界を入れ子にしない）。
2. プールから接続を取る。その接続で初めてなら、期待したロールで、スーパーユーザーでも BYPASSRLS でもないことを確かめる。違えば `unsafe_role` で、接続を捨てる。
3. `BEGIN ISOLATION LEVEL READ COMMITTED`。
4. `set_config('warifu.tenant_id', …, true)` と `set_config('warifu.user_id', …, true)`。使わない方は空文字。
5. fn を実行する。fn が終わったら tx を閉じる（以後は `tx_closed`）。
6. 境界の値とロールが 4 のままかを読み直す。違えば `boundary_tampered` で ROLLBACK。
7. COMMIT。どこで失敗しても ROLLBACK。ROLLBACK も失敗したら、接続を捨てる。
8. pg の例外は、SQLSTATE と制約の名前だけの `DbError` にし、本文、DETAIL、HINT を捨てる（入力の値が入るため。不変条件4）。

warifu-core は、プールも pg のクライアントも外に出さない。`pg` を import するのは `packages/warifu-core/src/db/` だけにする（x-db-boundary で固定する）。

### SQL の書き方（TH-35）

1. アプリのコードは `tx.query(sql\`…\`)` などだけを使う。`sql` タグが作ったもの（WeakSet に登録）だけを受け付ける。
2. `${}` はすべてパラメータ（`$1`…）。識別子や SQL の断片は埋め込めない。可変長の一覧は `= ANY(${array})`。動的な形が要るときは、別の静的な SQL を書く。
3. すべて拡張プロトコル（`queryMode: 'extended'`）で送る。Postgres は1つの文だけを受け付ける。
4. `sql` タグは、先頭の語が SELECT、INSERT、UPDATE、DELETE、WITH のどれかで、静的な部分に `;`、`"`、ドル記号の引用、`U&`、`--`、`/*`、`set_config`、`current_setting`、`warifu.tenant_id`、`warifu.user_id` を含まないことを確かめる。違えば DB に送らない。
5. 名前はすべてスキーマで修飾する（アプリのロールの `search_path` は空）。

この検査は開発者の誤りを止めるためのもの。攻撃者の入力は値としてしか届かない。

### マイグレーション

- `packages/warifu-core/migrations/NNNN_<名前>.sql` を、`scripts/migrate.ts` がブートストラップのロールで流す。未適用のものを番号の順に、全体で1つのトランザクションとアドバイザリロックで流し、`warifu_meta.migrations` に記録する。トランザクションを操作する文を含むファイルは流さない。
- マージした後のファイルは書き換えず、変更は新しいファイルにする。チェックサムは取らない（SHA-256 は不変条件9の許可リストにない）。
- runner はアプリのコードに入れない（サービスのプロセスにマイグレーションの経路を持たせない）。`npm run migrate` で、`npm run pg-up` が表示した接続先に流す。

### ローカルの DB の資格情報

ローカルでは、ログインロールに資格情報を付けない（`scripts/pg-up.ts` の trust 認証と、0700 のソケットのディレクトリのまま）。ロールの分離は、資格情報ではなく権限で確かめる。SCRAM にしないのは、SCRAM-SHA-256 と PBKDF2 が不変条件9の許可リストにないため（本番の DB の認証、SCRAM と TLS をプロトコルで決まる例外に加えるかは、P1 で決める）。

## 採らなかった案

- **`set_config` の実行権限をアプリのロールから外す**：境界を渡すのに `set_config(…, …, true)` が要る。外すと SECURITY DEFINER の関数が要り、不変条件8の新しい例外になる。
- **マイグレーションの道具（node-pg-migrate など）**：依存が増える。必要なのは、1つのトランザクションで順に流すことだけ。
- **別名の世代の廃番を `retired_at` の UPDATE で表す**：UPDATE の権限が要る。最新でない世代を廃番とすれば、追記だけで済む。
- **検証のためにブートストラップのロールで DB を読む**：不変条件8の例外にない。テストは、境界の中か、アプリのロールの生の接続で読む。

## 残るリスク

- 同じトランザクションで SQL を書ける者（`sql` タグを使わずに書けるコードを足した者を含む）は、境界の値を書き換えられる（例：`U&"set_\0063onfig"`）。書き換えたまま終われば、6の読み直しで `boundary_tampered` になる。途中の文には効く。
- 盗んだログインロールの接続は、そのロールの権限の範囲で、境界の値を自分で設定できる（x-db-boundary で確かめている）。列単位の GRANT（例：`lookup_mac` を読めない）と、解決関数を relay だけにすることで、範囲を狭めている。
- 一意制約と外部キーの検査は RLS を越えるので、別のテナントの値と一致するかどうかが、エラーで分かりうる（例：`lookup_mac` の一意制約）。照合用の HMAC は鍵サービスの鍵がないと作れないので、M2 の表では実害は小さい。新しい一意制約を足すときは、この点を点検する。

## 結果

- RLS の固定テスト（x-rls-fixed）：全テーブルの ENABLE と FORCE、ログインロールとスーパーユーザーの一覧、アプリのロールの属性と設定、所属と所有者、ポリシーと列単位の GRANT の完全な一覧、SECURITY DEFINER が1つだけであること、関数とスキーマと DB の権限。
- x-db-boundary：テナントと利用者の境界、境界なしの生の接続、境界の値を自分で設定した接続、権限の昇格、`sql` タグ、UUID でない ID、入れ子と閉じた tx、接続の使い回し、エラーに値を入れないこと、`pg` を直接使わないこと。
- x-relay-resolver：解決関数の戻り値、廃番と存在しない入力の区別のなさ、relay 以外から呼べないこと、世代の書き換えと再利用ができないこと、導出から解決までの往復。

## オーナーの確認

- O-3：別名の世代の表と、その権限を M2 で作る（spec 04 は M3 で決めるとしていた）。既定の案：作る。解決関数が読む表と、RLS の固定テストに、テナントと利用者の両方の境界の表が要るため。
- O-6：ローカルでは、DB のログインロールに資格情報を付けない。既定の案：そのとおりにする。
- O-8：テナント ID を UUID にする（スパイクは `tenant-a` のような文字列だった）。既定の案：UUID にする。
