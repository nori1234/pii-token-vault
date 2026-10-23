# ADR 0017：ログは許可リストで伏せる

- 状態：採用
- 日付：2026-10-23

## 状況

不変条件4は、ログに値を文字列で埋め込まず、構造化したフィールドで渡し、伏せる対象（Cookie と Authorization のヘッダー、`req.url` のクエリ、リクエストの本文を含む）を warifu-core の1か所にまとめることを求めている。plan 9章では pino の redact を想定していたが、redact は「伏せるパスを並べる」方式で、新しいフィールドを足したときに漏れる。

## 決定

- **許可リスト方式**にする。伏せる対象を並べる方式は、新しい項目で必ず漏れる（ADR 0001 と同じ考え方）。規則は `packages/warifu-core/src/log/redact.ts` の1か所だけに置く。
- **フィールド**：載せてよい名前と、値の形を決める。
  - `event`、`op`、`target`、`purpose`、`keyId`、`reason`：識別子の形（小文字と区切りの48文字まで）
  - `service`：割符の部品の名前の列挙
  - `method`：HTTP のメソッドの列挙
  - `route`：ルートの型（例 `/v1/:op`）。`?`、`#`、`@`、`=` を含めない
  - `status`、`durationMs`、`count`：安全な整数
  - `errorName`、`errorCode`、`sqlstate`、`reqId`：それぞれの決まった形
  - 名前が一覧にないキーと、形の合わない値は落とし、落とした数だけを `dropped` に出す（キーの名前も出さない）。
- **特別なキー**：`req` は method とルートの型だけ（`req.url` を読まない）、`res` はステータスだけ、`err` は例外の名前とコードだけ（message、detail、stack、cause を出さない）、`responseTime` は整数に丸めた `durationMs`。
- **メッセージ**：固定の文の許可リスト（いまは Fastify 5 の `incoming request` と `request completed` だけ）に一致するものだけを出し、ほかは `[redacted]` にする。値を埋め込んだメッセージは一致しないので伏せられる（「値を文字列に埋め込まず」を実行時にも強制する）。
- 出力は1行の JSON。ログは例外を投げない。
- ロガーは Fastify 5 の `loggerInstance` に渡せる形（`info`、`error`、`debug`、`fatal`、`warn`、`trace`、`child`）にし、M3 で Fastify の既定のシリアライザに頼らずにつなぐ。依存は足さない（pino を使わない）。

## 採らなかった案

- **pino の redact**：否定リスト。新しいフィールドの名前を足したときに漏れる。
- **フィールドの名前だけの許可リスト**（値の形を見ない）：`op` などの名前に、誤って連絡先やトークンを入れたときに漏れる。

## 残るリスク

- 識別子の形をした値（例：別名のローカル部は小文字16文字）を、`op` などの許可したフィールドに入れると、形の検査を通ってしまう。許可したフィールドに動的な値を入れる変更は、principle-review の観点4で点検する。

## 結果

- warifu-core の単体テスト（`test/log.test.ts`）で、目印を入れたメール、トークン、Cookie、Authorization、クエリ付きの URL、本文、DETAIL 付きの pg のエラー、テンプレート文字列のメッセージが出力に出ないことと、Fastify 5 の `loggerInstance` として URL のクエリなどを出さないことを確かめる。
- 鍵サービスの出力に値が出ないことは、t08-keysvc-isolation で確かめる（テスト7の前倒しの一部）。
