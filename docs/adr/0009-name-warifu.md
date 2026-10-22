# ADR 0009：名前を「金庫」から「割符（Warifu）」に変える

- 状態：採用（2026-10-21 にオーナーが確認した）
- 日付：2026-10-21

## 状況

この基盤は「金庫（PII Token Vault）」と呼んでいた。この名前には、次の問題がある。

- 「安全にしまってある」と読まれやすい。DESIGN.md 4章と CLAUDE.md「主張の書き方」は「安全です」のような断定を避けるが、名前そのものが断定に近い印象を与える。
- お金や貴重品を連想させ、連絡先を本人確認に使わせないという目的が伝わらない。
- 英語の vault は、秘密の管理の製品（HashiCorp Vault など）や、企業向けのパスワード管理の製品と重なり、検索でも埋もれる。

## 決定

名前を「割符（わりふ、Warifu）」に変える。

- 割符は、1枚の札を2つに割って双方が持ち、突き合わせて相手を確かめる道具である。
- 次の2点が、この基盤の考え方と合う。
  - 割符が利用者を確かめる根拠は、利用者の手元にある片割れ（UV 付きのパスキーの秘密鍵。対になる公開鍵は割符が持つ）であって、連絡先や属性ではない（ADR 0001。回復は ADR 0003）。
  - 割る組は相手ごとに別にする。企業ごとに別の sub と別名を渡すこと（pairwise）に当たる。
- 候補だった「ハンコ」は採らない。持っていれば本人と見なされ、盗まれても複製されても通る道具で、原則と反対の象徴になるため。「合言葉」も、知識による本人確認（KBA）そのものなので採らない。

## 範囲

置き換えの対応は、npm のスコープを除いて、先に作った置き換えの案に合わせた（スコープは下の「変えないもの」）。

- 文書の表記：「金庫（PII Token Vault）」→「割符（Warifu）」、「金庫」→「割符」、「PII Token Vault」→「Warifu」。
  - 対象は、README、CLAUDE.md（不変条件の本文を含む。名前と、名前から作った識別子（`warifu-core`、`withWarifuUser`）だけを置き換えた）、DESIGN.md、docs/（plan、spec、standards、ADR 0001〜0008）、CONTRIBUTING.md、principle-review のスキル、test/leak/README.md、spikes/README.md、コードのコメント。
  - 以前の ADR の本文も置き換えた。製品の名前を変えただけで、判断の中身は変わらない。
  - DESIGN.md の固定の文言（1章の6のプッシュ通知の文言2つと、3章の警告文 B、D、E、G）も、名前だけを置き換えた。意味は変えていない。
- コードの識別子：
  - パッケージ：`packages/vault-core` → `packages/warifu-core`、パッケージ名 `@pii-token-vault/vault-core` → `@pii-token-vault/warifu-core`
  - DB の境界：`withVaultUser` → `withWarifuUser`
  - 中継のヘッダー：`X-Vault-Unauthenticated` → `X-Warifu-Unauthenticated`
  - テスト用の DB とロール：`vault_bootstrap`、`vault_template`、`vault_test_*` → `warifu_bootstrap`、`warifu_template`、`warifu_test_*`
  - 一時的なクラスタのディレクトリの接頭辞（`scripts/pg-up.ts`）：`vault-pg-` → `warifu-pg-`
  - 捨てスパイクの型と関数：`SpikeVault`、`SpikeVaultOptions`、`buildSpikeVault` → `SpikeWarifu`、`SpikeWarifuOptions`、`buildSpikeWarifu`
  - acr の URN は、すでに `urn:warifu:acr:*` を使っているので変えない。
- 変えないもの：
  - npm のパッケージのスコープは、旧名の `@pii-token-vault/*` のままにする。npm で組織 `warifu` を作れず、作れた組織 `pii-token-vault` に合わせた（オーナーが案 A を選んだ）。どのパッケージもまだ private で、npm に出すのは M9 の後。スコープの名前は動作に影響しない。
- コード上の名前（GitHub のリポジトリ `nori1234/pii-token-vault`、npm のスコープ `@pii-token-vault`、ルートのパッケージ名 `pii-token-vault`）は、`pii-token-vault` にそろえる（2026-10-21 にオーナーが決めた。リポジトリの名前は、一時 `warifu` に変えたあと、戻した）。

## 結果

- まだ接続している企業はない（PoC の段階）ので、ヘッダー名を変えても、影響を受ける企業はない。
- 製品の名前（割符）と、コード上の名前（`pii-token-vault`）が違う。README と CLAUDE.md の用語には、npm のパッケージ名だけを書いた。
- 公開の前の名前は「金庫（PII Token Vault）」だった。古い記録にその名前があれば、この ADR の前の名前として読む。

## 名前の確認（2026-10-21）

- 「割符」「Warifu」は、ほかでも使われている（検索による。2026-10-21）。秘密分散の製品（「電子割符」など）、同じたとえを使う別の OSS、npm のスコープ `@warifu`（このプロジェクトのものではない）、別の分野の商標。どれも、このプロジェクトとは関係がない。README にその旨を書いた。
- いまは名前を変えない。
- サービスとして提供する前に、J-PlatPat で 割符／ワリフ／WARIFU を、第9類・第38類・第42類・第45類で調べ、結果をこの ADR に追記する。
