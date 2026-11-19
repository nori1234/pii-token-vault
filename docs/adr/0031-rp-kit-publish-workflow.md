# ADR 0031：rp-kit の npm への公開を、GitHub Actions のワークフローで行う

- 状態：決定（2026-11-18 に、オーナーが GitHub Actions で公開する案を選んだ。細目は、この PR のレビューで確かめる）。O-118 は、2026-11-19 の追記のとおり、trusted publishing と staged publishing に切り替えた
- 日付：2026-11-18

## 状況

rp-kit（`@pii-token-vault/rp-kit`）は、M9 の後に npm に公開すると決めていた（plan 10章「公開の順番」。公開の作業はメンテナーが行う）。公開するものは、`npm run pack:rp-kit` で JavaScript と型定義に変換してまとめる（#77）。

初回の公開（0.1.0）の準備はできたが、次の事情で、手で公開する形は続けにくい。

- 公開には、npm にログインした環境が要る。メンテナーが使うクラウド環境（Claude Code など）から公開するには、npm のトークンを、その環境の中（環境変数や `.npmrc`）に置くことになる。環境の中のトークンは、その環境で動くどのコマンドからも読める（依存のインストールスクリプトを含む）。公開用のトークンが漏れると、`@pii-token-vault` のパッケージに、悪意のある版を出されうる（ソフトウェアのサプライチェーン攻撃）。
- バグを直した版を出すたびに、手元でログインして公開すると、どのコミットから作ったかを、利用する企業の側で確かめられない。

## 決定

### 公開のワークフロー（`.github/workflows/publish-rp-kit.yml`）

- メンテナーが、GitHub の Actions の画面から、`main` で手で起動する（`workflow_dispatch`）。既定は `dry_run`（公開しない）。中身と版を確かめてから、`dry_run` を外して起動し直す。
- 公開するのは、そのコミットで CI（lint・typecheck・test と e2e）が通ったものだけ。ワークフローの最初に、GitHub の API で、そのコミットの check run を確かめる（GitHub Actions が付けたものに限る）。
- まとめるジョブ（pack）と、公開するジョブ（publish）を分ける。
  - pack は、`npm ci --ignore-scripts` と `npm run pack:rp-kit` と `npm pack` で tarball を作り、`npm publish --dry-run` で中身を確かめる。秘密の値を持たない。同じ版が公開済みなら、ここで止める。
  - pack は、作った tarball を空のプロジェクトに入れ（`--ignore-scripts`）、パッケージ名で SDK と `/kit` を読み込めることと、企業に届く依存に既知の脆弱性がないこと（`npm audit --omit=dev`。重さによらず止める）を確かめる。CI の `npm ci` は `--no-audit` なので、CI が通っただけでは、監査の結果は分からない（2026-11-18 のレビュー）。
  - 公開用の `package.json` の `files` に、変換したファイルと README、LICENSE だけを並べる。出力先にほかのファイルが紛れても、npm は入れない。
  - publish は、pack が作った tarball を受け取って、`npm publish` だけを実行する。依存を入れず、リポジトリのコードも動かさない。
- npm のトークン（`NPM_TOKEN`）は、GitHub の environment `npm-publish` の secret に置き、publish のジョブの、公開の手順にだけ渡す。environment の保護の規則で、`main` だけから使えるようにし、メンテナーの承認を求める（GitHub の設定。オーナーが行う）。
- `--provenance` を付ける。npm のページで、どのリポジトリ、コミット、ワークフローから作ったかを確かめられる。
- 公開のワークフローでは、依存のキャッシュを使わない。アクションは、ci.yml と同じく、コミットの SHA で固定する。

### 依存の版

- 公開するパッケージの依存（`jose`）は、版をぴったり固定する（いまは `6.2.14`）。範囲（`^6.2.14` など）にすると、企業が新しく入れるときに、公開のときに検査していない新しい版が選ばれうる。公開する版には、検査した依存の版を届ける（2026-11-18 にオーナーが決めた）。
- 依存にセキュリティの修正が出たら、依存の版を上げて、このワークフローで検査した rp-kit の新しい版を出す。

### 初回の公開の後（O-118）

- npm の trusted publishing（GitHub Actions の OIDC で公開する。トークンを使わない）に切り替える。npm の側で、パッケージの設定に、このリポジトリ、ワークフロー（`publish-rp-kit.yml`）、environment（`npm-publish`）を登録する。trusted publishing は、パッケージが npm に既にあることが前提なので、初回だけはトークンを使う。
- 切り替えたら、`NPM_TOKEN` を GitHub から消し、npm でトークンを取り消す。ワークフローからトークンの手順を外す PR を出す（trusted publishing には npm CLI 11.5.1 以上が要るので、その PR で publish のジョブの npm の版も決める）。
- 切り替えた後は、npm のパッケージの設定で、トークンでの公開を許さない形にする（オーナーが決める）。
- → 下の追記（2026-11-19）のとおり切り替えた。

## 理由

- トークンを、メンテナーの手元やクラウド環境に置かずに済む。GitHub の environment の secret は、承認したジョブの、決めた手順の中だけで使われ、ログでは伏せられる。
- 公開のジョブで依存を入れないので、依存のインストールスクリプトやテストのコードが、トークンに触れる経路がない。
- 継続的に版を出すパッケージで、CI から provenance 付きで公開し、trusted publishing に移すのは、npm が勧める形である。バグを直した版も、同じ手順で出せる。

採らなかった案：

- メンテナーが手元で `npm login` と `npm publish` を行う：初回だけなら成り立つが、版を出すたびに手元のログインが要り、provenance を付けられない。
- クラウド環境の環境変数にトークンを置く：その環境のどのコマンドからも読めるので採らない。

## 残るリスク

- 初回の公開から trusted publishing に切り替えるまでの間は、`NPM_TOKEN` が GitHub にある。トークンは、範囲を `@pii-token-vault` のパッケージの読み書きに絞り、有効期限をいちばん短くする。
- GitHub のメンテナーのアカウントが乗っ取られると、ワークフローを起動して公開できる。GitHub と npm の両方で、2要素認証を必須にしておく（オーナーの設定）。
- provenance は、どこで作ったかを示すだけで、中身が正しいことは示さない。
- 依存を固定するので、依存の修正は、rp-kit の新しい版を出すまで企業に届かない。企業は、rp-kit を上げる必要がある。
- `npm audit` が見つけるのは、公開の時点で登録されている脆弱性だけである。公開の後に見つかった依存の脆弱性は、Dependabot（`.github/dependabot.yml`）の PR で知り、直した版を出す。

## 変えたもの

- `.github/workflows/publish-rp-kit.yml` を足した（2026-11-19 の追記で、publish のジョブを、trusted publishing での `npm stage publish` にした）。
- `scripts/pack-rp-kit.ts`：公開用の `package.json` に `files` を足した（テストも足した）。
- `packages/rp-kit/README.md` の「メンテナー向け」：公開の手順を、このワークフローにした。
- plan 10章「公開の順番」：公開の作業を、このワークフローで行うと書いた。

## 追記（2026-11-19）：trusted publishing と staged publishing に切り替えた（O-118）

0.1.0 を公開した後（2026-11-18）、オーナーが npm の設定を次のとおりにした。npm CLI 12.2.3 の `npm stage` の説明（Best Practices）が勧める3つ（2要素認証を飛ばせるトークンを消す、パッケージでトークンからの公開を禁じる、trusted publishing には `npm stage publish` だけを許す）と同じ形である。

- trusted publishing：GitHub Actions（`nori1234/pii-token-vault`、`publish-rp-kit.yml`、environment `npm-publish`）を登録した。Allowed actions は `npm stage publish` だけにし、`npm publish` と `npm dist-tag` は許さない。
- Publishing access：「Require two-factor authentication and disallow bypass 2fa tokens」にした。

これに合わせて、ワークフローを次のとおりにした（2026-11-19 にオーナーが、0.1.1 を出して、仮置きから承認までの流れを確かめる案を選んだ）。

- publish のジョブは、`npm stage publish`（staged publishing）だけを実行する。仮置きした版は、まだ誰も入れられない。npm にログインしたメンテナーが、2段階認証をして `npm stage approve <stage-id>` を実行したときに公開される。
- npm には trusted publishing でつなぐ。`NPM_TOKEN` を読む手順を外し、setup-node に `registry-url` を渡さない（トークンを読む `.npmrc` を作らない）。
- `npm stage` は、Node 22 に付いてくる npm（10.x）にはないので、publish のジョブで npm を 12.2.3 に固定して入れる（`--ignore-scripts`）。npm 12.2.3 は Node `^22.22.2` を求め、`node-version: 22` で入る版（22.23.x）は、これを満たす。
- 仮置きの ID は、ジョブの Summary に出す。
- 仮置きに失敗したときは、npm のログのファイル（`~/.npm/_logs`）から OIDC の行だけを、ジョブのログに出す。npm は、trusted publishing のトークンを得られなかった理由を、画面に出さないため（2026-11-19 の最初の仮置きは、理由が分からないまま `ENEEDAUTH` で止まった）。

理由：

- GitHub Actions のジョブは、公開まではできない。GitHub のメンテナーのアカウントやワークフローが乗っ取られても、npm で2段階認証をした承認がなければ、版は公開されない。GitHub の environment の承認と、npm の2段階認証の、2つの別々の確認を通す。
- 公開できるトークンを、どこにも置かずに済む。

残るリスク（上の「残るリスク」に足す）：

- 承認には、メンテナーが手元で npm にログインする必要がある（`npm stage approve`。npm の Web の画面で承認できるかは、まだ確かめていない）。手元のログインのセッションは、そのパソコンに残る。
- npm のアカウントが乗っ取られ、2段階認証も破られると、公開されうる。これは、staged publishing でも防げない。
- 仮置きした版は、同じ版の番号を使う。承認も取りやめもせずに残すと、その版の番号では公開できない。
- 承認の前に中身を確かめるのは、メンテナーの手順（`npm stage view` と `npm stage download`）に任せる。
