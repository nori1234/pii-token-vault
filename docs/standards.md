# 設計の根拠にしている基準と一次資料

設計の根拠にしている基準の一覧。「状態」列の意味は次のとおり。

- **未確認**：根拠として挙げているが、抜粋もまだ確かめていない。
- **抜粋のみ**：公式ドメインに絞った検索で抜粋を確認しただけで、原文は通読していない。報道の抜粋を含むものは、その旨を表の後の注に書く。
- **原文で確認済み**：原文を読み、版・節番号・文言を照合した。

この開発環境のネットワークでは、政府系サイトなどへの接続がポリシーで拒否されるため、2026-10-17 時点で「原文で確認済み」のものはない。原文の照合はイシュー #2（M0）で行い、照合したら状態を更新する。抜粋と原文が食い違った場合は、設計を見直して ADR に記録する。

## 本人確認・認証

| 基準 | 版・日付 | この製品が根拠にしている点 | 反映先 | 状態 |
|---|---|---|---|---|
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) | 2025-07 確定 | KBA は認証として認めない（3.1.1.2）。メールを OOB 認証に使ってはならない（3.1.3.1）。PSTN は制限付き（3.2.9）。同期パスキーは AAL2 まで。回復（4.2）の手段は保存型・発行型の回復コード、recovery contacts（指定した人の連絡先にコードを送る方式）、身元確認のやり直しで、メールや SMS で回復コードを送ることを条件付きで認めている（この製品はそれより厳しくする） | 原則、回復 | 抜粋のみ |
| [NIST SP 800-63A-4](https://pages.nist.gov/800-63-4/sp800-63a.html) | 2025-07 確定 | KBV を身元確認に使ってはならない（SHALL NOT） | 原則 | 抜粋のみ |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | errata set 2 | §5.7：email や phone_number を一意の識別子にしてはならない。§8.1：pairwise | 接続要件、idp | 抜粋のみ |
| [OpenID CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | 2021-09 Final | poll、ping、push。login_hint_token、binding_message、user_code | 窓口 | 抜粋のみ |
| [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba-ID1.html) | Implementer's Draft | push の禁止。広く知られた識別子を hint にする危険 | 窓口 | 抜粋のみ |
| [RFC 9470](https://www.rfc-editor.org/info/rfc9470/)、[RFC 9396](https://www.rfc-editor.org/info/rfc9396/) | 2023 | step-up と、操作に結び付いた承認（RAR） | 高リスクの操作 | 抜粋のみ |
| [RFC 8417（SET）](https://www.rfc-editor.org/info/rfc8417/) | 2018 | iss、aud、jti、iat を持つ署名付きのイベント | 企業への知らせ | 未確認 |
| [OpenID RISC 1.0 と SSF](https://openid.net/specs/openid-risc-1_0-final.html) | 2025-09 Final | 回復や識別子の変更を企業に知らせる | 企業への知らせ | 抜粋のみ |
| [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | — | BE/BS フラグ（同期できるか、同期されているか） | 回復の予防 | 未確認 |
| [FIDO Alliance：回復のベストプラクティス](https://fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf) | 2019-02 | 回復手段は、取り戻す認証情報より弱くてはならない | 回復（P0 が満たすかは未評価） | 抜粋のみ |
| [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0) | 2025-05-30 | 6.4.2（秘密の質問を置かない）、6.4.3（リセットで MFA を迂回させない）、6.4.4（要素を失ったら登録時と同じ水準で確認し直す。P0 の回復が満たすかは未評価）、6.6.1（L3 では SMS を使わせない） | 全体 | 抜粋のみ |
| [デジタル庁 DS-511](https://www.digital.go.jp/assets/contents/node/basic_page/field_ref_resources/e2a06143-ed29-4f1d-9c31-0f06fca67afc/12cb1a6c/20250930_resources_standard_guideline_identityverification_01.pdf) と [DS-512](https://www.digital.go.jp/assets/contents/node/basic_page/field_ref_resources/e2a06143-ed29-4f1d-9c31-0f06fca67afc/c7edc43c/20260224_resources_standard_guideline_identityverification_1.pdf) | 2025-09-30 / 2026-02-24 | AAL2 以上ではパスキーかマイナンバーカード。回復は認証と同等以上の強さ | 原則、回復（P0 が満たすかは未評価） | 抜粋のみ |
| [金融庁 監督指針の改正（証券）](https://www.fsa.go.jp/news/r7/shouken/20251015/01.pdf)、[（銀行）](https://www.fsa.go.jp/news/r7/sonota/20260227/20260227.html) | 2025-10-15 / 2026-02-27 | フィッシング耐性のある多要素認証を、初期設定で必須にする | 原則 | 抜粋のみ |
| [日本証券業協会 ガイドライン](https://www.jsda.or.jp/about/hatten/inv_alerts/alearts04/files/20251015_internetgl.pdf) | 2025-10-15 | 同上。SMS やメールの OTP では、リアルタイムのフィッシングを防げない | 原則 | 抜粋のみ |
| [Apple：iCloud キーチェーンのエスクローのセキュリティ](https://support.apple.com/guide/security/escrow-security-for-icloud-keychain-sec3e341e75d/web) | — | 同期パスキーの安全性が、同期先アカウントの回復手段に左右されること | 残るリスク | 抜粋のみ |

## 脅威の動向

| 資料 | 日付 | 根拠にしている点 | 反映先 | 状態 |
|---|---|---|---|---|
| [NICT：A2B攻撃の注意喚起](https://www.nict.go.jp/press/2026/10/13-1.html) | 2026-10-13 | App-to-Backend 攻撃。BOLA、SSRF、RCE、SQL インジェクション。相次ぐ漏えいの原因の一つとしている | plan Context、2章 | 抜粋のみ |
| [総務省：公開アプリの解析情報を悪用した攻撃への注意喚起](https://www.soumu.go.jp/menu_kyotsuu/important/kinkyu02_000680.html) | 2026-10-13 | サーバー側で認証・認可と入力の検証を行う | plan Context、2章 | 抜粋のみ |
| [JPCERT/CC JPCERT-AT-2026-0030「直近で相次いでいる国内組織における不正アクセスに関する注意喚起」](https://www.jpcert.or.jp/at/2026/at260030.html) | 2026-10-08（10-09 更新） | 2026年9月前後から、国内組織で不正アクセスによる個人情報の漏えいが相次ぐ。一般向けのアプリだけでなく、BI ツールや従業員向けの管理システムなど、外部からの利用を想定していないシステムも被害を受けた。把握している情報は限定的かつ断片的とされる（攻撃の類型は、表の後の注）。推奨する対策：API のレート制限、エンドポイントごとのアクセス制御、最小権限、トークンの有効期限の設定と、漏えいが疑われるものの速やかな無効化、既知の脆弱性の修正の適用、業務上不要な管理機能の公開の停止、保存期間を過ぎたデータの削除、侵害後の横展開への対策、検知の体制と初動対応の点検、地域限定のサービスでのアクセス元の地域の制限 | plan 2章、3-3、8章、9章、10章（地域の制限は反映していない。表の後の注） | 抜粋のみ |
| [JPCERT/CC Eyes「連続不正アクセス事案の攻撃手法に関する調査」](https://blogs.jpcert.or.jp/ja/2026/10/web_api_attacks.html) | 2026-10 | 攻撃者が AI を使って、既知の脆弱性のスキャンや、API 経由の攻撃をしていた。攻撃元のサーバーに、Android アプリ（APK）を解析した痕跡と、Flutter アプリのリバースエンジニアリングのツールがあった。SSRF への対策と、API の利用の監視を推奨する | plan 2章、03 の ATK-02 | 抜粋のみ |
| [国家サイバー統括室「不正アクセスによる漏えい等の事案を踏まえた対応について」](https://www.cyber.go.jp/pdf/press/taiou.pdf) | 2026-10-09 | 大量の個人情報や機微な情報を扱う事業者に、対策の徹底を求める。3分野：ウェブシステム等の適切な管理、サプライチェーンを通じた侵害への対策、データの適切な管理。パッチの迅速な適用、多要素認証の導入、委託先・再委託先の管理状況の継続的な確認、ログの監視など | plan 2章、3-3、8章、9章、10章 | 抜粋のみ |
| [国家サイバー統括室「お知らせ」](https://www.cyber.go.jp/news/20261014.html) | 2026-10-14 | 各機関の注意喚起をまとめている：個人情報保護委員会（10-07「大規模な漏えい等事案を踏まえた対応について」）、警察庁（10-08）、金融庁・経済産業省・IPA（10-09）、NICT（10-13。アプリの解析を足がかりにしたサーバーへの攻撃＝A2B攻撃）、JPCERT/CC。個別の資料をこの表に足すかは、原文の照合のときに決める | — | 抜粋のみ |
| [株式会社ラック「国内で相次ぐWebシステムからの情報漏えい～ラックの観測から見える変化と、企業が今とるべき対策」](https://www.lac.co.jp/lacwatch/alert/20261015_004996.html) | 2026-10-15 | いまの状況を「特定の製品や脆弱性」または「特定の業種」を狙った問題として捉えるだけでは十分ではない（複数の攻撃経路が幅広い業種にまたがる）。侵入の約7割は、ID の不正利用と Web アプリの脆弱性の悪用。クラウドのアクセスキーや API キーの管理不備も足がかりになる。問題の本質は、自社に攻撃できる弱点が残っていないか。予約・会員・業務のシステムや管理画面も含めて、公開している資産を継続的に点検する。WAF だけに頼らない。IDOR/BOLA には、正規の認証トークンでも、その利用者がそのデータにアクセスしてよいかをサーバー側で確かめる。アプリは解析される前提で、秘密の情報や重要な認証・認可の判断を、できる限りアプリ側に持たせない。多要素認証、アクセスキーや API キーの定期的な入れ替えと失効の手順。公表の件数の増加には、公表の早期化の影響もありうる | plan Context、1-2、2章、3-3、8章、12章 | 抜粋のみ |
| [個人情報保護委員会：大規模な漏えい等事案を踏まえた注意喚起](https://www.ppc.go.jp/news/careful_information/261007_alert/) | 2026-10-07 | 保有の必要性の見直し、データの最小化。国家サイバー統括室のお知らせ（2026-10-14）では「大規模な漏えい等事案を踏まえた対応について」の題名で挙げられている。題名は原文で確かめる | plan 3-3 | 抜粋のみ |
| [金融庁：本人確認書類の画像の漏えいを受けた要請](https://www.fsa.go.jp/news/r8/sonota/20261009/20261009.html) | 2026-10-09 | IC チップの読み取りへの前倒しの移行 | — | 抜粋のみ |
| 各社の漏えいの公表（plan の Context） | 2026-09〜10 | 相次ぐ漏えいの規模。個別の原因は事案ごとに異なる | plan Context | 未確認 |

- JPCERT-AT-2026-0030 の抜粋で確かめた攻撃の類型：A（標的ごとに複数のソフトウェアの既知の脆弱性を探索する。設定ファイルやバックアップファイルの窃取など、管理不備を突く攻撃も）、B（公開アプリを解析して API のエンドポイントやキーを特定し、管理用・内部の API に不正なリクエストを送る。利用者の権限の変更、不正なアカウントの作成など）、C（BI ツール Metabase の SQL インジェクションの脆弱性を、API 経由で悪用する）、D（公開 Web サーバーから届くアプリケーションサーバーに、WAR ファイルで Web シェルを設置する）。以前の抜粋にあったレート制限の例（ログイン、リセット、SMS の送信）は、今回の抜粋では確かめられなかった。
- JPCERT/CC の2つ、国家サイバー統括室の2つ、ラックの行と、個人情報保護委員会の行の題名の注（2026-10-20 に足した行と書き直した行）は、公式のページと報道の、検索結果の抜粋だけによる。報道の抜粋を含むので、上の「抜粋のみ」の定義（公式ドメインに絞った検索）より確かさが低い。原文は、この環境から取得できなかった。
- この表の資料は、どれも個別の事案に結び付けない（plan の Context）。
- JPCERT-AT-2026-0030 の推奨のうち、地域限定のサービスでのアクセス元の地域の制限は、計画に反映していない。理由は [ADR 0008](adr/0008-october-2026-advisories-review.md) に書いた。

## 暗号

| 基準 | 版・日付 | 根拠にしている点 | 状態 |
|---|---|---|---|
| [CRYPTREC 暗号リスト LS-0001-2022R1](https://www.cryptrec.go.jp/list/cryptrec-ls-0001-2022r1.pdf) | 2023-03-30 | AES、GCM（IV は96ビットを推奨）、HMAC、SHA-256、ECDSA が、電子政府推奨暗号リストに掲載されている。WebAuthn で受け付ける RS256（RSASSA-PKCS1-v1_5）の掲載状況は未確認 | 抜粋のみ |
| [CRYPTREC/IPA TLS 暗号設定ガイドライン](https://www.cryptrec.go.jp/report/cryptrec-gl-3001-3.1.1.pdf) | 2025-04 | 本番の TLS の設定 | 抜粋のみ |

プロトコルで方式が決まっているもの（Web Push の RFC 8291、DKIM と ARC の rsa-sha256、受け取ったメールの ed25519-sha256 の検証）は、CRYPTREC への掲載を問わない例外として扱う（plan 8章）。

## 法令・行政の解釈

| 資料 | 日付 | 根拠にしている点 | 状態 |
|---|---|---|---|
| [個人情報保護委員会 Q&A Q1-4](https://www.ppc.go.jp/all_faq_index/faq1-q1-4/)、[Q8-2](https://www.ppc.go.jp/all_faq_index/faq1-q8-2/) | Q&A 令和7年7月更新 | 別名と sub だけなら、企業にとって個人関連情報。氏名や住所を結び付けた時点で個人情報になる。令和8年改正の後は、連絡可能個人関連情報として規制される | 抜粋のみ |
| [個人情報保護委員会 通則編 2-1](https://www.ppc.go.jp/personalinfo/legal/guidelines_tsusoku/) | 令和8年6月一部改正 | 他の事業者への照会が要るなら、容易に照合できない | 抜粋のみ |
| [Q&A Q7-43](https://www.ppc.go.jp/all_faq_index/faq1-q7-43/) | — | 委託先は、複数の委託元のデータを本人ごとに突き合わせられない → 割符を委託先にしない | 抜粋のみ |
| [Q&A Q6-11](https://www.ppc.go.jp/all_faq_index/faq1-q6-11_/) | — | 連絡先だけの漏えいは、ただちには財産的被害の類型（第2号）に当たらない | 抜粋のみ |
| [Q&A「高度な暗号化等の秘匿化」](https://www.ppc.go.jp/all_faq_index/faq1-q6-19_/) | — | 推奨暗号と鍵の分離管理で、漏えい等報告が不要になりうる。反映先はなし：割符の報告義務は残る前提で設計し、主張には使わない | 抜粋のみ |
| [個人情報保護法 令和8年改正](https://www.ppc.go.jp/news/press/2026/260717/) | 2026-07-17 公布 | 連絡可能個人関連情報への、不適正な利用と不正な取得の禁止 | 抜粋のみ |
| [総務省 電気通信事業参入マニュアル［追補版］](https://www.soumu.go.jp/main_content/000477428.pdf) | 令和5年1月30日改定 | 内容を変えずに取り次ぐことは「他人の通信の媒介」に当たり、届出が要る | 抜粋のみ |
| [総務省：犯収法（電話受付代行業・電話転送サービス事業者向け）](https://www.soumu.go.jp/main_sosiki/joho_tsusin/d_syohi/money/top.html) | 2026-10 時点 | 電話転送サービス事業者の定義（番号の利用許諾と自動転送） | 抜粋のみ |
| [総務省：電話転送サービス事業者への是正命令](https://www.soumu.go.jp/menu_news/s-news/01kiban18_01000233.html) | 2024-06-03 | 取引時確認の義務違反で是正命令が出た例 | 抜粋のみ |
| [経済産業省：郵便物受取サービス業者の Q&A](https://www.meti.go.jp/policy/commercial_mail_receiving/pdf/questionandanswer.pdf) | 令和2年4月版 | 自己の所在地で顧客の郵便物を受け取って引き渡す事業は、犯収法の特定事業者 → 割符が荷物を受け取って転送する形は採らない | 抜粋のみ |
| [総務省：携帯電話不正利用防止法の Q&A（050アプリ電話）](https://www.soumu.go.jp/main_sosiki/joho_tsusin/d_syohi/050526_1.files/Page444.html) | 令和6年4月施行の改正 | 050 のアプリ通話を提供する事業者も、本人確認の義務の対象 | 抜粋のみ |
| [警察庁：犯収法施行規則の改正 Q&A](https://www.npa.go.jp/sosikihanzai/jafic/hourei/data/25062402qa.pdf) | 2025-06-24 公布、2027-04-01 施行 | 非対面の本人確認を、IC チップと JPKI に原則一本化する | 抜粋のみ |
| [古物営業法（e-Gov）](https://laws.e-gov.go.jp/law/324AC0000000108) | 現行 | 15条：買受けなどの際に、相手方の住所・氏名・職業・年齢を確認する | 抜粋のみ |
| [経済産業省：クレジットカード・セキュリティガイドライン 6.0版](https://www.meti.go.jp/press/2024/03/20250305002/20250305002.html) | 2025-03-05 | EC 加盟店への EMV 3-D セキュアと不正ログイン対策の要求。不正対策の「配送先情報」 | 抜粋のみ |

## メール

| 資料 | 根拠にしている点 | 反映先 | 状態 |
|---|---|---|---|
| [Google：Email sender guidelines](https://support.google.com/a/answer/81126) | 送信者の要件（SPF、DKIM、DMARC） | 8章 | 抜粋のみ |
| [Google：Best practices for forwarding email to Gmail](https://support.google.com/a/answer/175365) | 転送する事業者は ARC を付ける。DKIM で保護されたヘッダーは変えないのが原則。この製品は衛生のために意図して変える（plan 3-2）ので、その影響を plan 8章で扱う | 3-2、8章 | 抜粋のみ |
| [RFC 6376（DKIM）](https://www.rfc-editor.org/info/rfc6376/) | l= と x= の意味、h= と oversign | 送信元ロック | 未確認 |
| [RFC 7489（DMARC）](https://www.rfc-editor.org/info/rfc7489/) | 整合の判定 | 返信の中継 | 未確認 |
| [RFC 8617（ARC）](https://www.rfc-editor.org/info/rfc8617/) | 転送時の封印 | 8章 | 未確認 |
| [RFC 8058（ワンクリック配信停止）](https://www.rfc-editor.org/info/rfc8058/) | List-Unsubscribe-Post と DKIM の関係 | 中継の衛生 | 未確認 |
| [RFC 8463（Ed25519 の DKIM）](https://www.rfc-editor.org/info/rfc8463/) | 受け取ったメールの検証方式 | 暗号の許可リスト | 未確認 |
| [RFC 8291（Web Push の暗号）](https://www.rfc-editor.org/info/rfc8291/) | aes128gcm と ECDH | 暗号の例外 | 未確認 |

## 配送

| 資料 | 根拠にしている点 | 状態 |
|---|---|---|
| [日本郵便：郵便番号・デジタルアドレスAPI](https://www.post.japanpost.jp/notification/pressrelease/2025/00_honsha/0526_02.html) | 事業者はデジタルアドレスから住所を取得できる → 別名としては使えない | 抜粋のみ |
| [ヤマト運輸：配送連携API の FAQ](https://b-faq.kuronekoyamato.co.jp/app/answers/detail/a_id/678/) | 匿名配送はフリマなど向けで、EC から購入者への発送には使えない | 抜粋のみ |
| [ヤマト運輸：EC自宅外受け取りAPI](https://business.kuronekoyamato.co.jp/service/lineup/business_members/api/pickup/index.html) | 受け取り場所の指定（第1段階） | 抜粋のみ |

## スタックの前提

| 資料 | 根拠にしている点 | 状態 |
|---|---|---|
| [OpenID 認定の一覧](https://openid.net/certification/) | oidc-provider が認定を受けていること（ADR 0002） | 未確認 |
| [AWS：SES のメール受信リージョンの拡大](https://aws.amazon.com/about-aws/whats-new/2023/09/amazon-ses-email-service-7-regions) | 東京リージョンで受信できること（ADR 0002） | 抜粋のみ |

## 原文の照合に必要なドメイン

イシュー #2 で、次のドメインへの接続の許可か、PDF の提供が要る。

`nist.gov`、`openid.net`、`rfc-editor.org`、`w3.org`、`fidoalliance.org`、`github.com`、`digital.go.jp`、`fsa.go.jp`、`jsda.or.jp`、`nict.go.jp`、`soumu.go.jp`、`jpcert.or.jp`（`blogs.jpcert.or.jp` を含む）、`cyber.go.jp`、`lac.co.jp`、`ppc.go.jp`、`cryptrec.go.jp`、`meti.go.jp`、`npa.go.jp`、`e-gov.go.jp`、`support.google.com`、`support.apple.com`、`post.japanpost.jp`、`kuronekoyamato.co.jp`、`aws.amazon.com`
