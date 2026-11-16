# @pii-token-vault/rp-kit

割符（Warifu）に接続する企業のための SDK と、適合テストキットです。企業のサーバー（Node 22 以上）で動かします。

- これは PoC です。本番では使わないでください。
- npm には、まだ公開していません（公開は、M9 のマージの後に、メンテナーが行います）。
- 接続要件の正本は、リポジトリの [`docs/spec/02-rp-requirements.md`](../../docs/spec/02-rp-requirements.md) です。この README と食い違ったら、仕様を正とします。設計の判断は [ADR 0029](../../docs/adr/0029-company-side-code-boundary.md) と [ADR 0030](../../docs/adr/0030-high-risk-step-up.md) にあります。

## SDK が受け持つこと、企業が受け持つこと

| | 受け持つこと |
|---|---|
| SDK | 要求の組み立て（client assertion、PKCE、PAR、トークンの要求、企業向け API の要求）。応答の検証（ID トークン、操作ごとの承認、紐付けの承認、SET）。承認の JWT を一度しか使わせないこと。エラーの扱い |
| 企業 | 通信の関数（1つの要求を送って、1つの応答を返す）。秘密鍵の保管。自前のセッション。アカウントの識別（`iss` と `sub` の組だけ）。高リスクの操作の内容の固定と、実行の確定（下の「高リスクの操作」） |

SDK は、自分ではどこにもつなぎません。送る先は、設定で与えた割符のオリジンだけです。応答の中の URL には進みません。リダイレクト（3xx）は、失敗として扱います。

## 使い方

### 通信の関数

企業が書くのは、この関数だけです。リダイレクトに従わない作りにしてください。

```ts
import type { Send } from '@pii-token-vault/rp-kit';

const send: Send = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: request.body,
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  });
  return {
    status: response.status,
    headers: { 'content-type': response.headers.get('content-type') ?? '' },
    body: await response.text(),
  };
};
```

参照実装は、リポジトリの `packages/demo-rp/src/transport.ts` です（宛先を設定のオリジンの完全一致に限り、応答を上限までしか読みません）。

### ログイン

```ts
import { createWarifuClient } from '@pii-token-vault/rp-kit';

const warifu = await createWarifuClient({
  idpOrigin: 'https://idp.warifu.example', // https だけ。http は localhost などのループバックに限る
  clientId: 'your-client-id',
  redirectUri: 'https://your-site.example/callback',
  privateKey, // private_key_jwt の秘密鍵（P-256 の JWK）
  kid: 'your-key-id',
  send,
});

// 1. 認可の要求を始める。pending は、企業のサーバーのセッションに置く（ブラウザに渡さない）。
const { url, pending } = await warifu.authorize();
// 2. 利用者を url に移らせる。
// 3. redirect_uri に戻ってきたら、戻りの URL と、セッションに置いた pending で finish を呼ぶ（state、nonce、PKCE は SDK が確かめる）。
const login = await warifu.finish(callbackUrl, pending);
// 4. 自前のセッションを作る。アカウントは (login.iss, login.sub) の組だけで決める。
```

- 根拠にしてよいのは、`iss`・`sub`・`acr`・`authTime` だけです。`contactAlias`（別名）は連絡用です。識別、アカウントの統合、紐付け、再設定の宛先には使いません。
- `recoveredAt` は、回復の後の制限を強める方向にだけ使います。
- step-up は、`authorize({ maxAge: 0 })` で新しい認証を求めます。

### 高リスクの操作（出金先の変更）

```ts
// 申請ID を作るときに、変更の内容の全体（口座番号の全桁など）を、申請ID に結び付けて自社で固定する。
const { url, pending } = await warifu.pushOperation({
  action: 'payout_destination.change',
  requestId,
  sub: session.sub,
  content: { bankCode: '9991', branchCode: '001', accountLast4: '1234' },
});
// 利用者が割符の画面で承認して戻ってきたら：
const login = await warifu.finish(callbackUrl, pending);
const approval = await warifu.verifyOperationApproval(login, pending, {
  requestId,
  content: fixedContent, // 申請ID で自社に固定した内容から作る
});
```

割符が検出できるのは、申請ID と、表示した項目（金融機関コード、支店コード、口座番号の末尾4桁）の不一致だけです。表示が同じ別の口座への差し替えは、企業が次の3つで防ぎます（接続要件 RP-09）。

1. 申請の時に、変更の内容の全体を申請ID に結び付けて固定する。
2. 内容を変えるなら、新しい申請を作り、もう一度承認を受ける。
3. 変更の実行と、申請を使い済みにする更新を、1つのトランザクションで確定させる。

参照実装は `packages/demo-rp/src/payout.ts` です。

### 窓口の承認、初回紐付け

- 窓口の操作別承認：`pushDesk` と `verifyDeskApproval`。用途 `desk` の承認は、照会と軽い手続きだけに使います。高リスクの操作の根拠にはしません。
- 既存会員の初回紐付け：`pushInitialLink` と `readInitialLink`、`createCompanyApiClient` の `initialLink`（`prepare`、`status`、`submitProof`、`cancel`、`report`）。流れは [ADR 0028](../../docs/adr/0028-migration-details.md) にあります。

### SET の受け口

```ts
import { createCompanyApiClient, setRefusalOf } from '@pii-token-vault/rp-kit';

const companyApi = await createCompanyApiClient({
  origin: 'https://api.warifu.example',
  clientId: 'your-api-client-id',
  tenantId: 'your-tenant-id',
  privateKey,
  kid: 'your-key-id',
  send,
});

// 受け口（POST。本文は SET の文字列）
try {
  const set = await companyApi.verifySet(body);
  // jti の重複は、自分の記録で確かめる。処理できたら 202 を返す。
} catch (error) {
  const refusal = setRefusalOf(error); // refusal.status と refusal.body で応答する
}
```

- 受け取ったと言えるのは、`202` を返したときだけです。
- `setRefusalOf` は、SET を確かめて通らなかったときは `400`（古ければ `set_too_old`、先の時刻なら `iat_in_future` の理由を添える）を返します。割符の公開鍵を取れないなど、確かめられなかったときは `503`（本文なし）を返し、割符に送り直させます。

### 承認の JWT を一度だけにする

SDK は、承認の JWT の `jti` を一度しか使わせません。既定の置き場所は、1つのプロセスの中だけです。複数のサーバーで動かすときは、共有の置き場所（DB など）で `JtiStore` を作って渡してください。置き場所は、渡された時刻（`keepUntil`）を過ぎるまで、使い済みを忘れてはいけません。

### エラー

失敗は、すべて `RpKitError` です。`code` で分けます。

| code | 意味 |
|---|---|
| `invalid_config` | 設定の形が違う |
| `forbidden_destination` | 設定していない宛先に送ろうとした |
| `unavailable` | 割符に届かない、5xx、3xx、応答が大きすぎる |
| `rejected` | 割符が断った（4xx。`reason` に割符の `error` の値） |
| `invalid_response` | 応答の形が違う |
| `verification_failed` | 署名、宛先、期限、内容などの検証に失敗した |
| `replayed` | 同じ承認の JWT が、もう一度使われた |

エラーのメッセージには、トークンや ID の値を入れていません。

## 適合テストキット

企業が、自分の RP を自分の手元で点検するためのものです。模擬 OP は手元だけで動き、ネットワークを使いません。結果を外へ送りません。

```ts
import { createMockOp, runConformanceKit, type RpTestHooks } from '@pii-token-vault/rp-kit/kit';

const mockOp = await createMockOp({ clientId, redirectUri });
// テスト環境の RP の SDK を、模擬 OP に向ける（idpOrigin: mockOp.origin、send: mockOp.send）。

const hooks: RpTestHooks = {
  // 模擬 OP の固定の利用者で、RP のふだんのログインを1回通し、RP の内部のアカウントの参照を返す
  // （signInOnTestRp は、企業が自分のテスト環境に書く関数。authorize() の url を complete(url) に渡し、
  // 戻りの URL で finish() から先の自分の処理を行う。ログインを断ったら空文字を返す）。
  signIn: (persona, complete) => signInOnTestRp(persona, complete),
  legacyLogin: async () => 'absent', // 紐付けを済ませた会員の旧ログイン：accepted / refused / absent
  legacyReset: async () => 'absent', // メールや SMS による再設定
  linkAttack: async () => 'refused', // 漏れたメールで旧アカウントを奪って紐付ける攻撃：linked / refused
  routes: async () => [
    // 公開、管理、内部、バッチの入口を、性質の印と一緒に申告する
    { method: 'POST', path: '/orders/:id/cancel', tags: ['other'] },
  ],
};

const report = await runConformanceKit({ hooks, mockOp, participation: { mode: 'full' } });
// report.outcome：fail / incomplete / review / pass
```

- 模擬 OP の2人（`alpha` と `beta`）は、別名が同じで、`sub` が違います。別名でアカウントをまとめる RP は、不合格になります。
- 印が `sub_rewrite`・`account_merge`・`guest_lookup` のルートがあれば、不合格です。印がなく、名前だけが似ているルートは「要確認」で、企業が自分で確かめます。
- フックが未実装、例外、想定外の値（空のルートの申告を含む）のときは、「検査できなかった」として、合格にしません。
- 移行中の参加の企業は、`{ mode: 'migrating', reportedClosed: [...] }` を渡します。緩むのは、閉じたと報告していない入り口に対応する検査だけです。

### キットで分かること、分からないこと

- キットは、企業が自社で点検するためのものです。合格は、割符が企業を確かめたことを意味しません。企業の全体の安全性を保証するものでもありません。
- ルートの申告が正しいかは、キットでは確かめられません（自己申告）。
- 高リスクの操作の根拠、対象の持ち主の確かめ、窓口の運用などは、キットの検査に入っていません。接続要件の「監査」の項目を見てください。

## メンテナー向け：公開の準備

リポジトリの中では、Node が `.ts` をそのまま動かすので、このパッケージの `exports` は `src` の `.ts` を指しています。Node は `node_modules` の中の `.ts` を動かさないので、公開するものは、JavaScript と型定義に変換して作ります。

```
npm run pack:rp-kit -- <出力先のディレクトリ>
```

- 出力先に、変換した `.js` と `.d.ts`、公開用の `package.json`、README、LICENSE が入ります。テストと、変換の前の `.ts` は入りません。
- このコマンドは、公開をしません。中身を確かめた後、メンテナーが出力先で `npm publish` を実行します。
- 公開の前に決めること：版（いまは `0.0.0`）、npm のスコープ `@pii-token-vault` の持ち主、公開の範囲。
- `scripts/pack-rp-kit.test.ts`（`npm test` に入っています）が、まとめたものを、別のプロセスの Node で読み込めることを確かめています。
- `packages/rp-kit/test/readme.test.ts`（`npm test` に入っています）が、この README の `ts` のコードの例を、SDK の型で確かめています。例を変えたら、`npm test` で確かめてください。
