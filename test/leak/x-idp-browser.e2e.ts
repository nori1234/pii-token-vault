// idp の E2E（plan 10章 M3、ADR 0007、ADR 0018）。CDP の仮想認証器で、画面からパスキーを使う。
// 一時的な Postgres、鍵サービス、idp を、このワーカーの中で起動する（webServer は使わない。企業の鍵をテストが持つため）。
// 企業（RP）の役はテストが行い、redirect_uri への移動は、ブラウザが出した要求の URL から読む。
//
// どのテストも、先頭のコメントに漏えいシナリオの形式（攻撃者が持っている情報／試す経路／期待する結果）で狙いを書く。

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { type CDPSession, expect, type Page, test } from '@playwright/test';
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  jwtVerify,
  SignJWT,
} from 'jose';
import pg from 'pg';
import { createIdp, type Idp } from '../../packages/idp/src/app.ts';
import { type ApprovalType, DEVICE_KINDS, deviceKindOf } from '../../packages/idp/src/inbox.ts';
import { MemoryOutbox } from '../../packages/idp/src/mailer.ts';
import { type KeysvcProcess, startKeysvc } from '../../scripts/keysvc-up.ts';
import { applyDatabaseAcl, migrate } from '../../scripts/migrate.ts';
import { type PgCluster, startCluster } from '../../scripts/pg-up.ts';

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

const DATABASE = 'warifu_e2e';
const REDIRECT_URI = 'http://127.0.0.1:65000/callback';
const TENANT = {
  tenantId: randomUUID(),
  displayName: 'デモ予約（E2E）',
  relayDomain: 'e2e.relay.warifu.test',
};
const CLIENT_ID = 'rp-e2e';
/** M6 には製品の承認待ちの型がまだないので、E2E の型を使う（ADR 0023）。 */
const E2E_APPROVAL: ApprovalType = {
  type: 'e2e.pickup_change',
  channel: 'device',
  operation: '受け取り場所の変更',
  parse: (details) =>
    typeof details === 'object' &&
    details !== null &&
    typeof (details as { place_name?: unknown }).place_name === 'string'
      ? { place_name: String((details as { place_name: string }).place_name) }
      : undefined,
  lines: (content) => [{ label: '受け取り場所の名称', value: String(content.place_name) }],
};

let cluster: PgCluster;
let keysvc: KeysvcProcess;
let idp: Idp;
let origin: string;
let approvalOrigin: string;
let rpKey: PrivateKey;
const outbox = new MemoryOutbox();

async function freePort(): Promise<number> {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, 'localhost', () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

test.beforeAll(async () => {
  cluster = await startCluster();
  const admin = new pg.Client({
    host: cluster.host,
    port: cluster.port,
    user: cluster.user,
    database: 'postgres',
  });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${DATABASE}`);
  await admin.end();
  const bootstrap = new pg.Client({
    host: cluster.host,
    port: cluster.port,
    user: cluster.user,
    database: DATABASE,
  });
  await bootstrap.connect();
  await migrate(bootstrap);
  await applyDatabaseAcl(bootstrap, DATABASE);
  await bootstrap.end();
  keysvc = await startKeysvc();

  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  rpKey = privateKey;
  const jwk = await exportJWK(publicKey);
  const port = await freePort();
  origin = `http://localhost:${port}`;
  let approvalPort = await freePort();
  while (approvalPort === port) approvalPort = await freePort();
  approvalOrigin = `http://localhost:${approvalPort}`;
  idp = await createIdp({
    origin,
    approvalOrigin,
    approvalTypes: [E2E_APPROVAL],
    rpId: 'localhost',
    registry: {
      tenants: [TENANT],
      clients: [
        {
          clientId: CLIENT_ID,
          tenantId: TENANT.tenantId,
          redirectUris: [REDIRECT_URI],
          jwks: {
            keys: [
              {
                kty: 'EC',
                crv: 'P-256',
                x: jwk.x,
                y: jwk.y,
                kid: 'rp-1',
                alg: 'ES256',
                use: 'sig',
              },
            ],
          },
        },
      ],
    },
    keysvc: { socketPath: keysvc.socketPath, credential: keysvc.credentials.idp },
    db: { host: cluster.host, port: cluster.port, database: DATABASE },
    mailer: outbox,
    logWrite: () => {},
  });
  await idp.app.listen({ host: 'localhost', port });
  await idp.listenApproval({ host: 'localhost', port: approvalPort });
});

test.afterAll(async () => {
  await idp?.close();
  await keysvc?.stop();
  await cluster?.stop();
});

async function addVirtualAuthenticator(
  page: Page,
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/** CSP や Trusted Types の違反、捕まえていない例外を集める。4xx の読み込みの失敗は、拒否のテストで出るので除く。 */
function watchProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('pageerror', (error) => problems.push(`pageerror: ${error.name}: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    if (
      /^Failed to load resource: the server responded with a status of 4\d\d/.test(message.text())
    )
      return;
    problems.push(`console: ${message.text()}`);
  });
  return problems;
}

async function redeem(callback: URL, verifier: string) {
  const code = callback.searchParams.get('code');
  if (code === null) throw new Error('認可コードがない');
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: 'rp-1' })
    .setIssuer(CLIENT_ID)
    .setSubject(CLIENT_ID)
    .setAudience(idp.issuer)
    .setIssuedAt()
    .setExpirationTime('2m')
    .setJti(randomUUID())
    .sign(rpKey);
  const response = await fetch(`${idp.issuer}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: CLIENT_ID,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    }),
  });
  const body = (await response.json()) as Record<string, unknown>;
  expect(response.status).toBe(200);
  const jwks = createLocalJWKSet(
    (await (await fetch(`${idp.issuer}/jwks`)).json()) as JSONWebKeySet,
  );
  const { payload } = await jwtVerify(String(body.id_token), jwks, {
    issuer: idp.issuer,
    audience: CLIENT_ID,
    algorithms: ['ES256'],
  });
  return payload;
}

test('企業のログイン：画面でアカウントを作り、接続に同意し、企業に戻る', async ({ page }) => {
  // 攻撃者が持っている情報：なし（正規の利用者の基本の流れ。画面が CSP と Trusted Types の下で動くことを確かめる）
  // 試す経路：企業の認可の要求 → ログインの画面で「割符のアカウントを作る」→ 同意の画面で「接続する」→ 企業の redirect_uri
  // 期待する結果：企業名は登録簿の値。同意の画面の2つのボタンは同じ大きさで、初期フォーカスはどちらにもない。
  //               企業には ES256 の ID トークン（テナント単位の sub、別名、email_verified=false）。CSP の違反はない
  // plan 11章：テスト4（前半の基本の流れ）
  const problems = watchProblems(page);
  await addVirtualAuthenticator(page);
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email',
    state: 'state-1',
    nonce: 'nonce-1',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  });
  await page.goto(`${idp.issuer}/auth?${params}`);
  await expect(page.locator('#company')).toHaveText(TENANT.displayName);
  await page.getByRole('button', { name: '割符のアカウントを作る' }).click();

  const connect = page.getByRole('button', { name: '接続する' });
  const decline = page.getByRole('button', { name: '接続しない' });
  await expect(connect).toBeVisible();
  await expect(page.locator('#heading')).toBeFocused();
  const [a, b] = [await connect.boundingBox(), await decline.boundingBox()];
  expect(Math.round(a?.width ?? 0)).toBe(Math.round(b?.width ?? 1));
  expect(Math.round(a?.height ?? 0)).toBe(Math.round(b?.height ?? 1));
  // 企業の redirect_uri（127.0.0.1:65000）では何も待ち受けていない。リダイレクトの先は page.route でつかまえられない
  // ので、ブラウザが出した要求の URL を読む。
  const [request] = await Promise.all([
    page.waitForRequest((r) => r.url().startsWith(`${REDIRECT_URI}?`)),
    connect.click(),
  ]);
  const callback = new URL(request.url());
  expect(callback.searchParams.get('state')).toBe('state-1');
  const claims = await redeem(callback, verifier);
  expect(String(claims.sub)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(String(claims.email)).toMatch(/^[a-z2-7]{16}@e2e\.relay\.warifu\.test$/);
  expect(claims.email_verified).toBe(false);
  expect(claims.acr).toBe('urn:warifu:acr:passkey');
  expect(problems, 'CSP 違反やスクリプトのエラーがない').toEqual([]);
});

test('PWA：アカウントを作り、メールアドレスを宛先確認で登録する', async ({ page }) => {
  // 攻撃者が持っている情報：なし（正規の利用者の流れ）
  // 試す経路：PWA でアカウントを作る → メールアドレスを入れる → 送信箱の8桁のコードを入れる
  // 期待する結果：コードを入れるまでは「まだ登録していません」。入れた後は「登録しました」。
  //               画面に本物のメールアドレスは出さない（登録済みかどうかと更新の日時だけ）。CSP の違反はない
  // plan 11章：テスト10（登録時の応答は、登録済みかどうかで変わらない。ここでは画面の文言を確かめる）
  const problems = watchProblems(page);
  await addVirtualAuthenticator(page);
  await page.goto(`${origin}/`);
  await page.getByRole('button', { name: '割符のアカウントを作る' }).click();
  await expect(page.getByRole('heading', { name: 'メールアドレス' })).toBeVisible();
  await expect(page.getByText('まだ登録していません。')).toBeVisible();

  const email = `${randomBytes(6).toString('hex')}@example.com`;
  await page.getByLabel('新しいメールアドレス').fill(email);
  await page.getByRole('button', { name: '確認コードを送る' }).click();
  await expect(
    page.getByText(
      '入力したアドレスに確認コードを送りました。届いた8桁のコードを入力してください。',
    ),
  ).toBeVisible();
  const message = outbox.all().at(-1);
  if (message?.kind !== 'email_verification') throw new Error('確認コードのメールがない');
  await page.getByLabel('確認コード').fill(message.code);
  await page.getByRole('button', { name: '確認する' }).click();
  await expect(page.getByRole('status')).toHaveText('メールアドレスを登録しました。');
  await expect(page.getByText(/^登録済み/)).toBeVisible();
  await expect(page.locator('body')).not.toContainText(email);
  await expect(page.getByRole('button', { name: 'パスキーを追加する' })).toBeVisible();
  expect(problems, 'CSP 違反やスクリプトのエラーがない').toEqual([]);
});

test('UV のないアサーションでは、PWA にログインできない（ADR 0007 の4）', async ({ page }) => {
  // 攻撃者が持っている情報：利用者の認証器に触れられるが、生体認証や PIN を通せない
  // 試す経路：仮想認証器でアカウントを作った後、isUserVerified を false にしてログインする
  // 期待する結果：ログインできず、理由を出さない固定の文言が出る。ログインの画面のまま
  // plan 11章：番号なし（ADR 0007 の4）
  const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
  await page.goto(`${origin}/`);
  await page.getByRole('button', { name: '割符のアカウントを作る' }).click();
  await page.getByRole('button', { name: 'ログアウト' }).click();
  await expect(page.getByRole('status')).toHaveText('ログアウトしました。');
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
  await page.getByRole('button', { name: 'パスキーでログイン' }).click();
  await expect(page.getByRole('status')).toHaveText(
    'パスキーでの確認ができませんでした。もう一度お試しください。',
  );
  await expect(page.getByRole('button', { name: 'パスキーでログイン' })).toBeVisible();
});

test('承認用のオリジン：受信箱から承認待ちを開き、パスキーで承認する', async ({ page }) => {
  // 攻撃者が持っている情報：なし（正規の利用者の流れ。DESIGN.md 2章「端末での承認」と「受信箱」の画面を確かめる）
  // 試す経路：PWA でアカウントを作る → 承認待ちを作る → 受信箱のリンクから承認用のオリジンを開く → パスキーで
  //           確認待ちを表示する → 承認する
  // 期待する結果：承認画面に、企業名、操作の種類、型が決めた項目、要求の時刻と端末、警告文 A-2（DESIGN.md の文言の
  //               まま）、同じ大きさの承認と拒否が出る。初期フォーカスは企業名で、どのボタンにも置かない。承認すると、受信箱で
  //               「承認しました」になる。CSP の違反はない
  // plan 11章：番号なし（plan 10章 M6、DESIGN.md 原則4・8）
  const problems = watchProblems(page);
  const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
  await page.goto(`${origin}/`);
  await page.getByRole('button', { name: '割符のアカウントを作る' }).click();
  await expect(page.getByRole('heading', { name: '受信箱' })).toBeVisible();
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  const handle = Buffer.from(credentials[0]?.userHandle ?? '', 'base64').toString('hex');
  const userId = `${handle.slice(0, 8)}-${handle.slice(8, 12)}-${handle.slice(12, 16)}-${handle.slice(16, 20)}-${handle.slice(20)}`;
  // 要求の端末は、要求を出したブラウザの User-Agent から決める（ここでは、同じブラウザから出したことにする）。
  const device = deviceKindOf(await page.evaluate(() => navigator.userAgent));
  const requested = await idp.requestApproval({
    userId: userId as never,
    tenantId: TENANT.tenantId as never,
    type: E2E_APPROVAL.type,
    details: { place_name: 'テスト店' },
    ttlSeconds: 300,
    device,
  });
  expect(requested.ok).toBe(true);
  await page.reload();
  await expect(page.getByText('確認待ち', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: '確認待ちの画面を開く' }).click();
  await expect(page).toHaveURL(`${approvalOrigin}/`);
  await page.getByRole('button', { name: 'パスキーで確認待ちを表示する' }).click();

  const card = page.getByRole('article');
  await expect(card.getByRole('heading', { name: TENANT.displayName })).toBeFocused();
  await expect(card.getByText('受け取り場所の変更', { exact: true })).toBeVisible();
  await expect(card.getByText('テスト店')).toBeVisible();
  await expect(card.getByText(/^要求の時刻：/)).toBeVisible();
  await expect(
    card.getByText(`要求の端末：${DEVICE_KINDS[device]}`, { exact: true }),
  ).toBeVisible();
  await expect(card.getByRole('note')).toContainText('ご注意');
  await expect(card.getByRole('note')).toContainText(
    'この確認は、あなたが今この端末で受け取り場所の変更をしようとしている場合だけ承認してください。電話やメッセージで頼まれて承認してはいけません。',
  );
  const approve = card.getByRole('button', { name: '承認する' });
  const deny = card.getByRole('button', { name: '拒否する' });
  const [a, d] = await Promise.all([approve.boundingBox(), deny.boundingBox()]);
  expect(a?.width).toBe(d?.width);
  expect(a?.height).toBe(d?.height);
  await approve.click();
  await expect(page.getByRole('status')).toHaveText('承認しました。');
  await expect(page.getByText('確認待ちはありません。')).toBeVisible();

  await page.goto(`${origin}/`);
  await expect(page.getByText('承認しました', { exact: true })).toBeVisible();
  expect(problems, 'CSP 違反やスクリプトのエラーがない').toEqual([]);
});
