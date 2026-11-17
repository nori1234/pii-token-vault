// demo-rp（A社のデモ証券）の E2E（plan 10章 M9、ADR 0028、ADR 0029、ADR 0030）。実際のブラウザで、企業の画面と割符の画面を
// 行き来し、割符の画面に実際に表示されるもの（警告文 I、初回紐付けの承認と最終確認、出金先の変更の内容と警告文 A-2）を確かめる。
// 一時的な Postgres、鍵サービス、sender（テストの補助）、company-api、idp、demo-rp を、このワーカーの中で起動する。
// demo-rp は、自分の transport.ts（設定のオリジンにだけつなぐ fetch）で、idp と company-api につなぐ。
// 旧パスキー（demo-rp の RP ID も localhost）は、割符のパスキーと取り違えないよう、ブラウザの仮想認証器には入れず、
// テストの中のソフトウェアの認証器で、利用者のセッションのクッキーを付けて確かめる。

import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type BrowserContext, expect, type Page, test } from '@playwright/test';
import { exportJWK, generateKeyPair } from 'jose';
import pg from 'pg';
import { type CompanyApi, createCompanyApi } from '../../packages/company-api/src/app.ts';
import { createDemoRp, type DemoRp } from '../../packages/demo-rp/src/app.ts';
import { createIdp, type Idp } from '../../packages/idp/src/app.ts';
import { MemoryOutbox } from '../../packages/idp/src/mailer.ts';
import { type KeysvcProcess, startKeysvc } from '../../scripts/keysvc-up.ts';
import { applyDatabaseAcl, migrate } from '../../scripts/migrate.ts';
import { type PgCluster, startCluster } from '../../scripts/pg-up.ts';
import { installEgressGuard, takeEgressAttempts, uninstallEgressGuard } from '../setup/egress.ts';
import {
  makeTlsFixture,
  PUBLIC_V4,
  startTestSender,
  type TestSender,
  WEBHOOK_HOST,
} from '../setup/sender.ts';
import { SoftAuthenticator } from '../setup/soft-authenticator.ts';

const DATABASE = 'warifu_demo_e2e';
const TENANT_ID = randomUUID();
const COMPANY = 'デモ証券（E2E）';
const RESPONSIBILITY_NOTE =
  '割符は、割符を使った認証と操作の承認、割符のアカウントの管理と回復、それらに関わる知らせを受け持ちます。この企業独自のログイン方法や業務上の手続きは、この企業が管理しています。';
const HOUR = 3600 * 1000;

let clock = Date.now();
const now = () => new Date(clock);
let cluster: PgCluster;
let keysvc: KeysvcProcess;
let sender: TestSender;
let company: CompanyApi;
let idp: Idp;
let demo: DemoRp;
let demoOrigin: string;
let dir: string;

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

async function ports(count: number): Promise<number[]> {
  const found = new Set<number>();
  while (found.size < count) found.add(await freePort());
  return [...found];
}

test.beforeAll(async () => {
  // 外へのつなぎの見張り（Vitest の setupFiles と同じもの。test/setup/egress.ts）。afterAll で0件を確かめる。
  installEgressGuard();
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
  sender = await startTestSender({ A: { [WEBHOOK_HOST]: [PUBLIC_V4] } }, await makeTlsFixture());
  dir = await mkdtemp(join(tmpdir(), 'warifu-demo-e2e-'));

  const [idpPort, approvalPort, companyPort, demoPort] = (await ports(4)) as [
    number,
    number,
    number,
    number,
  ];
  const idpOrigin = `http://localhost:${idpPort}`;
  const companyOrigin = `http://localhost:${companyPort}`;
  demoOrigin = `http://localhost:${demoPort}`;
  const db = { host: cluster.host, port: cluster.port, database: DATABASE };
  const oidcKey = await generateKeyPair('ES256', { extractable: true });
  const apiKey = await generateKeyPair('ES256', { extractable: true });
  const publicOf = async (key: typeof oidcKey, kid: string) => {
    const jwk = await exportJWK(key.publicKey);
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid, alg: 'ES256', use: 'sig' };
  };
  const internalSecret = randomBytes(32);

  company = await createCompanyApi({
    config: {
      issuer: companyOrigin,
      tenants: [
        {
          tenantId: TENANT_ID,
          relayDomain: 'demo-e2e.relay.warifu.test',
          participation: 'full',
          initialLink: { profileVersion: 1, approvedOn: '2026-11-01' },
          webhookUrl: `https://${WEBHOOK_HOST}/set/demo`,
          apiClients: [
            {
              clientId: 'demo-api',
              jwks: { keys: [await publicOf(apiKey, 'api-1')] },
              scopes: ['company_api', 'initial_link'],
            },
          ],
        },
      ],
    },
    keysvc: { socketPath: keysvc.socketPath, credential: keysvc.credentials['company-api'] },
    db,
    sender: { socketPath: sender.sender.socketPath, credential: sender.credentials['company-api'] },
    deskInternal: {
      socketPath: join(dir, 'company-api.sock'),
      credentials: { idp: internalSecret },
    },
    now,
    logWrite: () => {},
    deliveryIntervalMs: 0,
  });
  await company.app.listen({ host: 'localhost', port: companyPort });

  idp = await createIdp({
    origin: idpOrigin,
    approvalOrigin: `http://localhost:${approvalPort}`,
    rpId: 'localhost',
    registry: {
      tenants: [
        { tenantId: TENANT_ID, displayName: COMPANY, relayDomain: 'demo-e2e.relay.warifu.test' },
      ],
      clients: [
        {
          clientId: 'demo-securities',
          tenantId: TENANT_ID,
          redirectUris: [`${demoOrigin}/callback`],
          jwks: { keys: [await publicOf(oidcKey, 'oidc-1')] },
          initialLink: true,
          operationActions: ['payout_destination.change'],
        },
      ],
    },
    keysvc: { socketPath: keysvc.socketPath, credential: keysvc.credentials.idp },
    db,
    mailer: new MemoryOutbox(),
    desk: {
      socketPath: join(dir, 'company-api.sock'),
      credential: `idp.${internalSecret.toString('base64url')}`,
    },
    now,
    logWrite: () => {},
  });
  await idp.app.listen({ host: 'localhost', port: idpPort });
  await idp.listenApproval({ host: 'localhost', port: approvalPort });

  demo = await createDemoRp({
    company: 'securities',
    displayName: COMPANY,
    origin: demoOrigin,
    idpOrigin,
    idpApprovalOrigin: `http://localhost:${approvalPort}`,
    oidc: {
      clientId: 'demo-securities',
      kid: 'oidc-1',
      privateKey: await exportJWK(oidcKey.privateKey),
    },
    companyApi: {
      origin: companyOrigin,
      tenantId: TENANT_ID,
      clientId: 'demo-api',
      kid: 'api-1',
      privateKey: await exportJWK(apiKey.privateKey),
    },
    initialLink: { profileVersion: 1 },
    demoSeed: true,
    now,
    // idp は、ID トークンを実際の時計で出す（テストの時計を進めても変わらない）。
    oidcNow: () => new Date(),
  });
  await demo.listen(demoPort);
});

test.afterAll(async () => {
  await demo?.close();
  await idp?.close();
  await company?.close();
  await sender?.stop();
  await keysvc?.stop();
  await cluster?.stop();
  if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  expectNoEgress();
});

/** 見張りが止めたつなぎと名前解決が0件であることを確かめて、見張りを外す。 */
function expectNoEgress(): void {
  const attempts = takeEgressAttempts();
  uninstallEgressGuard();
  expect(attempts).toEqual([]);
}

async function addVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

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

/** demo-rp に、利用者のセッションのクッキーを付けて JSON を送る（旧パスキーの確かめ。画面のボタンと同じ要求）。 */
async function demoPost(context: BrowserContext, path: string, body: unknown) {
  const cookie = (await context.cookies(demoOrigin)).map((c) => `${c.name}=${c.value}`).join('; ');
  const response = await fetch(`${demoOrigin}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: demoOrigin, cookie },
    body: JSON.stringify(body),
  });
  return {
    status: response.status,
    json: (await response.json().catch(() => ({}))) as Record<string, unknown>,
  };
}

async function verifyLegacy(context: BrowserContext, legacy: SoftAuthenticator): Promise<void> {
  const options = await demoPost(context, '/legacy/options', {});
  const response = legacy.get(options.json as never, undefined, { origin: demoOrigin });
  expect((await demoPost(context, '/legacy/verify', { response })).status).toBe(200);
}

/** 割符が送った SET（テストの受け口に届いたもの）を、demo-rp の受け口に渡す。 */
async function deliverSets(): Promise<void> {
  clock += 61_000;
  const from = sender.requests.length;
  await company.deliverDue();
  for (const request of sender.requests.slice(from)) {
    const response = await fetch(`${demoOrigin}/warifu/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/secevent+jwt' },
      body: request.body,
    });
    expect(response.status).toBe(202);
  }
}

test('デモ証券：割符でログインし、出金先を変更し、旧会員を引き継ぐ。割符の画面に、決めた文言と内容が表示される', async ({
  page,
}) => {
  // 攻撃者が持っている情報：なし（正規の利用者の流れ。割符の画面に実際に表示されるものを確かめる）
  // 試す経路：demo-rp でログイン → 出金先の変更（割符の /operation）→ 旧会員の引き継ぎの申請（割符の /initial-link）→
  //           待機の SET → 24時間 → 最終の確認（割符の /initial-link）
  // 期待する結果：ログインと初回紐付けの2つの画面に警告文 I。出金先の変更の画面に、割符の対応表の金融機関名・支店名、
  //               末尾4桁、架空の注記、警告文 A-2（口座番号の全桁は出ない）。最終の確認の画面に「取り消す」。
  //               ボタンは同じ大きさで、初期フォーカスはボタンにない。CSP の違反はない
  // plan 11章：テスト1・テスト9（画面の表示）
  const problems = watchProblems(page);
  await addVirtualAuthenticator(page);

  // ---- ログイン（警告文 I） ----
  await page.goto(demoOrigin);
  await expect(page.locator('#company')).toHaveText(COMPANY);
  await page.getByRole('button', { name: '割符でログイン' }).click();
  await expect(page.locator('#company')).toHaveText(COMPANY);
  await expect(page.locator('.responsibility-note')).toHaveText(RESPONSIBILITY_NOTE);
  await page.getByRole('button', { name: '割符のアカウントを作る' }).click();
  await page.getByRole('button', { name: '接続する' }).click();
  await expect(page.locator('#notice')).toHaveText('ログインしました。');
  await expect(page.locator('#payout')).toHaveText('出金先は、まだ登録していません。');

  // ---- 出金先の変更（割符の /operation。警告文 A-2） ----
  await page.goto(`${demoOrigin}/payout`);
  await page.getByLabel('金融機関コード（4桁）').fill('9991');
  await page.getByLabel('支店コード（3桁）').fill('101');
  await page.getByLabel('口座番号（7桁）').fill('1234567');
  await page.getByRole('button', { name: '割符で確認して変更する' }).click();
  const card = page.locator('.approval-card');
  await expect(card.locator('.company')).toHaveText(COMPANY);
  await expect(card.locator('.company')).toBeFocused();
  await expect(card.locator('.operation')).toHaveText('出金先の変更');
  await expect(card).toContainText('わりふデモ銀行（9991）');
  await expect(card).toContainText('中央支店（101）');
  await expect(card).toContainText('4567');
  await expect(card).not.toContainText('1234567');
  await expect(card).toContainText('デモ用の架空の金融機関・支店です。');
  await expect(card).toContainText(
    'この確認は、あなたが今この端末で出金先の変更をしようとしている場合だけ承認してください。電話やメッセージで頼まれて承認してはいけません。',
  );
  const approve = page.getByRole('button', { name: '承認する' });
  const deny = page.getByRole('button', { name: '承認しない' });
  const [a, b] = [await approve.boundingBox(), await deny.boundingBox()];
  expect(Math.round(a?.width ?? 0)).toBe(Math.round(b?.width ?? 1));
  await approve.click();
  await expect(page.locator('#notice')).toHaveText('出金先を変更しました。');
  await expect(page.locator('#payout')).toContainText('口座番号の末尾 4567');

  // ---- 旧会員の引き継ぎの申請（割符の /initial-link。最初の承認。警告文 I） ----
  const legacy = new SoftAuthenticator(demoOrigin);
  const seedOptions = await demoPost(page.context(), '/legacy/demo/options', {});
  const seeded = await demoPost(page.context(), '/legacy/demo/verify', {
    response: legacy.create(seedOptions.json as never),
  });
  expect(seeded.status).toBe(200);
  await verifyLegacy(page.context(), legacy);
  await page.goto(`${demoOrigin}/legacy`);
  await expect(page.locator('#legacy-verified')).toBeVisible();
  await page.getByRole('button', { name: '割符で確認して、引き継ぎを申請する' }).click();
  await expect(card.locator('.company')).toHaveText(COMPANY);
  await expect(card.locator('.operation')).toHaveText('旧会員の紐付け');
  await expect(card).toContainText(
    'この企業で確認された旧会員を、この割符のアカウントに結び付けます。',
  );
  await expect(card).toContainText('P0 では、結び付けた後に付け替えることはできません。');
  await expect(card).toContainText('企業に、元の会員への知らせを依頼します。');
  await expect(card.locator('.responsibility-note')).toHaveText(RESPONSIBILITY_NOTE);
  await expect(page.getByRole('button', { name: '心当たりがない' })).toBeVisible();
  await expect(card).not.toContainText('元の会員に知らせました');
  await page.getByRole('button', { name: '承認する' }).click();
  await expect(page.locator('#notice')).toContainText('旧会員の引き継ぎを申請しました。');

  // ---- 待機の知らせ（SET）と、旧会員の側の知らせ ----
  await deliverSets();
  await verifyLegacy(page.context(), legacy);
  await page.goto(`${demoOrigin}/legacy`);
  await expect(page.locator('#legacy-notice')).toContainText('引き継ぐ申請が出ています');

  // ---- 24時間の後の最終の確認（割符の /initial-link。最終の承認。警告文 I と「取り消す」） ----
  clock += 24 * HOUR + 1000;
  await verifyLegacy(page.context(), legacy);
  await page.goto(`${demoOrigin}/legacy`);
  await page.getByRole('button', { name: '割符で確認して、引き継ぎを確定する' }).click();
  await expect(card.locator('.operation')).toHaveText('旧会員の紐付け（最終の確認）');
  await expect(card).toContainText(
    '待機が終わりました。承認すると、旧会員がこの割符のアカウントに結び付きます。',
  );
  await expect(card).toContainText('P0 では、結び付けた後に付け替えることはできません。');
  await expect(card.locator('.responsibility-note')).toHaveText(RESPONSIBILITY_NOTE);
  await expect(page.getByRole('button', { name: '取り消す' })).toBeVisible();
  await expect(card.locator('.company')).toBeFocused();
  await page.getByRole('button', { name: '承認する' }).click();
  await expect(page.locator('#notice')).toContainText(
    '旧会員を、この割符のアカウントに引き継ぎました。',
  );
  await expect(page.locator('#legacy-linked')).toBeVisible();

  expect(problems, 'CSP 違反やスクリプトのエラーがない').toEqual([]);
});
