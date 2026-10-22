// 捨てスパイク1の E2E：CDP の仮想認証器で、パスキーの登録とログインを通す。
// plan 11章：該当なし（M3 で本実装のテストに置き換える）
//
// どのテストも、先頭のコメントに漏えいシナリオの形式（攻撃者が持っている情報／試す経路／期待する結果）で
// 狙いを書く。サーバーは spikes/passkey/server.ts（playwright.config.ts の webServer が起動する）。
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { type CDPSession, expect, type Page, type Request, test } from '@playwright/test';
import {
  COSEALG,
  cose,
  decodeAttestationObject,
  decodeCredentialPublicKey,
  isoBase64URL,
  isoUint8Array,
  parseAuthenticatorData,
  toHash,
  verifySignature,
} from '@simplewebauthn/server/helpers';

const port = Number(process.env.SPIKE_PASSKEY_PORT ?? '4101');
test.use({ baseURL: `http://localhost:${port}` });

type VirtualAuthenticator = { cdp: CDPSession; authenticatorId: string };

type RegistrationRequestBody = {
  ceremonyId: string;
  response: {
    id: string;
    response: { attestationObject: string; publicKeyAlgorithm?: number };
    clientExtensionResults: { credProps?: { rk?: boolean } };
  };
};

type AuthenticationRequestBody = {
  ceremonyId: string;
  response: {
    id: string;
    response: {
      authenticatorData: string;
      clientDataJSON: string;
      signature: string;
      userHandle?: string;
    };
  };
};

type OptionsResponseBody = {
  ceremonyId: string;
  options: Record<string, unknown>;
};

const statusOf = (page: Page) => page.getByRole('status');

async function addVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
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

async function credentialsOf(authenticator: VirtualAuthenticator) {
  const { credentials } = await authenticator.cdp.send('WebAuthn.getCredentials', {
    authenticatorId: authenticator.authenticatorId,
  });
  return credentials;
}

function isPath(path: string) {
  return (request: Request) => new URL(request.url()).pathname === path;
}

// ボタンを押し、指定した経路へのリクエストをつかまえる。
async function clickAndCapture(page: Page, buttonName: string, path: string): Promise<Request> {
  const [request] = await Promise.all([
    page.waitForRequest(isPath(path)),
    page.getByRole('button', { name: buttonName }).click(),
  ]);
  return request;
}

async function statusCodeOf(request: Request): Promise<number | undefined> {
  return (await request.response())?.status();
}

async function register(page: Page): Promise<RegistrationRequestBody> {
  const request = await clickAndCapture(page, 'パスキーを登録', '/register/verify');
  await expect(statusOf(page)).toHaveText('登録しました');
  expect(await statusCodeOf(request)).toBe(200);
  return request.postDataJSON() as RegistrationRequestBody;
}

function parseRegistration(body: RegistrationRequestBody) {
  const attestationObject = decodeAttestationObject(
    isoBase64URL.toBuffer(body.response.response.attestationObject),
  );
  const authData = parseAuthenticatorData(attestationObject.get('authData'));
  if (authData.credentialPublicKey === undefined || authData.aaguid === undefined) {
    throw new Error('登録の応答に資格情報の公開鍵がない');
  }
  const publicKey = decodeCredentialPublicKey(authData.credentialPublicKey);
  return {
    fmt: attestationObject.get('fmt'),
    attStmtSize: attestationObject.get('attStmt').size,
    flags: authData.flags,
    counter: authData.counter,
    aaguid: isoUint8Array.toHex(authData.aaguid),
    alg: publicKey.get(cose.COSEKEYS.alg),
    credentialPublicKey: authData.credentialPublicKey,
  };
}

// テストの側で、アサーションの署名を自分で確かめる（拒否の理由が署名ではないことを示すため）。
async function assertionSignatureIsValid(
  body: AuthenticationRequestBody,
  credentialPublicKey: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const authenticatorData = isoBase64URL.toBuffer(body.response.response.authenticatorData);
  const clientDataHash = await toHash(isoBase64URL.toBuffer(body.response.response.clientDataJSON));
  return verifySignature({
    signature: isoBase64URL.toBuffer(body.response.response.signature),
    data: isoUint8Array.concat([authenticatorData, clientDataHash]),
    credentialPublicKey,
  });
}

function assertionFlags(body: AuthenticationRequestBody) {
  return parseAuthenticatorData(isoBase64URL.toBuffer(body.response.response.authenticatorData));
}

// CDP の binary は標準の base64、WebAuthn の JSON は base64url。
const base64ToBase64url = (value: string) => Buffer.from(value, 'base64').toString('base64url');
const base64urlToBase64 = (value: string) => Buffer.from(value, 'base64url').toString('base64');

// ページを開き、CSP や Trusted Types の違反、捕まえていない例外がないことを、テストの終わりに確かめる。
// サーバーが 4xx を返したときの「Failed to load resource」は、拒否を確かめるテストで必ず出るので除く。
const it = test.extend<{ openedPage: Page }>({
  openedPage: async ({ page }, use) => {
    const problems: string[] = [];
    page.on('pageerror', (error) => problems.push(`pageerror: ${error.name}: ${error.message}`));
    page.on('console', (message) => {
      if (message.type() !== 'error') return;
      if (
        /^Failed to load resource: the server responded with a status of 4\d\d/.test(message.text())
      ) {
        return;
      }
      problems.push(`console: ${message.text()}`);
    });
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'パスキーを登録' })).toBeEnabled();
    await use(page);
    expect(problems, 'CSP 違反やスクリプトのエラーがない').toEqual([]);
  },
});

it('(a) 登録してからログインできる。認証器には発見可能な資格情報がちょうど1つ残る', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：なし（正規の利用者の基本の流れ。ほかのテストの前提を確かめる）
  // 試す経路：POST /register/options → navigator.credentials.create → POST /register/verify、
  //   POST /login/options → navigator.credentials.get（allowCredentials なし）→ POST /login/verify
  // 期待する結果：登録もログインも 200。選択肢は不変条件どおり（ES256 と RS256 だけ、UV と
  //   発見可能な資格情報が必須、アテステーションは none、user.name は乱数のラベル）。
  const authenticator = await addVirtualAuthenticator(page);

  const [registerOptionsResponse] = await Promise.all([
    page.waitForResponse((response) => isPath('/register/options')(response.request())),
    clickAndCapture(page, 'パスキーを登録', '/register/verify'),
  ]);
  await expect(statusOf(page)).toHaveText('登録しました');
  const registerOptions = ((await registerOptionsResponse.json()) as OptionsResponseBody).options;
  expect(registerOptions.pubKeyCredParams).toEqual([
    { alg: COSEALG.ES256, type: 'public-key' },
    { alg: COSEALG.RS256, type: 'public-key' },
  ]);
  expect(registerOptions.authenticatorSelection).toEqual({
    residentKey: 'required',
    requireResidentKey: true,
    userVerification: 'required',
  });
  expect(registerOptions.attestation).toBe('none');
  const user = registerOptions.user as { name: string; displayName: string };
  expect(user.name).toMatch(/^spike-[0-9a-f]{8}$/);
  expect(user.displayName).toBe(user.name);

  const credentials = await credentialsOf(authenticator);
  expect(credentials).toHaveLength(1);
  const [credential] = credentials;
  expect(credential?.isResidentCredential).toBe(true);
  expect(credential?.rpId).toBe('localhost');
  expect(credential?.userName).toBe(user.name);

  const [loginOptionsResponse] = await Promise.all([
    page.waitForResponse((response) => isPath('/login/options')(response.request())),
    clickAndCapture(page, 'パスキーでログイン', '/login/verify'),
  ]);
  await expect(statusOf(page)).toHaveText('ログインしました');
  await expect(statusOf(page)).toHaveAttribute('data-outcome', 'logged-in');
  const loginOptions = ((await loginOptionsResponse.json()) as OptionsResponseBody).options;
  expect(loginOptions.userVerification).toBe('required');
  expect(loginOptions.allowCredentials).toBeUndefined();
  expect(await credentialsOf(authenticator)).toHaveLength(1);
});

it('(a2) 仮想認証器が返す値を記録する（アルゴリズム、UV、BE/BS、AAGUID、カウンター）', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：なし（ADR と plan に書くための事実を、テストで固定する）
  // 試す経路：登録とログインで、ブラウザが送った authenticatorData と attestationObject を読む
  // 期待する結果：fmt は none、アルゴリズムは ES256、UV は立つ、BE と BS は立たない（仮想認証器の既定）。
  //   AAGUID は 0 にならない。カウンターは登録で 1、最初のログインで 2。
  const authenticator = await addVirtualAuthenticator(page);
  const registration = await register(page);
  const parsed = parseRegistration(registration);
  expect(parsed.fmt).toBe('none');
  expect(parsed.attStmtSize).toBe(0);
  expect(parsed.alg).toBe(COSEALG.ES256);
  expect(registration.response.response.publicKeyAlgorithm).toBe(COSEALG.ES256);
  expect(parsed.flags).toMatchObject({ up: true, uv: true, be: false, bs: false, at: true });
  // attestation が none でも、Chrome は AAGUID を 0 にしない（仮想認証器の AAGUID がそのまま届く）。
  // AAGUID は認証器の型番を指すので、サーバーは保存しない。
  expect(parsed.aaguid).toBe('01020304050607080102030405060708');
  // 仮想認証器は、登録の時点でカウンターを 1 にする。
  expect(parsed.counter).toBe(1);
  expect(registration.response.clientExtensionResults.credProps?.rk).toBe(true);

  const loginRequest = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText('ログインしました');
  const assertion = loginRequest.postDataJSON() as AuthenticationRequestBody;
  const flags = assertionFlags(assertion);
  expect(flags.flags).toMatchObject({ up: true, uv: true, be: false, bs: false });
  expect(flags.counter).toBe(2);
  const [credential] = await credentialsOf(authenticator);
  expect(assertion.response.response.userHandle).toBe(
    base64ToBase64url(credential?.userHandle ?? ''),
  );
});

it('(b) 認証器での利用者の確認（UV）が失敗すると、ブラウザの段階でログインが止まる', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：利用者の端末（パスキーの入った認証器）だけ。生体認証や PIN は通せない
  // 試す経路：WebAuthn.setUserVerified { isUserVerified: false } にして「パスキーでログイン」を押す
  // 期待する結果：userVerification が required なので、ブラウザが NotAllowedError で止め、
  //   POST /login/verify は送られない（CLAUDE.md 1(b)：UV 付きのアサーションだけが根拠）。
  //   UV を戻すと同じ認証器でログインできる（止まった理由が UV だけであることの対照）。
  const authenticator = await addVirtualAuthenticator(page);
  await register(page);
  await authenticator.cdp.send('WebAuthn.setUserVerified', {
    authenticatorId: authenticator.authenticatorId,
    isUserVerified: false,
  });

  const verifyRequests: Request[] = [];
  page.on('request', (request) => {
    if (isPath('/login/verify')(request)) verifyRequests.push(request);
  });
  const [optionsRequest] = await Promise.all([
    page.waitForRequest(isPath('/login/options')),
    page.getByRole('button', { name: 'パスキーでログイン' }).click(),
  ]);
  expect(await statusCodeOf(optionsRequest)).toBe(200);
  await expect(statusOf(page)).toHaveText(
    'エラー: 端末での確認が完了しませんでした。もう一度お試しください。',
  );
  await expect(statusOf(page)).toHaveAttribute(
    'data-outcome',
    'authenticator-error:NotAllowedError',
  );
  expect(verifyRequests).toHaveLength(0);

  await authenticator.cdp.send('WebAuthn.setUserVerified', {
    authenticatorId: authenticator.authenticatorId,
    isUserVerified: true,
  });
  await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText('ログインしました');
});

it('(b2) UV のビットが立っていない、署名は正しいアサーションを、サーバーが拒否する', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：利用者の端末。ブラウザか認証器が UV を確かめずにアサーションを作る
  // 試す経路：WebAuthn.setResponseOverrideBits { isBadUV: true } で、UV のビットを 0 にした
  //   アサーションを POST /login/verify に送らせる
  // 期待する結果：サーバーが 401 で拒否する。テストの側で、UV が 0 であることと、署名そのものは
  //   正しいことを確かめ、拒否の理由が UV だけであることを示す。
  const authenticator = await addVirtualAuthenticator(page);
  const registration = await register(page);
  const { credentialPublicKey } = parseRegistration(registration);
  await authenticator.cdp.send('WebAuthn.setResponseOverrideBits', {
    authenticatorId: authenticator.authenticatorId,
    isBadUV: true,
  });

  const request = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText(
    'エラー: ログインできませんでした。もう一度お試しください。',
  );
  await expect(statusOf(page)).toHaveAttribute('data-outcome', 'server-rejected');
  expect(await statusCodeOf(request)).toBe(401);
  const assertion = request.postDataJSON() as AuthenticationRequestBody;
  expect(assertion.response.id).toBe(registration.response.id);
  expect(assertionFlags(assertion).flags).toMatchObject({ up: true, uv: false });
  expect(await assertionSignatureIsValid(assertion, credentialPublicKey)).toBe(true);
});

it('(c) 登録していない資格情報のアサーションは、userHandle が本物でも拒否する', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：利用者の userHandle（秘密ではない値として扱う）と、自分で作った鍵
  // 試す経路：別の認証器に、未登録の資格情報 ID と自分の鍵、利用者の userHandle を入れ、
  //   POST /login/verify に送る
  // 期待する結果：資格情報 ID が見つからないので 401。userHandle など、ほかの手がかりで
  //   アカウントを探して受け入れることはない。
  const victimAuthenticator = await addVirtualAuthenticator(page);
  const registration = await register(page);
  const [victimCredential] = await credentialsOf(victimAuthenticator);
  if (victimCredential?.userHandle === undefined) throw new Error('userHandle がない');
  await victimAuthenticator.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: victimAuthenticator.authenticatorId,
  });

  const attackerAuthenticator = await addVirtualAuthenticator(page);
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const attackerCredentialId = randomBytes(32);
  await attackerAuthenticator.cdp.send('WebAuthn.addCredential', {
    authenticatorId: attackerAuthenticator.authenticatorId,
    credential: {
      credentialId: attackerCredentialId.toString('base64'),
      isResidentCredential: true,
      rpId: 'localhost',
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      userHandle: victimCredential.userHandle,
      signCount: 0,
    },
  });

  const request = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText(
    'エラー: ログインできませんでした。もう一度お試しください。',
  );
  expect(await statusCodeOf(request)).toBe(401);
  const assertion = request.postDataJSON() as AuthenticationRequestBody;
  expect(assertion.response.id).toBe(attackerCredentialId.toString('base64url'));
  expect(assertion.response.id).not.toBe(registration.response.id);
  expect(assertion.response.response.userHandle).toBe(
    base64ToBase64url(victimCredential.userHandle),
  );
  expect(assertionFlags(assertion).flags).toMatchObject({ up: true, uv: true });
});

it('(c2) 資格情報 ID と鍵が本物でも、userHandle が持ち主と違えば拒否する', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：利用者の資格情報 ID と秘密鍵の複製（userHandle の結び付きを確かめるための想定）
  // 試す経路：複製した鍵に、別の userHandle を付けて別の認証器に入れ、POST /login/verify に送る
  // 期待する結果：401（WebAuthn L3 7.2 の手順6。ライブラリは userHandle を確かめないので、
  //   サーバーが自分で確かめる）。対照として、正しい userHandle を付けた複製では 200 になる
  //   （拒否の理由が userHandle だけであることを示す）。
  const victimAuthenticator = await addVirtualAuthenticator(page);
  await register(page);
  const [victimCredential] = await credentialsOf(victimAuthenticator);
  if (victimCredential?.userHandle === undefined) throw new Error('userHandle がない');
  await victimAuthenticator.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: victimAuthenticator.authenticatorId,
  });

  const cloneAuthenticator = await addVirtualAuthenticator(page);
  const addClone = (userHandle: string, signCount: number) =>
    cloneAuthenticator.cdp.send('WebAuthn.addCredential', {
      authenticatorId: cloneAuthenticator.authenticatorId,
      credential: {
        credentialId: victimCredential.credentialId,
        isResidentCredential: true,
        rpId: 'localhost',
        privateKey: victimCredential.privateKey,
        userHandle,
        // カウンターで拒否されないよう、十分に大きくする。
        signCount,
      },
    });

  await addClone(randomBytes(32).toString('base64'), victimCredential.signCount + 10);
  const rejected = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText(
    'エラー: ログインできませんでした。もう一度お試しください。',
  );
  expect(await statusCodeOf(rejected)).toBe(401);
  const rejectedAssertion = rejected.postDataJSON() as AuthenticationRequestBody;
  expect(rejectedAssertion.response.id).toBe(base64ToBase64url(victimCredential.credentialId));
  expect(rejectedAssertion.response.response.userHandle).not.toBe(
    base64ToBase64url(victimCredential.userHandle),
  );

  await cloneAuthenticator.cdp.send('WebAuthn.clearCredentials', {
    authenticatorId: cloneAuthenticator.authenticatorId,
  });
  await addClone(victimCredential.userHandle, victimCredential.signCount + 20);
  const accepted = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText('ログインしました');
  expect(await statusCodeOf(accepted)).toBe(200);
});

it('(d) 許可リストの外のアルゴリズム（EdDSA）の資格情報は、登録で拒否する。RS256 は受け付ける', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：自分の端末。登録の選択肢を書き換えられる（ブラウザの拡張などを想定）
  // 試す経路：POST /register/options の応答の pubKeyCredParams を EdDSA（-8）だけに書き換えて、
  //   作られた資格情報を POST /register/verify に送る
  // 期待する結果：400 で拒否する（不変条件9：WebAuthn は ES256 と RS256 だけ）。対照として、
  //   RS256（-257）だけに書き換えたときは 200 で登録できる。
  const authenticator = await addVirtualAuthenticator(page);
  let offeredAlgorithm: number = COSEALG.EdDSA;
  await page.route('**/register/options', async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as OptionsResponseBody;
    body.options.pubKeyCredParams = [{ alg: offeredAlgorithm, type: 'public-key' }];
    await route.fulfill({ response, json: body });
  });

  const rejected = await clickAndCapture(page, 'パスキーを登録', '/register/verify');
  await expect(statusOf(page)).toHaveText('エラー: 登録できませんでした。もう一度お試しください。');
  expect(await statusCodeOf(rejected)).toBe(400);
  expect(parseRegistration(rejected.postDataJSON() as RegistrationRequestBody).alg).toBe(
    COSEALG.EdDSA,
  );

  offeredAlgorithm = COSEALG.RS256;
  const registration = await register(page);
  expect(parseRegistration(registration).alg).toBe(COSEALG.RS256);
  expect(await credentialsOf(authenticator)).toHaveLength(2);

  // 拒否した EdDSA の資格情報は認証器に残るが、サーバーは知らないのでログインには使えない。
  // RS256 の資格情報を選ばせるため、EdDSA の資格情報を認証器から消してからログインする。
  await authenticator.cdp.send('WebAuthn.removeCredential', {
    authenticatorId: authenticator.authenticatorId,
    credentialId: base64urlToBase64(
      (rejected.postDataJSON() as RegistrationRequestBody).response.id,
    ),
  });
  const login = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText('ログインしました');
  expect((login.postDataJSON() as AuthenticationRequestBody).response.id).toBe(
    registration.response.id,
  );
});

it('(d2) 証明書（x5c）付きのアテステーションは、検証に渡す前に拒否する', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：自分の端末。登録の応答のアテステーションを選べる
  // 試す経路：POST /register/options の応答の attestation を direct に書き換え、仮想認証器に
  //   x5c 付きの packed を作らせて、POST /register/verify に送る
  // 期待する結果：400。サーバーは fmt が none 以外のものを、ライブラリの検証（証明書の失効確認で
  //   外へ fetch しうる）に渡さない（不変条件7）。
  const authenticator = await addVirtualAuthenticator(page);
  await page.route('**/register/options', async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as OptionsResponseBody;
    body.options.attestation = 'direct';
    await route.fulfill({ response, json: body });
  });

  const request = await clickAndCapture(page, 'パスキーを登録', '/register/verify');
  await expect(statusOf(page)).toHaveText('エラー: 登録できませんでした。もう一度お試しください。');
  expect(await statusCodeOf(request)).toBe(400);
  const attestationObject = decodeAttestationObject(
    isoBase64URL.toBuffer(
      (request.postDataJSON() as RegistrationRequestBody).response.response.attestationObject,
    ),
  );
  expect(attestationObject.get('fmt')).toBe('packed');
  expect(attestationObject.get('attStmt').get('x5c')).toHaveLength(1);
  // 認証器には資格情報が残るが、サーバーは知らないので、ログインには使えない。
  expect(await credentialsOf(authenticator)).toHaveLength(1);
  const login = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText(
    'エラー: ログインできませんでした。もう一度お試しください。',
  );
  expect(await statusCodeOf(login)).toBe(401);
});

it('(e) 一度使ったアサーションを送り直しても、ログインできない', async ({ openedPage: page }) => {
  // 攻撃者が持っている情報：利用者が送ったアサーションと儀式の ID（通信やログからの漏えいを想定）
  // 試す経路：成功した POST /login/verify の本文を、そのまま送り直す。新しい儀式の ID に差し替えても送る
  // 期待する結果：どちらも 401。チャレンジは使い捨てで、別の儀式のチャレンジとは一致しない。
  await addVirtualAuthenticator(page);
  await register(page);
  const login = await clickAndCapture(page, 'パスキーでログイン', '/login/verify');
  await expect(statusOf(page)).toHaveText('ログインしました');
  const captured = login.postDataJSON() as AuthenticationRequestBody;
  const headers = { origin: `http://localhost:${port}` };

  const replayed = await page.request.post('/login/verify', { data: captured, headers });
  expect(replayed.status()).toBe(401);

  const fresh = await page.request.post('/login/options', { headers });
  expect(fresh.status()).toBe(200);
  const { ceremonyId } = (await fresh.json()) as OptionsResponseBody;
  const rebound = await page.request.post('/login/verify', {
    data: { ...captured, ceremonyId },
    headers,
  });
  expect(rebound.status()).toBe(401);
});

it('(f) どの応答にも、CSP などの見出しが付く。別の Host や別のオリジンからの POST は断る', async ({
  openedPage: page,
}) => {
  // 攻撃者が持っている情報：利用者を誘導できる別のサイト（XSS、埋め込み、DNS リバインディングを狙う）
  // 試す経路：HTML、スクリプト、API、404、拒否の応答の見出しを読む。Host を書き換えた GET と、
  //   Origin のない POST を送る
  // 期待する結果：すべての応答に、Trusted Types を必須にした CSP、nosniff、no-referrer、no-store が付く。
  //   Host が違えば 421、Origin が違えば 403。
  const expectSecurityHeaders = (headers: Record<string, string>) => {
    expect(headers['content-security-policy']).toBe(
      [
        "default-src 'none'",
        "script-src 'self'",
        "connect-src 'self'",
        "img-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
        "trusted-types 'none'",
      ].join('; '),
    );
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['cache-control']).toBe('no-store');
  };
  const origin = `http://localhost:${port}`;
  const responses = [
    await page.request.get('/'),
    await page.request.get('/app.js'),
    await page.request.get('/vendor/simplewebauthn-browser.js'),
    await page.request.get('/no-such-path'),
    await page.request.post('/login/options', { headers: { origin } }),
    await page.request.post('/login/verify', { headers: { origin }, data: {} }),
  ];
  expect(responses.map((response) => response.status())).toEqual([200, 200, 200, 404, 200, 400]);
  for (const response of responses) {
    expectSecurityHeaders(response.headers());
  }

  const wrongHost = await page.request.get('/', { headers: { host: 'attacker.example' } });
  expect(wrongHost.status()).toBe(421);
  expectSecurityHeaders(wrongHost.headers());
  const noOrigin = await page.request.post('/register/options');
  expect(noOrigin.status()).toBe(403);
  const otherOrigin = await page.request.post('/register/options', {
    headers: { origin: 'http://localhost:1' },
  });
  expect(otherOrigin.status()).toBe(403);
});
