// 捨てスパイク1のブラウザ側。M3 で packages/idp に置き換える。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
// 文字は textContent でだけ書く（Trusted Types を必須にしているので、innerHTML などは使えない）。
// @simplewebauthn/browser は、先に読み込んだ UMD 版がグローバルに置く。
const { startRegistration, startAuthentication } = globalThis.SimpleWebAuthnBrowser;

const statusElement = document.getElementById('status');
const registerButton = document.getElementById('register');
const loginButton = document.getElementById('login');

// ブラウザや認証器が返すエラーの名前のうち、画面の分岐に使うもの。これ以外は「その他」として扱う。
const KNOWN_ERROR_NAMES = new Set([
  'NotAllowedError',
  'InvalidStateError',
  'NotSupportedError',
  'SecurityError',
  'AbortError',
  'ConstraintError',
  'UnknownError',
]);

class ServerRejected extends Error {}

function showStatus(text, outcome) {
  statusElement.textContent = text;
  // テストが結果を見分けるための印。値は決まった語だけにする。
  statusElement.dataset.outcome = outcome;
}

async function postJson(path, body) {
  const init = {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
  };
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new ServerRejected();
  }
  return response.json();
}

function showError(error, serverRejectedText) {
  if (error instanceof ServerRejected) {
    showStatus(`エラー: ${serverRejectedText}`, 'server-rejected');
    return;
  }
  const name =
    typeof error?.name === 'string' && KNOWN_ERROR_NAMES.has(error.name) ? error.name : '';
  if (name === 'NotAllowedError') {
    showStatus(
      'エラー: 端末での確認が完了しませんでした。もう一度お試しください。',
      'authenticator-error:NotAllowedError',
    );
    return;
  }
  showStatus(
    'エラー: 処理を完了できませんでした。もう一度お試しください。',
    name === '' ? 'error' : `authenticator-error:${name}`,
  );
}

async function withButtonsDisabled(task) {
  registerButton.disabled = true;
  loginButton.disabled = true;
  try {
    await task();
  } finally {
    registerButton.disabled = false;
    loginButton.disabled = false;
  }
}

async function register() {
  showStatus('登録しています…', 'pending');
  try {
    const { ceremonyId, options } = await postJson('/register/options');
    const response = await startRegistration({ optionsJSON: options });
    await postJson('/register/verify', { ceremonyId, response });
    showStatus('登録しました', 'registered');
  } catch (error) {
    showError(error, '登録できませんでした。もう一度お試しください。');
  }
}

async function login() {
  showStatus('ログインしています…', 'pending');
  try {
    const { ceremonyId, options } = await postJson('/login/options');
    const response = await startAuthentication({ optionsJSON: options });
    await postJson('/login/verify', { ceremonyId, response });
    showStatus('ログインしました', 'logged-in');
  } catch (error) {
    showError(error, 'ログインできませんでした。もう一度お試しください。');
  }
}

registerButton.addEventListener('click', () => withButtonsDisabled(register));
loginButton.addEventListener('click', () => withButtonsDisabled(login));
