// 旧会員の引き継ぎの画面：旧パスキーの確かめ（WebAuthn）。それ以外の画面は、JavaScript を使わない。
// 値は textContent だけで出す。失敗のときは、固定の文だけを出す。
(() => {
  const status = document.getElementById('legacy-status');
  const say = (text) => {
    if (status) status.textContent = text;
  };

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    return { status: response.status, data: await response.json().catch(() => ({})) };
  }

  async function run(kind, optionsPath, verifyPath) {
    try {
      const options = await post(optionsPath);
      if (options.status !== 200) return false;
      const response =
        kind === 'create'
          ? await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options.data })
          : await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options.data });
      return (await post(verifyPath, { response })).status === 200;
    } catch {
      return false;
    }
  }

  document.getElementById('legacy-verify')?.addEventListener('click', async () => {
    if (await run('get', '/legacy/options', '/legacy/verify')) window.location.assign('/legacy');
    else say('旧パスキーで確かめられませんでした。');
  });

  document.getElementById('legacy-seed')?.addEventListener('click', async () => {
    say(
      (await run('create', '/legacy/demo/options', '/legacy/demo/verify'))
        ? 'デモ用の旧会員と旧パスキーを用意しました。'
        : '用意できませんでした。',
    );
  });
})();
