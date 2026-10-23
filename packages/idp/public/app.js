// 割符の PWA（M3 の土台）。ブラウザで動く。
// - 画面は DOM の API（createElement、textContent）だけで組む。文字列を HTML として解釈させない（Trusted Types は 'none'）。
// - 判断はすべてサーバーで行う。ここには資格情報も鍵も置かない（plan 2章「ブラウザ側」）。
// - 文言は DESIGN.md 4章（です・ます調、専門用語を出さない、登録済みかどうかが分かる書き方をしない）。

(() => {
  const root = document.getElementById('app');
  const view = document.getElementById('view');
  const heading = document.getElementById('heading');
  const company = document.getElementById('company');
  if (!root || !view || !heading) return;
  const { startAuthentication, startRegistration } = window.SimpleWebAuthnBrowser;

  const DATE = new Intl.DateTimeFormat('ja-JP', {
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props ?? {})) {
      if (key === 'onclick') node.addEventListener('click', value);
      else if (key === 'onsubmit') node.addEventListener('submit', value);
      else if (key === 'className') node.className = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return node;
  }

  function show(...nodes) {
    view.replaceChildren(...nodes);
    heading.focus();
  }

  function status(text) {
    return el('p', { role: 'status', className: 'status' }, text);
  }

  async function call(method, path, body) {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: method === 'GET' ? {} : { 'content-type': 'application/json' },
      body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }
    return { status: response.status, data };
  }

  function failureText(result) {
    if (result.status === 429) return 'しばらく時間をおいてから、もう一度お試しください。';
    return 'パスキーでの確認ができませんでした。もう一度お試しください。';
  }

  /** WebAuthn の儀式を1回行う。optionsPath で選択肢を取り、verifyPath に結果を送る。 */
  async function ceremony(kind, optionsPath, verifyPath) {
    const started = await call('POST', optionsPath);
    if (started.status !== 200) return started;
    let response;
    try {
      response =
        kind === 'register'
          ? await startRegistration({ optionsJSON: started.data.options })
          : await startAuthentication({ optionsJSON: started.data.options });
    } catch {
      return { status: 400, data: {} };
    }
    return call('POST', verifyPath, { ceremonyId: started.data.ceremonyId, response });
  }

  async function stepUp() {
    const result = await ceremony('authenticate', '/api/stepup/options', '/api/stepup/verify');
    return result.status === 200;
  }

  /** step-up が要るときは、パスキーで確かめてから、もう一度送る。 */
  async function withStepUp(method, path, body) {
    let result = await call(method, path, body);
    if (result.status === 401 && result.data.error === 'reauth_required') {
      if (!(await stepUp())) return { status: 401, data: {} };
      result = await call(method, path, body);
    }
    return result;
  }

  // ---- ログインしていないとき ----

  function renderSignedOut(note) {
    show(
      note ? status(note) : null,
      el(
        'div',
        { className: 'actions' },
        el('button', { type: 'button', onclick: login }, 'パスキーでログイン'),
        el('button', { type: 'button', onclick: register }, '割符のアカウントを作る'),
      ),
    );
  }

  async function login() {
    const result = await ceremony('authenticate', '/api/login/options', '/api/login/verify');
    if (result.status === 200) return renderHome();
    renderSignedOut(failureText(result));
  }

  async function register() {
    const result = await ceremony('register', '/api/register/options', '/api/register/verify');
    if (result.status === 200) return renderHome();
    renderSignedOut(failureText(result));
  }

  // ---- ログインした後 ----

  function emailSection(email) {
    const section = el('section', { 'aria-labelledby': 'email-heading' });
    const current = email.registered
      ? `登録済み（${DATE.format(new Date(email.updatedAt))}に更新）`
      : 'まだ登録していません。';
    const input = el('input', {
      type: 'email',
      id: 'email-input',
      name: 'email',
      autocomplete: 'email',
      required: 'required',
    });
    const area = el('div');
    const form = el(
      'form',
      {
        onsubmit: async (event) => {
          event.preventDefault();
          const result = await withStepUp('POST', '/api/email/start', { email: input.value });
          if (result.status === 202) {
            input.value = '';
            area.replaceChildren(codeForm());
          } else if (result.status === 400) {
            area.replaceChildren(status('メールアドレスの形を確かめてください。'));
          } else {
            area.replaceChildren(status(failureText(result)));
          }
        },
      },
      el('label', { for: 'email-input' }, '新しいメールアドレス'),
      input,
      el('button', { type: 'submit' }, '確認コードを送る'),
    );
    section.append(
      el('h2', { id: 'email-heading' }, 'メールアドレス'),
      el('p', {}, current),
      el(
        'p',
        {},
        'メールアドレスは、企業からのメールを届けるためだけに使います。変更すると、前のアドレスには、変更したことだけをお知らせします（操作のためのリンクは入りません）。',
      ),
      form,
      area,
    );
    return section;
  }

  function codeForm() {
    const input = el('input', {
      type: 'text',
      id: 'code-input',
      inputmode: 'numeric',
      autocomplete: 'one-time-code',
      pattern: '[0-9]{8}',
      maxlength: '8',
      required: 'required',
    });
    const note = el('div');
    return el(
      'form',
      {
        onsubmit: async (event) => {
          event.preventDefault();
          const result = await call('POST', '/api/email/confirm', { code: input.value });
          if (result.status === 200) return renderHome('メールアドレスを登録しました。');
          note.replaceChildren(
            status(
              'コードを確かめられませんでした。届いたコードをもう一度入力するか、コードを送り直してください。',
            ),
          );
        },
      },
      status('入力したアドレスに確認コードを送りました。届いた8桁のコードを入力してください。'),
      el('label', { for: 'code-input' }, '確認コード'),
      input,
      el('button', { type: 'submit' }, '確認する'),
      note,
    );
  }

  function passkeySection(passkeys) {
    const list = el('ul', { className: 'passkeys' });
    for (const passkey of passkeys) {
      list.append(
        el(
          'li',
          {},
          el('span', {}, passkey.synced ? '同期パスキー' : '端末固定のパスキー'),
          el('span', {}, `登録：${DATE.format(new Date(passkey.createdAt))}`),
          el(
            'span',
            {},
            passkey.lastUsedAt
              ? `最後に使った日時：${DATE.format(new Date(passkey.lastUsedAt))}`
              : 'まだ使っていません',
          ),
          passkeys.length > 1
            ? el(
                'button',
                {
                  type: 'button',
                  className: 'danger',
                  onclick: async () => {
                    const result = await withStepUp('POST', '/api/passkeys/delete', {
                      id: passkey.id,
                    });
                    if (result.status === 200) {
                      return renderSignedOut(
                        'パスキーを削除しました。もう一度ログインしてください。',
                      );
                    }
                    renderHome(failureText(result));
                  },
                },
                'このパスキーを削除する',
              )
            : null,
        ),
      );
    }
    return el(
      'section',
      { 'aria-labelledby': 'passkey-heading' },
      el('h2', { id: 'passkey-heading' }, 'パスキー'),
      el(
        'p',
        {},
        'パスキーを2つ以上登録し、うち1つは端末固定（セキュリティキーなど）にすることをおすすめします。',
      ),
      list,
      el(
        'button',
        {
          type: 'button',
          onclick: async () => {
            let result = await ceremony(
              'register',
              '/api/passkeys/options',
              '/api/passkeys/verify',
            );
            if (result.status === 401 && result.data.error === 'reauth_required') {
              if (await stepUp()) {
                result = await ceremony(
                  'register',
                  '/api/passkeys/options',
                  '/api/passkeys/verify',
                );
              }
            }
            renderHome(result.status === 200 ? 'パスキーを追加しました。' : failureText(result));
          },
        },
        'パスキーを追加する',
      ),
    );
  }

  function companySection(companies) {
    const list = el('ul', { className: 'companies' });
    for (const entry of companies) {
      list.append(
        el(
          'li',
          {},
          el('span', { className: 'name' }, entry.name),
          entry.alias
            ? el('span', { className: 'alias' }, `連絡用のアドレス：${entry.alias}`)
            : null,
        ),
      );
    }
    return el(
      'section',
      { 'aria-labelledby': 'company-heading' },
      el('h2', { id: 'company-heading' }, '接続している企業'),
      companies.length === 0 ? el('p', {}, 'まだありません。') : list,
    );
  }

  async function renderHome(note) {
    const result = await call('GET', '/api/me');
    if (result.status !== 200) return renderSignedOut(note);
    const me = result.data;
    show(
      note ? status(note) : null,
      emailSection(me.email),
      passkeySection(me.passkeys),
      companySection(me.companies),
      el(
        'button',
        {
          type: 'button',
          onclick: async () => {
            await call('POST', '/api/logout');
            renderSignedOut('ログアウトしました。');
          },
        },
        'ログアウト',
      ),
    );
  }

  // ---- 企業へのログイン（インタラクション） ----

  function go(result) {
    if (result.status === 200 && typeof result.data.redirectTo === 'string') {
      window.location.assign(result.data.redirectTo);
      return true;
    }
    return false;
  }

  function renderInteractionLogin(uid, note) {
    const base = `/interaction/${encodeURIComponent(uid)}`;
    show(
      el('p', {}, 'この企業に、割符のパスキーでログインします。'),
      note ? status(note) : null,
      el(
        'div',
        { className: 'actions' },
        el(
          'button',
          {
            type: 'button',
            onclick: async () => {
              const result = await ceremony(
                'authenticate',
                `${base}/login/options`,
                `${base}/login/verify`,
              );
              if (!go(result)) renderInteractionLogin(uid, failureText(result));
            },
          },
          'パスキーでログイン',
        ),
        el(
          'button',
          {
            type: 'button',
            onclick: async () => {
              const result = await ceremony(
                'register',
                `${base}/register/options`,
                `${base}/register/verify`,
              );
              if (!go(result)) renderInteractionLogin(uid, failureText(result));
            },
          },
          '割符のアカウントを作る',
        ),
        el(
          'button',
          {
            type: 'button',
            onclick: async () => {
              go(await call('POST', `${base}/abort`));
            },
          },
          'やめる',
        ),
      ),
    );
  }

  function renderConsent(uid) {
    const base = `/interaction/${encodeURIComponent(uid)}`;
    const decide = (decision) => async () => {
      if (!go(await call('POST', `${base}/consent`, { decision }))) {
        show(status('処理を続けられませんでした。企業の画面から、もう一度お試しください。'));
      }
    };
    show(
      el('p', {}, 'この企業に接続しますか？接続すると、次のものだけを企業に渡します。'),
      el(
        'ul',
        {},
        el('li', {}, 'この企業だけで使う ID'),
        el(
          'li',
          {},
          'この企業だけで使う連絡用のメールアドレス（本物のメールアドレスは渡しません）',
        ),
      ),
      el(
        'div',
        { className: 'actions equal' },
        el('button', { type: 'button', onclick: decide('connect') }, '接続する'),
        el('button', { type: 'button', onclick: decide('decline') }, '接続しない'),
      ),
    );
  }

  if (root.dataset.page === 'interaction') {
    const uid = root.dataset.uid ?? '';
    if (company) company.setAttribute('aria-label', '接続先の企業');
    if (root.dataset.prompt === 'consent') renderConsent(uid);
    else renderInteractionLogin(uid);
  } else {
    void renderHome();
  }
})();
