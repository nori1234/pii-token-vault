// 割符の PWA（M3 の土台）と、承認用のオリジンの承認待ちの画面（M6。ADR 0023）と、窓口での承認の画面と窓口の作成の
// 項目（M7。ADR 0026）。ブラウザで動く。
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
  /** 受信箱を読み直す間隔（ADR 0023。サーバー側の受信箱を正とし、ポーリングで受け取る）。 */
  const INBOX_POLL_MS = 30_000;

  // 固定の警告文（DESIGN.md 3章）。文言は変えない。〈〉の部分だけを、登録簿の企業名と、割符が決めた操作の種類で埋める。
  // サーバーからは警告文の ID だけを受け取る（FixedWarning は任意の文字列を受け取らない。DESIGN.md 6章）。
  const WARNINGS = Object.freeze({
    'A-1':
      'あなたが自分から〈企業名〉の公式窓口に連絡した場合だけ、操作と担当者を確認して承認してください。相手からかかってきた電話で求められた場合は、承認せず、公式窓口へ連絡し直してください。',
    'A-2':
      'この確認は、あなたが今この端末で〈操作の種類〉をしようとしている場合だけ承認してください。電話やメッセージで頼まれて承認してはいけません。',
    E: 'あなたが窓口に連絡していないのに、この通知が届いた場合は、取り消してください。割符や企業が電話で『取り消さないでください』と頼むことはありません。',
  });

  /** 窓口の作成の項目の状態（ADR 0026 の O-68）。未着や期限切れだけで「作成されませんでした」とは出さない。 */
  const DESK_STATE_TEXT = Object.freeze({
    approving: '承認の処理中です',
    awaiting_notice: '承認済み（作成の知らせ待ち）',
    created: '作成されました',
    cancel_requested: '取消を受け付けました（企業の確認待ち）',
    cancelled: '取り消しました',
    not_created: '作成されませんでした',
    closed: '受付を終えました',
    unknown: '状態を確かめられませんでした。しばらくしてから、もう一度お試しください。',
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

  /** ExpiryText（DESIGN.md 4章・6章）：絶対時刻と、分単位の相対時刻。秒は出さない（急がせない。原則7）。 */
  function expiryText(iso) {
    const at = new Date(iso);
    const minutes = Math.max(0, Math.ceil((at.getTime() - Date.now()) / 60_000));
    const relative =
      minutes >= 120 ? `あと約${Math.round(minutes / 60)}時間` : `あと約${minutes}分`;
    return `${DATE.format(at)} まで（${relative}）`;
  }

  let warningCount = 0;

  /** FixedWarning（DESIGN.md 6章）：警告文の ID と、埋める値（企業名、操作の種類）だけを受け取る。 */
  function fixedWarning(id, params) {
    const template = WARNINGS[id];
    if (template === undefined) return null;
    // 置き換えには関数を渡す（企業名に $& などがあっても、そのまま文字として出す）。
    const text = template
      .replace('〈企業名〉', () => params.company ?? '')
      .replace('〈操作の種類〉', () => params.operation ?? '');
    warningCount += 1;
    const headingId = `warning-${warningCount}`;
    return el(
      'section',
      { className: 'fixed-warning', role: 'note', 'aria-labelledby': headingId },
      el('h3', { id: headingId }, el('span', { 'aria-hidden': 'true' }, '⚠ '), 'ご注意'),
      el('p', {}, text),
    );
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

  /**
   * WebAuthn の儀式を1回行う。optionsPath で選択肢を取り（body を添えて）、verifyPath に結果を送る
   * （verifyBody があれば、それも添える）。
   */
  async function ceremony(kind, optionsPath, verifyPath, body, verifyBody) {
    const started = await call('POST', optionsPath, body);
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
    return call('POST', verifyPath, {
      ...(verifyBody ?? {}),
      ceremonyId: started.data.ceremonyId,
      response,
    });
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

  function approvalOriginUrl() {
    try {
      const url = new URL(root.dataset.approvalOrigin ?? '');
      return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : null;
    } catch {
      return null;
    }
  }

  const STATE_TEXT = Object.freeze({
    approved: '承認しました',
    denied: '拒否しました',
    expired: '期限が切れました',
  });

  /** 窓口の作成の項目の1行（企業名、固定の操作型、状態、取消期限）。 */
  function deskItemLines(item) {
    return [
      el('strong', {}, item.company),
      el('span', {}, item.operation),
      el('span', {}, DESK_STATE_TEXT[item.state] ?? DESK_STATE_TEXT.unknown),
      item.state === 'created' && item.cancelDeadline
        ? el('span', {}, `取消期限：${expiryText(item.cancelDeadline)}`)
        : null,
    ];
  }

  /** 受信箱（DESIGN.md 2章）：承認待ちと知らせの一覧と、承認待ちの期限。文言はサーバーの型が決めたものだけ。 */
  function inboxList(inbox) {
    const desk = inbox.desk ?? [];
    if (inbox.items.length === 0 && desk.length === 0) return el('p', {}, 'お知らせはありません。');
    const approvalUrl = approvalOriginUrl();
    const list = el('ul', { className: 'inbox' });
    // 窓口の作成の項目。取り消すのは、承認用のオリジンの画面だけ（パスキーで確かめる。ADR 0026 の O-68）。
    for (const item of desk) {
      list.append(
        el(
          'li',
          {},
          ...deskItemLines(item),
          item.state === 'created' ? fixedWarning(item.warning, { company: item.company }) : null,
          item.cancellable && approvalUrl
            ? el('a', { href: approvalUrl }, '取り消す（確認待ちの画面を開く）')
            : null,
        ),
      );
    }
    for (const item of inbox.items) {
      if (item.kind === 'approval') {
        const pending = item.state === 'pending';
        list.append(
          el(
            'li',
            {},
            el('strong', {}, item.title),
            el('span', {}, item.company),
            el('span', {}, item.operation),
            pending
              ? el('span', {}, `期限：${expiryText(item.expiresAt)}`)
              : el('span', { className: 'muted' }, STATE_TEXT[item.state] ?? ''),
            pending && approvalUrl ? el('a', { href: approvalUrl }, '確認待ちの画面を開く') : null,
          ),
        );
        continue;
      }
      list.append(
        el(
          'li',
          {},
          el('strong', {}, item.title),
          ...item.lines.map((line) => el('span', {}, `${line.label}：${line.value}`)),
          el('span', { className: 'muted' }, DATE.format(new Date(item.createdAt))),
          item.state === 'unread'
            ? el(
                'button',
                {
                  type: 'button',
                  onclick: async () => {
                    await call('POST', '/api/inbox/read', { id: item.id });
                    await refreshInbox();
                  },
                },
                '確認しました',
              )
            : null,
        ),
      );
    }
    return list;
  }

  const inboxBody = el('div', { id: 'inbox-body' });
  let inboxTimer = null;

  async function refreshInbox() {
    const result = await call('GET', '/api/inbox');
    if (result.status !== 200) return;
    inboxBody.replaceChildren(inboxList(result.data));
  }

  function inboxSection() {
    if (inboxTimer === null) {
      inboxTimer = setInterval(() => {
        if (inboxBody.isConnected) void refreshInbox();
      }, INBOX_POLL_MS);
    }
    void refreshInbox();
    return el(
      'section',
      { 'aria-labelledby': 'inbox-heading' },
      el('h2', { id: 'inbox-heading' }, '受信箱'),
      inboxBody,
    );
  }

  async function renderHome(note) {
    const result = await call('GET', '/api/me');
    if (result.status !== 200) return renderSignedOut(note);
    const me = result.data;
    show(
      note ? status(note) : null,
      inboxSection(),
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

  // ---- 承認用のオリジン：承認待ちの画面（DESIGN.md 2章「端末での承認」「窓口での承認」、ADR 0023） ----

  function renderApprovalLogin(note) {
    show(
      note ? status(note) : null,
      el('p', {}, '確認待ちを表示するには、パスキーで確かめてください。'),
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
                '/api/approvals/login/options',
                '/api/approvals/login/verify',
              );
              if (result.status === 200) return renderApprovals();
              renderApprovalLogin(failureText(result));
            },
          },
          'パスキーで確認待ちを表示する',
        ),
      ),
    );
  }

  const decide = (id, decision) => async () => {
    const result = await ceremony(
      'authenticate',
      '/api/approvals/decide/options',
      '/api/approvals/decide/verify',
      { id, decision },
    );
    if (result.status === 200) {
      return renderApprovals(decision === 'approved' ? '承認しました。' : '拒否しました。');
    }
    if (result.status === 401 && result.data.error === 'login_required') {
      return renderApprovalLogin('もう一度、パスキーで確かめてください。');
    }
    renderApprovals(
      result.status === 429
        ? failureText(result)
        : '選べませんでした。期限が切れたか、すでに選ばれた可能性があります。パスキーでの確認ができなかったときは、もう一度お試しください。',
    );
  };

  let cardCount = 0;

  /** ApprovalCard（DESIGN.md 6章）：企業名、操作の種類、操作の内容、要求の時刻と端末、補足の順。承認と拒否は同じ大きさ。 */
  function approvalCard(card) {
    cardCount += 1;
    const companyId = `approval-company-${cardCount}`;
    return el(
      'article',
      { className: 'approval-card', 'aria-labelledby': companyId },
      el('h2', { id: companyId, className: 'company', tabindex: '-1' }, card.company),
      el('p', { className: 'operation' }, card.operation),
      card.lines.length === 0
        ? null
        : el(
            'dl',
            {},
            ...card.lines.flatMap((line) => [el('dt', {}, line.label), el('dd', {}, line.value)]),
          ),
      el('p', {}, `要求の時刻：${DATE.format(new Date(card.createdAt))}`),
      el('p', {}, `要求の端末：${card.device}`),
      el('p', {}, `期限：${expiryText(card.expiresAt)}`),
      fixedWarning(card.warning, { company: card.company, operation: card.operation }),
      el(
        'div',
        { className: 'actions equal' },
        el('button', { type: 'button', onclick: decide(card.id, 'approved') }, '承認する'),
        el('button', { type: 'button', onclick: decide(card.id, 'denied') }, '拒否する'),
      ),
    );
  }

  /** 窓口の作成の取消（承認用のオリジン。パスキーで確かめる）。「心当たりがない」も同じ取消に、申告の案内を添える。 */
  const cancelDesk = (item, unrecognized) => async () => {
    const result = await ceremony(
      'authenticate',
      '/api/desk-items/cancel/options',
      '/api/desk-items/cancel/verify',
      { id: item.id },
    );
    if (result.status === 200) {
      return renderApprovals(
        unrecognized
          ? `取消を受け付けました。心当たりがない場合は、${item.company}の公式窓口に、自分から連絡して、不正の疑いを申告してください。`
          : '取消を受け付けました。',
      );
    }
    if (result.status === 401 && result.data.error === 'login_required') {
      return renderApprovalLogin('もう一度、パスキーで確かめてください。');
    }
    renderApprovals(
      result.status === 409
        ? '取消期限を過ぎたか、受付が終わっていたため、取り消せませんでした。'
        : failureText(result),
    );
  };

  /** 窓口の作成の項目（DESIGN.md 2章「窓口の承認済み・作成の知らせ待ち」「窓口での変更の通知」）。 */
  function deskItemCard(item) {
    return el(
      'article',
      { className: 'approval-card' },
      ...deskItemLines(item),
      item.state === 'created' ? fixedWarning(item.warning, { company: item.company }) : null,
      item.cancellable
        ? el(
            'div',
            { className: 'actions equal' },
            el('button', { type: 'button', onclick: cancelDesk(item, false) }, '取り消す'),
            el('button', { type: 'button', onclick: cancelDesk(item, true) }, '心当たりがない'),
          )
        : null,
    );
  }

  async function renderApprovals(note) {
    const result = await call('GET', '/api/approvals');
    if (result.status === 401) return renderApprovalLogin(note);
    const deskResult = await call('GET', '/api/desk-items');
    const deskItems = deskResult.status === 200 ? deskResult.data.items : [];
    const refresh = el(
      'button',
      { type: 'button', onclick: () => renderApprovals() },
      '確認待ちを更新する',
    );
    if (result.status !== 200) {
      return show(
        status('確認待ちを読み込めませんでした。しばらくしてから、もう一度お試しください。'),
        refresh,
      );
    }
    const cards = result.data.approvals.map(approvalCard);
    show(
      note ? status(note) : null,
      ...(cards.length === 0 ? [el('p', {}, '確認待ちはありません。')] : cards),
      deskItems.length === 0
        ? null
        : el(
            'section',
            { 'aria-labelledby': 'desk-items-heading' },
            el('h2', { id: 'desk-items-heading' }, '窓口での手続き'),
            ...deskItems.map(deskItemCard),
          ),
      refresh,
    );
    // 初期フォーカスは見出し（企業名）に置き、どのボタンにも置かない（DESIGN.md 原則4）。
    const first = cards[0]?.querySelector('.company');
    if (first) first.focus();
  }

  // ---- 承認用のオリジン：窓口での承認（DESIGN.md 2章「窓口での承認（step-up）」、ADR 0026 の O-61） ----

  /** 承認しなかったときの案内。理由は画面の案内と監査だけに使い、企業には区別して返さない。 */
  const DECLINE_TEXT = Object.freeze({
    denied: '承認しませんでした。企業の画面に戻ります。',
    unrecognized:
      'この申請を取りやめました。心当たりがない場合は、〈企業名〉の公式窓口に、自分から連絡して、不正の疑いを申告してください。',
    incoming_call:
      '承認しませんでした。相手からかかってきた電話で求められた操作は、承認しないでください。〈企業名〉の公式窓口に、自分から連絡し直してください。',
  });

  function renderDeskEnded(text) {
    show(status(text));
  }

  async function renderDesk() {
    const uid = window.location.hash.slice(1);
    const loaded = /^[A-Za-z0-9_-]{1,64}$/.test(uid)
      ? await call('POST', '/api/desk/view', { uid })
      : { status: 400, data: {} };
    if (loaded.status !== 200) {
      return renderDeskEnded(
        'この確認は、期限が切れたか、すでに終わっています。企業の画面から、もう一度お試しください。',
      );
    }
    const card = loaded.data;
    let answer = null;
    const note = el('div');
    const decline = (reason) => async () => {
      const result = await call('POST', '/api/desk/decline', { uid, reason });
      const text = DECLINE_TEXT[reason].replace('〈企業名〉', () => card.company);
      if (result.status === 200 && typeof result.data.redirectTo === 'string') {
        const target = result.data.redirectTo;
        return show(
          status(text),
          el(
            'button',
            { type: 'button', onclick: () => window.location.assign(target) },
            '企業の画面に戻る',
          ),
        );
      }
      renderDeskEnded(text);
    };
    const approve = async () => {
      if (answer !== 'self') {
        note.replaceChildren(status('先に、上の問いに答えてください。'));
        return;
      }
      const result = await ceremony(
        'authenticate',
        '/api/desk/approve/options',
        '/api/desk/approve/verify',
        { uid, call: 'self' },
        { uid },
      );
      if (go(result)) return;
      note.replaceChildren(
        status(
          result.status === 429
            ? failureText(result)
            : 'パスキーでの確認ができませんでした。企業の画面でログインしているアカウントの割符で、もう一度お試しください。',
        ),
      );
    };
    const question = el(
      'fieldset',
      { className: 'question' },
      el('legend', {}, 'この操作は、相手からかかってきた電話で求められていますか？'),
      el(
        'div',
        { className: 'actions equal' },
        el(
          'button',
          {
            type: 'button',
            onclick: () => {
              answer = 'self';
              note.replaceChildren(status('自分から公式窓口に連絡した、と答えました。'));
            },
          },
          'いいえ、自分から公式窓口に連絡しました',
        ),
        el(
          'button',
          { type: 'button', onclick: decline('incoming_call') },
          'はい、相手からかかってきました',
        ),
      ),
    );
    show(
      el(
        'article',
        { className: 'approval-card', 'aria-labelledby': 'desk-company' },
        el('h2', { id: 'desk-company', className: 'company', tabindex: '-1' }, card.company),
        el('p', { className: 'operation' }, card.operation),
        card.lines.length === 0
          ? null
          : el(
              'dl',
              {},
              ...card.lines.flatMap((line) => [el('dt', {}, line.label), el('dd', {}, line.value)]),
            ),
        el('p', {}, `要求の時刻：${DATE.format(new Date(card.createdAt))}`),
        el('p', {}, `要求の端末：${card.device}`),
        el('p', {}, `期限：${expiryText(card.expiresAt)}`),
        el('h3', {}, '窓口に許すこと'),
        el('p', {}, card.scope),
        el('p', {}, card.validity),
        el('p', {}, card.change),
        question,
        fixedWarning(card.warning, { company: card.company }),
        note,
        el(
          'div',
          { className: 'actions equal' },
          el('button', { type: 'button', onclick: approve }, '承認する'),
          el('button', { type: 'button', onclick: decline('denied') }, '承認しない'),
          el('button', { type: 'button', onclick: decline('unrecognized') }, '心当たりがない'),
        ),
      ),
    );
    // 初期フォーカスは見出し（企業名）に置き、どのボタンにも置かない（DESIGN.md 原則4）。
    document.getElementById('desk-company')?.focus();
  }

  if (root.dataset.page === 'approval') {
    void renderApprovals();
  } else if (root.dataset.page === 'desk') {
    void renderDesk();
  } else if (root.dataset.page === 'interaction') {
    const uid = root.dataset.uid ?? '';
    if (company) company.setAttribute('aria-label', '接続先の企業');
    if (root.dataset.prompt === 'consent') renderConsent(uid);
    else renderInteractionLogin(uid);
  } else {
    void renderHome();
  }
})();
