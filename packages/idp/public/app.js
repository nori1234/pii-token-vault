// 割符の PWA（M3 の土台）と、承認用のオリジンの承認待ちの画面（M6。ADR 0023）と、窓口での承認の画面と窓口の作成の
// 項目（M7。ADR 0026）と、回復と協力者の画面（M8。ADR 0027）。ブラウザで動く。
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

  // 固定の警告文（DESIGN.md 3章）。文言は変えない。〈〉の部分だけを、登録簿の企業名、割符が決めた操作の種類、協力者の
  // 端末の中だけにある表示名、サーバーが返した時刻で埋める。
  // サーバーからは警告文の ID だけを受け取る（FixedWarning は任意の文字列を受け取らない。DESIGN.md 6章）。
  const WARNINGS = Object.freeze({
    'A-1':
      'あなたが自分から〈企業名〉の公式窓口に連絡した場合だけ、操作と担当者を確認して承認してください。相手からかかってきた電話で求められた場合は、承認せず、公式窓口へ連絡し直してください。',
    'A-2':
      'この確認は、あなたが今この端末で〈操作の種類〉をしようとしている場合だけ承認してください。電話やメッセージで頼まれて承認してはいけません。',
    C: 'このコードを入力すると、〈表示名〉さんのアカウントが、〈時刻〉から新しい端末で使えるようになります。〈表示名〉さんと直接会い、その人の新しい端末に出ている QR やコードを自分の目で見たときだけ入力してください。電話、ビデオ通話、メッセージで伝えられたコードは入力しないでください。',
    E: 'あなたが窓口に連絡していないのに、この通知が届いた場合は、取り消してください。割符や企業が電話で『取り消さないでください』と頼むことはありません。',
    F: 'あなたが回復を始めていないなら、取り消してください。『この通知は無視して』『取り消さないで』と電話やメッセージで言われたら、それは詐欺です。',
    G: '回復コードを、割符や企業が電話・メール・メッセージで聞くことはありません。このコードを入力するのは、割符のアプリの『回復』の画面だけです。',
    H: '協力者には、あなたが直接会って頼んだ、よく知っている人だけを選んでください。招待のコードや QR を、電話やメッセージで教えてはいけません。',
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

  /** 絶対時刻と、分単位の相対時刻（DESIGN.md 4章）。秒は出さない（急がせない。原則7）。 */
  function timeText(iso) {
    const at = new Date(iso);
    const minutes = Math.max(0, Math.ceil((at.getTime() - Date.now()) / 60_000));
    const relative =
      minutes >= 120 ? `あと約${Math.round(minutes / 60)}時間` : `あと約${minutes}分`;
    return `${DATE.format(at)}（${relative}）`;
  }

  /** ExpiryText（DESIGN.md 4章・6章）：期限を、絶対時刻と分単位の相対時刻で示す。 */
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
    // 置き換えには関数を渡す（企業名や表示名に $& などがあっても、そのまま文字として出す）。
    const text = template
      .replaceAll('〈企業名〉', () => params.company ?? '')
      .replaceAll('〈操作の種類〉', () => params.operation ?? '')
      .replaceAll('〈表示名〉', () => params.name ?? '')
      .replaceAll('〈時刻〉', () => params.time ?? '');
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

  function passkeySection(passkeys, restrictedUntil) {
    const list = el('ul', { className: 'passkeys' });
    for (const passkey of passkeys) {
      list.append(
        el(
          'li',
          {},
          el('span', {}, passkey.synced ? '同期パスキー' : '端末固定のパスキー'),
          passkey.suspended
            ? el('strong', {}, '一時停止中（回復したため、ログインにも確認にも使えません）')
            : null,
          el('span', {}, `登録：${DATE.format(new Date(passkey.createdAt))}`),
          el(
            'span',
            {},
            passkey.lastUsedAt
              ? `最後に使った日時：${DATE.format(new Date(passkey.lastUsedAt))}`
              : 'まだ使っていません',
          ),
          passkeys.length > 1 && !restrictedUntil
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
      restrictedUntil
        ? el(
            'p',
            {},
            `回復の後のため、${DATE.format(new Date(restrictedUntil))} までは、パスキーを削除できません。`,
          )
        : null,
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

  /** 回復の通知の行（回復が始まった時刻、回復が可能になる時刻、要求した端末の種類、取消の説明）。 */
  function recoveryNoticeLines(attempt) {
    return [
      el('strong', {}, 'アカウントの回復が始まっています'),
      el('span', {}, `回復が始まった時刻：${DATE.format(new Date(attempt.startedAt))}`),
      attempt.readyAt
        ? el('span', {}, `回復が可能になる時刻：${timeText(attempt.readyAt)}`)
        : el(
            'span',
            {},
            `協力者の承認待ちです（${expiryText(attempt.helperDeadline)}に承認されなければ、期限が切れます）`,
          ),
      el('span', {}, `要求した端末：${attempt.device}`),
      el(
        'span',
        {},
        '取り消すと、いまの回復コードは使えなくなり、14日間は回復を始められなくなります。',
      ),
    ];
  }

  /** 回復の設定は、承認用のオリジンの画面で行う（ADR 0027 の O-82）。ここには案内だけを置く。 */
  function recoveryLinkSection() {
    const approvalUrl = approvalOriginUrl();
    if (!approvalUrl) return null;
    return el(
      'section',
      { 'aria-labelledby': 'recovery-heading' },
      el('h2', { id: 'recovery-heading' }, '回復'),
      el(
        'p',
        {},
        '端末をなくしたときに備えて、回復コードを作り、回復協力者を登録します。設定は、確認用の画面で行います。',
      ),
      el(
        'ul',
        { className: 'links' },
        el(
          'li',
          {},
          el('a', { href: `${approvalUrl}/recovery` }, '回復コードと協力者の設定を開く'),
        ),
        el('li', {}, el('a', { href: `${approvalUrl}/helper` }, '協力者として承認する画面を開く')),
      ),
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
    const recovery = inbox.recovery ?? null;
    if (inbox.items.length === 0 && desk.length === 0 && recovery === null) {
      return el('p', {}, 'お知らせはありません。');
    }
    const approvalUrl = approvalOriginUrl();
    const list = el('ul', { className: 'inbox' });
    // 進行中の回復（DESIGN.md 2章「回復の通知」）。取り消すのは、承認用のオリジンの回復の設定の画面（パスキーで確かめる）。
    if (recovery !== null) {
      list.append(
        el(
          'li',
          { className: 'recovery-notice' },
          ...recoveryNoticeLines(recovery),
          fixedWarning('F', {}),
          approvalUrl
            ? el('a', { href: `${approvalUrl}/recovery` }, '回復を取り消す（回復の設定を開く）')
            : null,
        ),
      );
    }
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
      recoveryLinkSection(),
      emailSection(me.email),
      passkeySection(me.passkeys, me.restrictedUntil),
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

  function renderApprovalLogin(note, next = renderApprovals, intro, label) {
    show(
      note ? status(note) : null,
      el('p', {}, intro ?? '確認待ちを表示するには、パスキーで確かめてください。'),
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
              if (result.status === 200) return next();
              renderApprovalLogin(failureText(result), next, intro, label);
            },
          },
          label ?? 'パスキーで確認待ちを表示する',
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

  // ---- 承認用のオリジン：回復と協力者（DESIGN.md 2章、ADR 0027 の O-82） ----

  /**
   * CodeDisplay（DESIGN.md 6章）：等幅で、3文字ごとに区切って見せる。読み上げ用には、1文字ずつ読める文を添える。
   * コードは、この画面の DOM にだけ置く（保存も送信もしない）。
   */
  function codeDisplay(code, label) {
    const plain = code.replace(/-/g, '');
    const visible = el('p', { className: 'code-display', 'aria-hidden': 'true' });
    for (let i = 0; i < plain.length; i += 3) {
      visible.append(el('span', {}, plain.slice(i, i + 3)));
    }
    return el(
      'div',
      { className: 'code-block' },
      el('p', { className: 'code-label' }, label),
      visible,
      el('p', { className: 'sr-only' }, `${label}：${[...plain].join('、')}`),
    );
  }

  /** QR を canvas に描く（サーバーが返した白黒の行列だけを使う。HTML として描かない。O-82）。 */
  function qrCanvas(rows, label) {
    const valid =
      Array.isArray(rows) &&
      rows.length > 0 &&
      rows.length <= 200 &&
      rows.every(
        (row) => typeof row === 'string' && /^[01]+$/.test(row) && row.length === rows.length,
      );
    if (!valid) return null;
    const scale = 6;
    const size = rows.length * scale;
    const canvas = el('canvas', {
      width: size,
      height: size,
      className: 'qr',
      role: 'img',
      'aria-label': label,
    });
    const context = canvas.getContext('2d');
    if (!context) return null;
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, size, size);
    context.fillStyle = '#000000';
    rows.forEach((row, y) => {
      for (let x = 0; x < row.length; x += 1) {
        if (row[x] === '1') context.fillRect(x * scale, y * scale, scale, scale);
      }
    });
    return canvas;
  }

  // 協力者の端末の中だけに置く、相手の表示名（DESIGN.md 2章の注、PRN-91）。サーバーには送らない。
  const NAMES_KEY = 'warifu.helperNames.v1';

  function loadNames() {
    try {
      const value = JSON.parse(window.localStorage.getItem(NAMES_KEY) ?? '{}');
      return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
    } catch {
      return {};
    }
  }

  function nameOf(relationshipId) {
    const name = loadNames()[relationshipId];
    return typeof name === 'string' && name.length > 0 ? name : null;
  }

  function saveName(relationshipId, name) {
    try {
      const names = loadNames();
      names[relationshipId] = name;
      window.localStorage.setItem(NAMES_KEY, JSON.stringify(names));
      return true;
    } catch {
      // 保存できない端末（プライベートの窓など）では、表示名なしで続ける。
      return false;
    }
  }

  function nameInput(id) {
    return el('input', {
      id,
      type: 'text',
      autocomplete: 'off',
      spellcheck: 'false',
      maxlength: '40',
      required: 'required',
    });
  }

  function cleanName(value) {
    const name = value.trim().replace(/\s+/g, ' ');
    return name.length >= 1 && name.length <= 40 ? name : null;
  }

  /** 24文字のコード（区切りの有無と、大文字・小文字を問わない）。QR とコードの入力の両方に使う。 */
  function shortCodeOf(value) {
    const plain = String(value).replace(/[\s-]/g, '').toUpperCase();
    return /^[0-9A-Z]{24}$/.test(plain) ? plain : null;
  }

  /** カメラと BarcodeDetector があるときだけ、QR を読み取る（O-82）。読み取れたら、onCode に値を渡す。 */
  function qrReader(onCode) {
    const supported =
      'BarcodeDetector' in window && typeof navigator.mediaDevices?.getUserMedia === 'function';
    if (!supported) return null;
    const video = el('video', {
      className: 'qr-video',
      playsinline: 'playsinline',
      muted: 'muted',
    });
    const note = el('div');
    let stream = null;
    const stop = () => {
      for (const track of stream?.getTracks() ?? []) track.stop();
      stream = null;
      video.remove();
    };
    const start = async () => {
      try {
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' },
        });
        video.srcObject = stream;
        note.replaceChildren(video);
        await video.play();
        const scan = async () => {
          if (stream === null || !video.isConnected) return stop();
          const found = await detector.detect(video).catch(() => []);
          const code = found.map((item) => shortCodeOf(item.rawValue)).find((c) => c !== null);
          if (code) {
            stop();
            return onCode(code);
          }
          setTimeout(scan, 300);
        };
        void scan();
      } catch {
        stop();
        note.replaceChildren(status('カメラを使えませんでした。下のコードを入力してください。'));
      }
    };
    return el(
      'div',
      { className: 'qr-reader' },
      el('button', { type: 'button', onclick: start }, 'QR を読み取る'),
      note,
    );
  }

  /** QR の読み取り（第一の方法）と、使えないときだけのコードの入力（DESIGN.md 2章「協力者の承認」）。 */
  function codeEntry(id, label, onCode) {
    const input = el('input', {
      id,
      type: 'text',
      autocomplete: 'off',
      autocapitalize: 'characters',
      spellcheck: 'false',
      maxlength: '40',
    });
    const form = el(
      'form',
      {
        onsubmit: (event) => {
          event.preventDefault();
          const code = shortCodeOf(input.value);
          input.value = '';
          if (code) return onCode(code);
          return onCode(null);
        },
      },
      el('label', { for: id }, label),
      input,
      el('button', { type: 'submit' }, 'コードを入力する'),
    );
    const reader = qrReader(onCode);
    if (reader === null) return el('div', {}, form);
    return el(
      'div',
      {},
      reader,
      el('details', {}, el('summary', {}, 'QR を読み取れないとき'), form),
    );
  }

  /** 回復コードの表示（DESIGN.md 2章）：コード、保管の案内、警告文 G。共有やメールで送る機能は置かない。 */
  function recoveryCodeBlock(code, reissued) {
    return el(
      'section',
      { 'aria-labelledby': 'recovery-code-heading', className: 'approval-card' },
      el('h2', { id: 'recovery-code-heading', tabindex: '-1' }, '回復コード'),
      codeDisplay(code, '回復コード'),
      el(
        'p',
        {},
        'この回復コードは、この画面で1回だけ表示します。紙に書いて、自分だけが分かる場所に保管してください。メール、クラウド、写真には保存しないでください。',
      ),
      reissued ? el('p', {}, '前の回復コードは、もう使えません。') : null,
      fixedWarning('G', {}),
    );
  }

  // ---- 新しい端末：回復の開始、協力者の承認待ち、待機、完了 ----

  const RESUME_FAILED =
    'この端末で進めている回復を確かめられませんでした。期限が切れたか、取り消された可能性があります。回復コードから、もう一度始めてください。';

  async function resumeRecovery() {
    const result = await ceremony(
      'authenticate',
      '/api/recovery/resume/options',
      '/api/recovery/resume/verify',
    );
    if (result.status === 200) return renderRecoveryState(result.data);
    if (result.status === 503) {
      return renderRecover(
        '回復を完了する前に、接続している企業への知らせを送れませんでした。しばらくしてから、「回復の続きを確かめる」をもう一度押してください。',
      );
    }
    renderRecover(result.status === 429 ? failureText(result) : RESUME_FAILED);
  }

  const resumeButton = () =>
    el('button', { type: 'button', onclick: resumeRecovery }, '回復の続きを確かめる');

  function renderRecover(note) {
    const input = el('input', {
      id: 'recovery-code',
      type: 'text',
      autocomplete: 'off',
      autocapitalize: 'characters',
      spellcheck: 'false',
      maxlength: '64',
      required: 'required',
    });
    show(
      note ? status(note) : null,
      el(
        'p',
        {},
        'この端末で、割符のアカウントを回復します。回復コードと、回復協力者の承認が必要です。協力者が承認してから72時間たつと、回復が完了します。',
      ),
      el(
        'form',
        {
          onsubmit: async (event) => {
            event.preventDefault();
            const code = input.value;
            input.value = '';
            const result = await ceremony(
              'register',
              '/api/recovery/start',
              '/api/recovery/register',
              { code },
            );
            if (result.status === 200) return renderRecoveryState(result.data);
            renderRecover(
              result.status === 429
                ? failureText(result)
                : '回復を始められませんでした。回復コードを確かめて、もう一度お試しください。',
            );
          },
        },
        el('label', { for: 'recovery-code' }, '回復コード'),
        input,
        el('button', { type: 'submit' }, '回復を始める'),
      ),
      fixedWarning('G', {}),
      el(
        'section',
        { 'aria-labelledby': 'resume-heading' },
        el('h2', { id: 'resume-heading' }, 'この端末で始めた回復の続き'),
        el(
          'p',
          {},
          '協力者が承認した後や、待機が終わった後は、回復を始めたときにこの端末で作ったパスキーで、続きを確かめます。',
        ),
        resumeButton(),
      ),
    );
  }

  /** 新しい端末の状態ごとの画面（DESIGN.md 2章「協力者の承認待ち」「回復の待機」）。協力者を特定できる情報は出さない。 */
  function renderRecoveryState(data) {
    if (data.state === 'awaiting_helper' && data.binding) {
      return show(
        el('h2', { id: 'recover-step', tabindex: '-1' }, '協力者の承認を待っています'),
        el(
          'p',
          {},
          '協力者と直接会って、この画面を見せてください。協力者が、自分の割符のアプリで QR を読み取ります（読み取れないときは、下のコードを入力します）。',
        ),
        qrCanvas(data.binding.qr, '協力者に見せる QR コード'),
        codeDisplay(data.binding.code, '協力者に見せるコード'),
        el('p', {}, `有効期限：${expiryText(data.binding.expiresAt)}`),
        el(
          'p',
          {},
          '期限が切れたときや、協力者が承認した後は、「回復の続きを確かめる」を押してください。',
        ),
        resumeButton(),
      );
    }
    if (data.state === 'waiting' && data.readyAt) {
      return show(
        el('h2', { id: 'recover-step', tabindex: '-1' }, '回復の待機中です'),
        el('p', {}, `回復が可能になる時刻：${timeText(data.readyAt)}`),
        el(
          'p',
          {},
          'この時刻を過ぎたら、「回復の続きを確かめる」を押して、回復を完了してください。それまでの間、登録済みの端末には、回復が始まったことを知らせています。',
        ),
        resumeButton(),
      );
    }
    if (data.state === 'completed' && typeof data.recoveryCode === 'string') {
      return show(
        el('h2', { id: 'recover-step', tabindex: '-1' }, '回復が完了しました'),
        el(
          'p',
          {},
          'この端末のパスキーで、割符を使えます。前の端末のパスキーは一時停止にしました。回復の後7日間は、協力者の変更、パスキーの削除、メールアドレスの登録と変更、一部の確認ができません。',
        ),
        recoveryCodeBlock(data.recoveryCode, true),
        el('a', { href: '/recovery' }, '回復の設定を開く'),
      );
    }
    renderRecover(RESUME_FAILED);
  }

  // ---- 持ち主：回復の設定と、進行中の回復の取消（DESIGN.md 2章「回復の通知」「協力者の招待」） ----

  function loginForRecovery(next, note) {
    renderApprovalLogin(
      note,
      next,
      'この画面を表示するには、パスキーで確かめてください。',
      'パスキーで確かめる',
    );
  }

  async function cancelRecoveryAttempt(attempt) {
    const result = await ceremony(
      'authenticate',
      '/api/recovery/cancel/options',
      '/api/recovery/cancel/verify',
      { id: attempt.id },
    );
    if (result.status === 200) {
      return renderRecoverySettings(
        '回復を取り消しました。回復コードは使えなくなりました。新しい回復コードを作ってください（回復を始められるのは14日の後です）。',
      );
    }
    if (result.status === 401 && result.data.error === 'login_required') {
      return loginForRecovery(renderRecoverySettings, 'もう一度、パスキーで確かめてください。');
    }
    renderRecoverySettings(
      result.status === 429
        ? failureText(result)
        : '取り消せませんでした。回復がすでに終わったか、パスキーでの確認ができませんでした。もう一度お試しください。',
    );
  }

  function recoveryNoticeCard(attempt) {
    return el(
      'article',
      { className: 'approval-card recovery-notice', 'aria-labelledby': 'recovery-notice-heading' },
      el(
        'h2',
        { id: 'recovery-notice-heading', tabindex: '-1' },
        'アカウントの回復が始まっています',
      ),
      ...recoveryNoticeLines(attempt)
        .slice(1)
        .map((line) => el('p', {}, line.textContent ?? '')),
      fixedWarning('F', {}),
      el(
        'div',
        { className: 'actions' },
        el(
          'button',
          { type: 'button', className: 'danger', onclick: () => cancelRecoveryAttempt(attempt) },
          '回復を取り消す',
        ),
      ),
    );
  }

  async function issueRecoveryCode() {
    const result = await ceremony(
      'authenticate',
      '/api/recovery-code/options',
      '/api/recovery-code/verify',
    );
    if (result.status === 200 && typeof result.data.code === 'string') {
      show(
        recoveryCodeBlock(result.data.code, result.data.reissued === true),
        el(
          'button',
          { type: 'button', onclick: () => renderRecoverySettings() },
          '保管しました（設定に戻る）',
        ),
      );
      document.getElementById('recovery-code-heading')?.focus();
      return;
    }
    if (result.status === 401 && result.data.error === 'login_required') {
      return loginForRecovery(renderRecoverySettings, 'もう一度、パスキーで確かめてください。');
    }
    renderRecoverySettings(failureText(result));
  }

  async function confirmHelper(code, note) {
    const result = await ceremony(
      'authenticate',
      '/api/helpers/confirm/options',
      '/api/helpers/confirm/verify',
      { code },
    );
    if (result.status === 200) return renderRecoverySettings('回復協力者を登録しました。');
    if (result.status === 409) {
      return renderRecoverySettings('回復の後7日間は、協力者を変えられません。');
    }
    note.replaceChildren(
      status(
        result.status === 400
          ? 'まだ受け入れられていないか、期限が切れました。協力者の端末で受け入れてから、もう一度押してください。'
          : failureText(result),
      ),
    );
  }

  async function inviteHelper() {
    const result = await call('POST', '/api/helpers/invite');
    if (result.status === 409) {
      return renderRecoverySettings('回復の後7日間は、協力者を変えられません。');
    }
    if (result.status !== 200) return renderRecoverySettings(failureText(result));
    const { code, qr, expiresAt } = result.data;
    const note = el('div');
    show(
      el('h2', { id: 'invite-heading', tabindex: '-1' }, '回復協力者の招待'),
      el(
        'ol',
        {},
        el(
          'li',
          {},
          '協力者と直接会い、協力者の割符のアプリで「協力者の招待を受け入れる」を開いてもらいます。',
        ),
        el(
          'li',
          {},
          'この QR を読み取ってもらいます（読み取れないときは、下のコードを入力してもらいます）。',
        ),
        el(
          'li',
          {},
          '協力者の端末に、協力者があなたに付けた呼び名が出ていることを、自分の目で確かめます。',
        ),
        el('li', {}, '確かめたら「協力者として確定する」を押し、パスキーで確かめます。'),
      ),
      qrCanvas(qr, '協力者に読み取ってもらう QR コード'),
      codeDisplay(code, '招待コード'),
      el('p', {}, `有効期限：${expiryText(expiresAt)}`),
      fixedWarning('H', {}),
      note,
      el(
        'div',
        { className: 'actions' },
        el(
          'button',
          { type: 'button', onclick: () => confirmHelper(code, note) },
          '協力者として確定する',
        ),
        el('button', { type: 'button', onclick: () => renderRecoverySettings() }, 'やめる'),
      ),
    );
    document.getElementById('invite-heading')?.focus();
  }

  async function removeHelper() {
    const result = await ceremony(
      'authenticate',
      '/api/helpers/remove/options',
      '/api/helpers/remove/verify',
    );
    if (result.status === 200) {
      return renderRecoverySettings(
        '回復協力者を外しました。回復には協力者が必要です。新しい協力者を招待してください。',
      );
    }
    renderRecoverySettings(
      result.status === 409 ? '回復の後7日間は、協力者を変えられません。' : failureText(result),
    );
  }

  async function renderRecoverySettings(note) {
    const result = await call('GET', '/api/recovery/settings');
    if (result.status === 401) return loginForRecovery(renderRecoverySettings, note);
    if (result.status !== 200) {
      return show(status('読み込めませんでした。しばらくしてから、もう一度お試しください。'));
    }
    const settings = result.data;
    const restricted = settings.restrictedUntil;
    show(
      note ? status(note) : null,
      settings.attempt ? recoveryNoticeCard(settings.attempt) : null,
      restricted
        ? el(
            'p',
            { className: 'status' },
            `回復の後のため、${DATE.format(new Date(restricted))} までは、協力者の変更、パスキーの削除、メールアドレスの登録と変更、一部の確認ができません。`,
          )
        : null,
      el(
        'section',
        { 'aria-labelledby': 'code-section-heading' },
        el('h2', { id: 'code-section-heading' }, '回復コード'),
        el(
          'p',
          {},
          settings.code
            ? `作った日時：${DATE.format(new Date(settings.code.createdAt))}`
            : 'まだ作っていません。',
        ),
        el(
          'p',
          {},
          '端末をなくしたときは、回復コードと回復協力者の承認で、新しい端末からアカウントを回復します。作り直すと、前の回復コードは使えなくなります。',
        ),
        el(
          'button',
          { type: 'button', onclick: issueRecoveryCode },
          settings.code ? '回復コードを作り直す' : '回復コードを作る',
        ),
      ),
      el(
        'section',
        { 'aria-labelledby': 'helper-section-heading' },
        el('h2', { id: 'helper-section-heading' }, '回復協力者'),
        el(
          'p',
          {},
          settings.helper
            ? `回復協力者を登録しています（登録：${DATE.format(new Date(settings.helper.createdAt))}）。`
            : 'まだ登録していません。回復には、協力者が1人必要です。',
        ),
        restricted
          ? null
          : el(
              'div',
              { className: 'actions' },
              el(
                'button',
                { type: 'button', onclick: inviteHelper },
                settings.helper ? '協力者を入れ替える' : '協力者を招待する',
              ),
              settings.helper
                ? el(
                    'button',
                    { type: 'button', className: 'danger', onclick: removeHelper },
                    '協力者を外す',
                  )
                : null,
            ),
      ),
      el('p', {}, el('a', { href: '/helper' }, '協力者として承認する・招待を受け入れる')),
    );
    if (settings.attempt) document.getElementById('recovery-notice-heading')?.focus();
  }

  // ---- 協力者：招待の受け入れと、回復の承認（DESIGN.md 2章「協力者の承認」） ----

  const NOT_ELIGIBLE_TEXT =
    '直近の14日の間に、あなたのアカウントでパスキーの追加か回復があったため、いまは承認できません。';

  async function approveAsHelper(code, readyAt) {
    const result = await ceremony(
      'authenticate',
      '/api/recovery/helper/options',
      '/api/recovery/helper/verify',
      { code },
    );
    if (result.status === 200) {
      return renderHelper(
        `承認しました。${DATE.format(new Date(result.data.readyAt ?? readyAt))} から、新しい端末で使えるようになります。`,
      );
    }
    if (result.status === 409 && result.data.error === 'helper_not_eligible') {
      return renderHelper(NOT_ELIGIBLE_TEXT);
    }
    if (result.status === 401 && result.data.error === 'login_required') {
      return loginForRecovery(renderHelper, 'もう一度、パスキーで確かめてください。');
    }
    renderHelper(
      result.status === 429
        ? failureText(result)
        : 'このコードでは承認できませんでした。期限が切れたか、すでに使われています。新しい端末で、新しいコードを出してもらってください。',
    );
  }

  /** 承認の前に、何が起きるかと警告文 C を出す。承認と「入力しない」は同じ大きさ（既定の選択はない）。 */
  function renderHelperApproval(code, relationshipId, readyAt) {
    const name = nameOf(relationshipId);
    if (name === null) {
      const input = nameInput('helper-owner-name');
      return show(
        el(
          'p',
          {},
          'この端末には、この人の呼び名がありません。承認する前に、この人の呼び名を付けてください（この端末の中だけに保存します）。',
        ),
        el(
          'form',
          {
            onsubmit: (event) => {
              event.preventDefault();
              const cleaned = cleanName(input.value);
              if (cleaned === null) return;
              saveName(relationshipId, cleaned);
              renderHelperApproval(code, relationshipId, readyAt);
            },
          },
          el('label', { for: 'helper-owner-name' }, 'この人の呼び名'),
          input,
          el('button', { type: 'submit' }, '呼び名を付ける'),
        ),
        el(
          'button',
          { type: 'button', onclick: () => renderHelper() },
          '入力しない（本人に確かめられない）',
        ),
      );
    }
    show(
      el(
        'article',
        { className: 'approval-card', 'aria-labelledby': 'helper-approval-heading' },
        el(
          'h2',
          { id: 'helper-approval-heading', className: 'company', tabindex: '-1' },
          `${name}さんの回復`,
        ),
        el(
          'p',
          {},
          '承認すると、回復の待機が始まります。待機が終わると、この人のアカウントが新しい端末で使えるようになり、前の端末のパスキーは一時停止になります。',
        ),
        fixedWarning('C', { name, time: DATE.format(new Date(readyAt)) }),
        el(
          'div',
          { className: 'actions equal' },
          el(
            'button',
            { type: 'button', onclick: () => approveAsHelper(code, readyAt) },
            '承認する',
          ),
          el(
            'button',
            { type: 'button', onclick: () => renderHelper('承認しませんでした。') },
            '入力しない（本人に確かめられない）',
          ),
        ),
      ),
    );
    document.getElementById('helper-approval-heading')?.focus();
  }

  async function viewAsHelper(code) {
    if (code === null) return renderHelper('コードの形が違います。もう一度お試しください。');
    const result = await call('POST', '/api/recovery/helper/view', { code });
    if (result.status === 200) {
      return renderHelperApproval(code, result.data.relationshipId, result.data.readyAt);
    }
    if (result.status === 409) return renderHelper(NOT_ELIGIBLE_TEXT);
    renderHelper(
      result.status === 429
        ? failureText(result)
        : 'このコードでは承認できません。期限が切れたか、すでに使われています。新しい端末で、新しいコードを出してもらってください。',
    );
  }

  async function acceptInvite(code, name) {
    if (code === null) return renderHelper('コードの形が違います。もう一度お試しください。');
    if (name === null) return renderHelper('先に、この人の呼び名を入力してください。');
    const result = await call('POST', '/api/helpers/accept', { code });
    if (result.status !== 200) {
      return renderHelper(
        result.status === 429
          ? failureText(result)
          : 'この招待は受け入れられませんでした。期限が切れたか、すでに使われています。招待した人に、新しい招待を作ってもらってください。',
      );
    }
    saveName(result.data.relationshipId, name);
    show(
      el('h2', { id: 'accepted-heading', tabindex: '-1' }, '招待を受け入れました'),
      el(
        'p',
        {},
        'この画面を、招待した人に見せてください。招待した人が、自分の呼び名を確かめてから、協力者として確定します。',
      ),
      el('p', { className: 'shown-name' }, `${name}さん`),
      el('button', { type: 'button', onclick: () => renderHelper() }, '協力者の画面に戻る'),
    );
    document.getElementById('accepted-heading')?.focus();
  }

  async function renderHelper(note) {
    const result = await call('GET', '/api/recovery/settings');
    if (result.status === 401) return loginForRecovery(renderHelper, note);
    if (result.status !== 200) {
      return show(status('読み込めませんでした。しばらくしてから、もう一度お試しください。'));
    }
    const ownerName = nameInput('invite-owner-name');
    const helping = result.data.helping ?? [];
    show(
      note ? status(note) : null,
      el(
        'section',
        { 'aria-labelledby': 'helper-approve-heading' },
        el('h2', { id: 'helper-approve-heading' }, '協力している人の回復を承認する'),
        el(
          'p',
          {},
          '協力している人と直接会い、その人の新しい端末に出ている QR を読み取ります。電話、ビデオ通話、メッセージで伝えられたコードは使わないでください。',
        ),
        codeEntry('helper-approve-code', '新しい端末に出ているコード', viewAsHelper),
      ),
      el(
        'section',
        { 'aria-labelledby': 'helper-accept-heading' },
        el('h2', { id: 'helper-accept-heading' }, '協力者の招待を受け入れる'),
        el(
          'p',
          {},
          '招待した人と直接会い、その人の端末に出ている QR を読み取ります。先に、その人の呼び名を入力してください（この端末の中だけに保存し、割符のサーバーには送りません）。',
        ),
        el('label', { for: 'invite-owner-name' }, 'この人の呼び名'),
        ownerName,
        codeEntry('helper-invite-code', '招待コード', (code) =>
          acceptInvite(code, cleanName(ownerName.value)),
        ),
      ),
      el(
        'section',
        { 'aria-labelledby': 'helping-heading' },
        el('h2', { id: 'helping-heading' }, '協力している人'),
        helping.length === 0
          ? el('p', {}, 'いません。')
          : el(
              'ul',
              { className: 'helping' },
              ...helping.map((entry) =>
                el(
                  'li',
                  {},
                  el(
                    'span',
                    {},
                    nameOf(entry.relationshipId) ??
                      '呼び名がありません（この端末で受け入れていない可能性があります）',
                  ),
                  el(
                    'span',
                    { className: 'muted' },
                    `協力者になった日時：${DATE.format(new Date(entry.createdAt))}`,
                  ),
                ),
              ),
            ),
      ),
    );
  }

  if (root.dataset.page === 'approval') {
    void renderApprovals();
  } else if (root.dataset.page === 'desk') {
    void renderDesk();
  } else if (root.dataset.page === 'recover') {
    renderRecover();
  } else if (root.dataset.page === 'recovery') {
    void renderRecoverySettings();
  } else if (root.dataset.page === 'helper') {
    void renderHelper();
  } else if (root.dataset.page === 'interaction') {
    const uid = root.dataset.uid ?? '';
    if (company) company.setAttribute('aria-label', '接続先の企業');
    if (root.dataset.prompt === 'consent') renderConsent(uid);
    else renderInteractionLogin(uid);
  } else {
    void renderHome();
  }
})();
