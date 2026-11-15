// demo-rp の画面（DESIGN.md 2章「demo-rp：利用者の窓口受付」「demo-rp：窓口担当者」、3章の警告文 B と固定文 S）。
// - サーバーで HTML を組み、値はすべてエスケープしたテキストとして出す。インラインのスクリプトとスタイルは使わない。
// - メール、電話、氏名、住所の入力欄と検索欄を置かない（DESIGN.md 原則3）。
// - 申請ID、移行専用ID、会員参照は、画面にも URL にも出さない（不変条件4、ADR 0028 の O-87）。

const ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function esc(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

/** DESIGN.md 3章の警告文 B（窓口の受付）。文言は変えない。 */
export const WARNING_B =
  '受付番号だけでは操作を許可しません。相手からの電話やメッセージで操作を求められたら、正規の窓口へ自分から連絡してください。';
/** DESIGN.md 3章の固定文 S（窓口担当者）。 */
export const FIXED_S =
  '利用者が自分から公式窓口に連絡したときだけ、この手順を案内します。こちらからの電話やメッセージで承認を求めてはいけません。';
export const STAFF_HIGH_RISK = '利用者ご自身の端末での確認が必要です';
export const STAFF_FAILED =
  '本人確認ができませんでした。ご案内できるのは、一般的な案内とアカウントの一時停止だけです。';
export const DEMO_NOTE =
  'これはデモ用の架空の企業です。本番では使わないでください。実在する口座や個人の情報を入力しないでください。';

/** 画面の上に出す固定の知らせ（?n= のコードで選ぶ。値は入れない）。 */
export const NOTICES: Readonly<Record<string, string>> = Object.freeze({
  signed_in: 'ログインしました。',
  signed_out: 'ログアウトしました。',
  failed: '手続きを完了できませんでした。もう一度、初めからお試しください。',
  declined: '割符の画面で承認されなかったため、何も変更していません。',
  payout_changed: '出金先を変更しました。',
  payout_invalid: '入力した口座の形が違います。数字の桁数を確かめてください。',
  payout_hold:
    '割符のアカウントを回復した後の8日間は、出金先の変更を受け付けません。期間が過ぎてから、もう一度お試しください。',
  payout_stale:
    'この申請は、期限が切れたか、新しい申請に置き換わっています。もう一度、初めからお試しください。',
  desk_granted: '窓口の担当者に、選んだ注文1件の状態を伝えることを許可しました（この1回だけ）。',
  desk_not_found: '受付番号を確かめられませんでした。番号を確かめて、もう一度入力してください。',
  desk_limited:
    '受付番号の入力の回数が上限に達しました。しばらくしてから、もう一度お試しください。',
  link_waiting:
    '旧会員の引き継ぎを申請しました。待機の時間（24時間）が終わった後に、もう一度この画面で確かめるまで、引き継ぎは確定しません。',
  link_not_ready: '待機がまだ終わっていないため、引き継ぎを確定できません。',
  link_done:
    '旧会員を、この割符のアカウントに引き継ぎました。旧パスキーでの確認は、今後は受け付けません。',
  link_cancelled: '引き継ぎの申請を取り消しました。',
  link_refused: '引き継ぎを始められませんでした。すでに引き継ぎ済みか、進行中の申請があります。',
  legacy_required: '先に、旧パスキーで確かめてください。',
  login_required: '先に、割符でログインしてください。',
});

export interface PageInput {
  readonly company: string;
  readonly title: string;
  readonly notice?: string | undefined;
  /** エスケープ済みの HTML。 */
  readonly body: string;
  readonly script?: boolean;
}

export function page(input: PageInput): string {
  const notice =
    input.notice !== undefined && Object.hasOwn(NOTICES, input.notice)
      ? `<p class="notice" role="status" id="notice">${esc(NOTICES[input.notice] ?? '')}</p>`
      : '';
  return [
    '<!doctype html>',
    '<html lang="ja">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${esc(input.title)}｜${esc(input.company)}</title>`,
    '<link rel="stylesheet" href="/assets/demo.css">',
    '</head>',
    '<body>',
    `<header><p class="company" id="company">${esc(input.company)}</p><p class="demo-note">${esc(DEMO_NOTE)}</p></header>`,
    '<main>',
    `<h1>${esc(input.title)}</h1>`,
    notice,
    input.body,
    '</main>',
    ...(input.script === true
      ? ['<script src="/assets/webauthn.js"></script>', '<script src="/assets/demo.js"></script>']
      : []),
    '</body>',
    '</html>',
  ].join('\n');
}

/** POST のボタン1つのフォーム。 */
export function postButton(
  action: string,
  label: string,
  hidden: Readonly<Record<string, string>> = {},
): string {
  const fields = Object.entries(hidden)
    .map(([name, value]) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`)
    .join('');
  return `<form method="post" action="${esc(action)}">${fields}<button type="submit">${esc(label)}</button></form>`;
}

export function cspOf(warifuOrigins: readonly string[]): string {
  return [
    "default-src 'none'",
    "style-src 'self'",
    "script-src 'self'",
    "connect-src 'self'",
    // ログインと承認は、割符の画面へのリダイレクトで進む（フォームの送信の後の 303）。
    `form-action 'self' ${warifuOrigins.join(' ')}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}
