// 画面の HTML と配信物（DESIGN.md、plan 2章「ブラウザ側」、ADR 0018）。
//
// - CSP は応答ごとの nonce と 'strict-dynamic'。Trusted Types を必須にし、ポリシーを1つも作らせない
//   （'none'）。画面は DOM の API（textContent、createElement）だけで組み、文字列を HTML として解釈させない。
// - テナント由来の文字列（企業名）は、登録簿の値を、エスケープしたテキストとしてだけ出す（DESIGN.md 原則2）。
// - 配信物（HTML、JavaScript）には、資格情報、鍵、API キーを含めない。判断はすべてサーバーで行う（plan 2章）。
// - 外部のフォントや CDN は使わない（DESIGN.md 5章）。

import { readFileSync } from 'node:fs';
import { toBase64Url } from '@pii-token-vault/warifu-core';

export const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
});

/** HTML の応答の CSP。nonce は応答ごとの乱数。 */
export function htmlCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ].join('; ');
}

/** HTML 以外（JSON、配信物）の CSP。 */
export const DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

const ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export function newNonce(bytes: Uint8Array): string {
  return toBase64Url(bytes);
}

export interface PageInput {
  readonly nonce: string;
  readonly page: 'home' | 'interaction';
  /** インタラクションの uid（英数字と - _ だけ。interactionDetails で確かめた値）。 */
  readonly uid?: string;
  readonly prompt?: 'login' | 'consent';
  /** 登録簿の企業名。 */
  readonly companyName?: string;
}

export function renderPage(input: PageInput): string {
  const attrs = [`data-page="${input.page}"`];
  if (input.uid !== undefined) attrs.push(`data-uid="${escapeHtml(input.uid)}"`);
  if (input.prompt !== undefined) attrs.push(`data-prompt="${input.prompt}"`);
  const company =
    input.companyName === undefined
      ? ''
      : `<p class="company" id="company">${escapeHtml(input.companyName)}</p>`;
  return [
    '<!doctype html>',
    '<html lang="ja">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>割符</title>',
    '<link rel="stylesheet" href="/assets/app.css">',
    '</head>',
    '<body>',
    `<main id="app" ${attrs.join(' ')}>`,
    '<h1 id="heading" tabindex="-1">割符</h1>',
    company,
    '<div id="view"></div>',
    '<noscript><p>この画面には JavaScript が必要です。</p></noscript>',
    '</main>',
    `<script nonce="${input.nonce}" src="/assets/webauthn.js"></script>`,
    `<script nonce="${input.nonce}" src="/assets/app.js"></script>`,
    '</body>',
    '</html>',
  ].join('\n');
}

export interface Assets {
  readonly appJs: Buffer;
  readonly appCss: Buffer;
  readonly webauthnJs: Buffer;
}

/**
 * @simplewebauthn/browser の UMD 版（グローバルの SimpleWebAuthnBrowser を定義する1ファイル）を読む。
 * 配るファイルが、インストールされた版と同じビルドであることを、先頭の注記で確かめる（捨てスパイク1と同じ）。
 */
function loadWebAuthnBundle(): Buffer {
  const entry = import.meta.resolve('@simplewebauthn/browser');
  const packageJson: unknown = JSON.parse(readFileSync(new URL('../package.json', entry), 'utf8'));
  const version =
    typeof packageJson === 'object' && packageJson !== null && 'version' in packageJson
      ? String(packageJson.version)
      : '';
  const bundle = readFileSync(new URL('../dist/bundle/index.umd.min.js', entry));
  const banner = `/* [@simplewebauthn/browser@${version}] */`;
  if (version === '' || !bundle.subarray(0, banner.length).equals(Buffer.from(banner))) {
    throw new Error('@simplewebauthn/browser の UMD 版が見つからないか、版が一致しない');
  }
  return bundle;
}

export function loadAssets(): Assets {
  const publicDir = new URL('../public/', import.meta.url);
  return Object.freeze({
    appJs: readFileSync(new URL('app.js', publicDir)),
    appCss: readFileSync(new URL('app.css', publicDir)),
    webauthnJs: loadWebAuthnBundle(),
  });
}
