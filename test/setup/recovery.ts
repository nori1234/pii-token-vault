// 回復のテストの補助（ADR 0003、ADR 0027）。持ち主の回復コードの作成、協力者の招待と確定、新しい端末での開始と
// 読み直し、協力者の承認、取消を、利用者のブラウザ役の HTTP で行う。どれも承認用のオリジンのルートだけを使う。

import { Browser, type HttpResult, type TestIdp } from './idp.ts';

/** 内容に結び付いた儀式（options → パスキーのアサーション → verify）を、承認用のオリジンで行う。 */
export async function bound(
  browser: Browser,
  path: string,
  body: Record<string, unknown> = {},
  overrides: { readonly origin?: string; readonly uv?: boolean } = {},
): Promise<HttpResult> {
  const options = await browser.post(`${path}/options`, body);
  if (options.status !== 200) return options;
  const response = browser.authenticator.get(options.json.options as never, undefined, {
    origin: overrides.origin ?? browser.origin,
    ...(overrides.uv === undefined ? {} : { uv: overrides.uv }),
  });
  return browser.post(`${path}/verify`, { ceremonyId: options.json.ceremonyId, response });
}

/** 回復コードを作る（作り直す）。平文のコードを返す。 */
export async function issueCode(approval: Browser): Promise<string> {
  const result = await bound(approval, '/api/recovery-code');
  if (result.status !== 200) throw new Error(`回復コードを作れない（${result.status}）`);
  return String(result.json.code);
}

/** 持ち主が招待を作り、協力者が受け入れ、持ち主が確定する。協力関係の ID を返す。 */
export async function makeHelper(owner: Browser, helper: Browser): Promise<string> {
  const invite = await owner.post('/api/helpers/invite');
  if (invite.status !== 200) throw new Error(`招待を作れない（${invite.status}）`);
  const accepted = await helper.post('/api/helpers/accept', { code: invite.json.code });
  if (accepted.status !== 200) throw new Error(`招待を受け入れられない（${accepted.status}）`);
  const confirmed = await bound(owner, '/api/helpers/confirm', { code: invite.json.code });
  if (confirmed.status !== 200) throw new Error(`協力者を確定できない（${confirmed.status}）`);
  return String(accepted.json.relationshipId);
}

export interface NewDevice {
  readonly browser: Browser;
  readonly start: HttpResult;
  readonly register?: HttpResult;
}

/** 新しい端末（セッションのないブラウザ役）で、回復コードから回復を始める。回復待ちのパスキーを作る。 */
export async function startOnNewDevice(
  t: TestIdp,
  code: unknown,
  browser: Browser = new Browser(t.approvalOrigin),
): Promise<NewDevice> {
  const start = await browser.post('/api/recovery/start', { code });
  if (start.status !== 200) return { browser, start };
  const response = browser.authenticator.create(start.json.options as never);
  const register = await browser.post('/api/recovery/register', {
    ceremonyId: start.json.ceremonyId,
    response,
  });
  return { browser, start, register };
}

/** 新しい端末で、回復待ちのパスキーを使って状態を読み直す（待機の後は成立させる）。 */
export async function resume(device: Browser): Promise<HttpResult> {
  const options = await device.post('/api/recovery/resume/options');
  if (options.status !== 200) return options;
  const response = device.authenticator.get(options.json.options as never, undefined, {
    origin: device.origin,
  });
  return device.post('/api/recovery/resume/verify', {
    ceremonyId: options.json.ceremonyId,
    response,
  });
}

/** 協力者が、新しい端末に出た結び付けのコードで承認する。 */
export function helperApprove(helper: Browser, code: unknown): Promise<HttpResult> {
  return bound(helper, '/api/recovery/helper', { code });
}

/** 持ち主の登録済みの端末で、進行中の回復を取り消す。 */
export async function cancelRecovery(owner: Browser): Promise<HttpResult> {
  const settings = await owner.get('/api/recovery/settings');
  const attempt = settings.json.attempt as { id: string } | null;
  if (attempt === null) throw new Error('進行中の回復がない');
  return bound(owner, '/api/recovery/cancel', { id: attempt.id });
}

/** 結び付けのコード（新しい端末に出たもの）を、応答から取り出す。 */
export function bindingCodeOf(result: HttpResult | undefined): string {
  const binding = result?.json.binding as { code?: unknown } | undefined;
  if (typeof binding?.code !== 'string') throw new Error('結び付けのコードがない');
  return binding.code;
}
