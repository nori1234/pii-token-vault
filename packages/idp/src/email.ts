// 本物のメールの登録と変更（plan 4章、DESIGN.md 2章「メールアドレスの登録と変更」、ADR 0018）。
//
// 1. 呼ぶ側で step-up（5分以内の認証）を確かめる。
// 2. 入力を整え、鍵サービスで暗号化する（contact、その利用者の文脈）。平文は、このリクエストのメモリの中だけ。
// 3. 確認コード（8桁）を作り、mac(email_verify_code) だけを DB に置く。コードは Mailer（M4 で relay）に渡す。
// 4. コードの照合が通ったら、確認中の暗号文を現在のものにし、前のものがあれば旧アドレスへ知らせる（リンクを含めない）。
//
// 不変条件10：応答は、そのアドレスがほかのアカウントで使われているかどうかで変わらない。P0 では、同じアドレスを
// 複数のアカウントに登録することを拒否しない（一意性の検査をしない）ので、分岐そのものがない（ADR 0018）。
// 不変条件1(d)：アドレスは配送先としてだけ使う。アカウントを探すことにも、本人と見なすことにも使わない。

import {
  lengthPrefixed,
  randomBytesOf,
  utf8,
  uuidBytes,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import type { Mailer } from './mailer.ts';
import type { RateLimiter } from './rate-limit.ts';
import { type ConfirmResult, confirmPendingEmail, putPendingEmail, type RepoDeps } from './repo.ts';

export const CODE_DIGITS = 8;
export const CODE_TTL_SECONDS = 15 * 60;
const CODE_PATTERN = /^[0-9]{8}$/;
const EMAIL_LABEL = 'warifu/email-verify/v1';

export interface EmailKeyClient {
  encryptContact(input: {
    readonly userId: WarifuUserId;
    readonly plaintext: Uint8Array;
  }): Promise<Uint8Array>;
  mac(purpose: 'email_verify_code', message: Uint8Array): Promise<Uint8Array>;
}

/**
 * 入力を整える。前後の空白を除き、ドメインだけを小文字にする（ローカル部は変えない）。
 * 形が違えば undefined。到達できるかは、宛先確認で確かめる。
 */
export function normalizeEmail(input: unknown): string | undefined {
  if (typeof input !== 'string') return undefined;
  const value = input.trim();
  if (value.length < 3 || value.length > 254) return undefined;
  // 空白、制御文字、山かっこ、引用符、カンマ、セミコロン、バックスラッシュは受け付けない（ヘッダーの注入に備える）。
  if (/[\s\p{Cc}\p{Cf}<>"',;\\()[\]]/u.test(value)) return undefined;
  const at = value.lastIndexOf('@');
  if (at < 1 || at !== value.indexOf('@')) return undefined;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return undefined;
  }
  if (
    !/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(
      domain,
    )
  ) {
    return undefined;
  }
  return `${local}@${domain}`;
}

/** 偏りのない8桁の数字（棄却法）。 */
export function newVerificationCode(): string {
  let code = '';
  while (code.length < CODE_DIGITS) {
    for (const byte of randomBytesOf(16)) {
      if (byte < 250 && code.length < CODE_DIGITS) code += String(byte % 10);
    }
  }
  return code;
}

export function codeMessage(userId: WarifuUserId, code: string): Uint8Array {
  return lengthPrefixed([EMAIL_LABEL, uuidBytes(userId), code]);
}

export interface EmailFlowDeps {
  readonly repo: RepoDeps;
  readonly keys: EmailKeyClient;
  readonly mailer: Mailer;
  readonly limiter: RateLimiter;
}

export type StartResult = 'accepted' | 'invalid_input' | 'rate_limited';

export async function startEmailVerification(
  deps: EmailFlowDeps,
  input: { readonly userId: WarifuUserId; readonly email: unknown; readonly ip: string },
): Promise<StartResult> {
  const email = normalizeEmail(input.email);
  if (email === undefined) return 'invalid_input';
  const byUser = deps.limiter.take('emailSendByUser', input.userId);
  const byIp = deps.limiter.take('emailSendByIp', input.ip);
  if (!byUser || !byIp) return 'rate_limited';
  const ciphertext = await deps.keys.encryptContact({
    userId: input.userId,
    plaintext: utf8(email),
  });
  const code = newVerificationCode();
  const codeMac = await deps.keys.mac('email_verify_code', codeMessage(input.userId, code));
  const expiresAt = new Date(deps.repo.now().getTime() + CODE_TTL_SECONDS * 1000);
  await putPendingEmail(deps.repo, input.userId, { ciphertext, codeMac, expiresAt });
  await deps.mailer.sendToUser({ kind: 'email_verification', userId: input.userId, code });
  return 'accepted';
}

export async function confirmEmailVerification(
  deps: EmailFlowDeps,
  input: { readonly userId: WarifuUserId; readonly code: unknown },
): Promise<ConfirmResult> {
  if (typeof input.code !== 'string' || !CODE_PATTERN.test(input.code)) return 'invalid';
  const codeMac = await deps.keys.mac('email_verify_code', codeMessage(input.userId, input.code));
  const result = await confirmPendingEmail(deps.repo, input.userId, codeMac);
  if (result === 'changed') {
    // 旧アドレスへは、操作のリンクもコードも含まない知らせだけ（plan 4章）。
    await deps.mailer.sendToUser({ kind: 'email_changed_notice', userId: input.userId });
  }
  return result;
}
