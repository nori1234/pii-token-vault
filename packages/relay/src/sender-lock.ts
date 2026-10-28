// 送信元ロック（plan 3-2、ADR 0021）。企業から別名あてに来たメールを、登録した DKIM の鍵だけで検証する。
//
// - DNS は引かない。mailauth に渡すリゾルバは、登録した (d=, s=) の公開鍵だけを返す（不変条件7）。
// - a= は rsa-sha256 と ed25519-sha256 だけ（不変条件9。rsa-sha1 は不合格）。RSA の鍵は 2048 ビット以上。
// - d= は登録と完全に一致。From のドメインは d= と同じか、その下（DMARC の relaxed の整合）。
// - l= 付きの署名は数えない。h= に from、to、subject、date、message-id を含み、from、to、subject を重ねて署名する。
// - From は1つ。To と Subject は1つまで（重複は拒否）。
// - t= は必須で、7日以内（未来は5分まで）。x= があれば、期限の前であること（ADR 0021 の仮置き）。
// 結果は、別名が生きているかどうかに関係なく決まる（不変条件10）。

import { dkimVerify } from 'mailauth/lib/dkim/verify.js';
import type { RelayTenant } from './config.ts';
import { fieldsNamed, headerValue, type ParsedMessage } from './mime.ts';

export const SIGNATURE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const REQUIRED_SIGNED = ['from', 'to', 'subject', 'date', 'message-id'];
const OVERSIGNED = ['from', 'to', 'subject'];
const ALLOWED_ALGORITHMS = new Set(['rsa-sha256', 'ed25519-sha256']);
const ED25519_SPKI_BYTES = 44;

export type SenderLockResult =
  | {
      readonly ok: true;
      /** 署名の b=（空白を除いたもの）。リプレイの判定に使う。 */
      readonly signature: string;
      readonly signedAt: Date;
      readonly expiresAt: Date | undefined;
      /** From のアドレス（mailauth が読んだもの）。 */
      readonly fromAddress: string;
      /** 署名した（h= に並んだ）ヘッダーの名前（小文字）。 */
      readonly signedHeaders: readonly string[];
    }
  | { readonly ok: false; readonly reason: SenderLockFailure };

export type SenderLockFailure =
  | 'no_valid_signature'
  | 'header_count'
  | 'from_not_aligned'
  | 'signature_time';

function tagsOf(value: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of value.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    tags.set(part.slice(0, at).trim().toLowerCase(), part.slice(at + 1).replace(/\s+/g, ''));
  }
  return tags;
}

function keyRecord(publicKey: string): string {
  const der = Buffer.from(publicKey, 'base64');
  if (der.byteLength === ED25519_SPKI_BYTES) {
    return `v=DKIM1; k=ed25519; p=${der.subarray(12).toString('base64')}`;
  }
  return `v=DKIM1; k=rsa; p=${der.toString('base64')}`;
}

function pinnedResolver(tenant: RelayTenant) {
  const name = `${tenant.sender.selector}._domainkey.${tenant.sender.domain}`;
  const record = keyRecord(tenant.sender.publicKey);
  return async (domain: string, rrtype: string) => {
    if (rrtype === 'TXT' && domain.toLowerCase() === name) return [[record]];
    const error = new Error('not found') as Error & { code: string };
    error.code = 'ENOTFOUND';
    throw error;
  };
}

function aligned(fromDomain: string, signingDomain: string): boolean {
  return fromDomain === signingDomain || fromDomain.endsWith(`.${signingDomain}`);
}

export async function verifySenderLock(
  raw: Buffer,
  message: ParsedMessage,
  tenant: RelayTenant,
  now: Date,
): Promise<SenderLockResult> {
  const from = fieldsNamed(message.headers, 'from');
  if (
    from.length !== 1 ||
    fieldsNamed(message.headers, 'to').length > 1 ||
    fieldsNamed(message.headers, 'subject').length > 1
  ) {
    return { ok: false, reason: 'header_count' };
  }
  const verified = await dkimVerify(raw, {
    resolver: pinnedResolver(tenant),
    minBitLength: 2048,
    curTime: now,
    rejectRsaSha1: true,
  });
  if (verified.fromFields !== 1 || verified.headerFrom.length !== 1) {
    return { ok: false, reason: 'header_count' };
  }
  const fromAddress = verified.headerFrom[0] ?? '';
  const fromDomain = fromAddress.slice(fromAddress.lastIndexOf('@') + 1).toLowerCase();

  const signatures = fieldsNamed(message.headers, 'dkim-signature').map((h) =>
    tagsOf(headerValue(h)),
  );
  const counts = new Map<string, number>();
  for (const h of message.headers) counts.set(h.key, (counts.get(h.key) ?? 0) + 1);

  for (const result of verified.results) {
    if (result.status.result !== 'pass') continue;
    if (!ALLOWED_ALGORITHMS.has(result.algo ?? '')) continue;
    const d = (result.signingDomain ?? '').toLowerCase();
    if (d !== tenant.sender.domain || result.selector !== tenant.sender.selector) continue;
    const tags = signatures.find((t) => t.get('b') === result.signature);
    if (tags === undefined || tags.has('l')) continue;
    const signed = (tags.get('h') ?? '').toLowerCase().split(':');
    const signedCount = (name: string) => signed.filter((n) => n === name).length;
    if (!REQUIRED_SIGNED.every((name) => signedCount(name) >= 1)) continue;
    if (!OVERSIGNED.every((name) => signedCount(name) > (counts.get(name) ?? 0))) continue;
    if (!aligned(fromDomain, d)) return { ok: false, reason: 'from_not_aligned' };
    const t = Number(tags.get('t'));
    const x = tags.has('x') ? Number(tags.get('x')) : undefined;
    if (!Number.isSafeInteger(t)) return { ok: false, reason: 'signature_time' };
    const signedAt = new Date(t * 1000);
    if (
      signedAt.getTime() > now.getTime() + FUTURE_SKEW_MS ||
      signedAt.getTime() < now.getTime() - SIGNATURE_MAX_AGE_MS ||
      (x !== undefined && (!Number.isSafeInteger(x) || x * 1000 <= now.getTime()))
    ) {
      return { ok: false, reason: 'signature_time' };
    }
    return {
      ok: true,
      signature: tags.get('b') ?? '',
      signedAt,
      expiresAt: x === undefined ? undefined : new Date(x * 1000),
      fromAddress,
      signedHeaders: signed,
    };
  }
  return { ok: false, reason: 'no_valid_signature' };
}
