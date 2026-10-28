// relay の設定（ADR 0021、ADR 0022）。テナントごとの登録（送信元ロックの d=、s=、公開鍵）は、静的な設定で受け取り、
// 起動の時点で検査する（鍵は長さと種類）。値は企業のもので、利用者の連絡先は入らない。

import { fromBase64Url, parseTenantId, type TenantId } from '@pii-token-vault/warifu-core';

export interface RelayTenant {
  readonly tenantId: TenantId;
  /** 中継したメールの From に出す企業名（登録簿の値。DESIGN.md 原則2）。改行や制御文字を含まない。 */
  readonly displayName: string;
  /** 別名と返信用のアドレスのドメイン。テナントごとに分ける（不変条件5）。署名の d= にも使う。 */
  readonly relayDomain: string;
  /** 送信元ロックの登録（plan 3-2）。 */
  readonly sender: {
    /** 企業の DKIM の d=。完全に一致するものだけを受け付ける。 */
    readonly domain: string;
    /** 企業の DKIM の s=。 */
    readonly selector: string;
    /** 企業の DKIM の公開鍵（SubjectPublicKeyInfo の DER の base64）。DNS は引かず、この鍵だけで検証する。 */
    readonly publicKey: string;
  };
}

export interface RelayConfig {
  readonly tenants: readonly RelayTenant[];
  /** relay の DKIM と ARC のセレクタ。 */
  readonly selector: string;
  /** ARC-Authentication-Results の authserv-id。 */
  readonly authservId: string;
  /** 割符からの知らせ（宛先確認など）の From のドメイン。署名の d= にも使う。 */
  readonly noticeDomain: string;
  /** 受け付けるメールの大きさの上限（バイト）。既定は 10 MiB（ADR 0021 の仮置き）。 */
  readonly maxMessageBytes?: number;
}

export class RelayConfigError extends Error {
  override name = 'RelayConfigError';
}

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SELECTOR_PATTERN = /^[a-z0-9](?:[a-z0-9_-]{0,62})$/;
// 表示名は、制御文字、改行、引用符、山括弧、バックスラッシュを含まない64文字まで（ヘッダーの差し込みを防ぐ）。
const DISPLAY_NAME_PATTERN = /^[^\p{Cc}\p{Cf}"<>\\]{1,64}$/u;
export const DEFAULT_MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
/** Ed25519 の SubjectPublicKeyInfo の DER は44バイト。RSA は 2048 ビットで294バイト以上。 */
const ED25519_SPKI_BYTES = 44;
const RSA2048_SPKI_MIN_BYTES = 294;
/** 鍵の種類（AlgorithmIdentifier）。Ed25519（1.3.101.112）と rsaEncryption（1.2.840.113549.1.1.1）だけ（ADR 0022）。 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const RSA_ALGORITHM_ID = Buffer.from('300d06092a864886f70d0101010500', 'hex');

/** DKIM の公開鍵が、不変条件9で受け付ける種類（Ed25519 か、2048 ビット以上の RSA）か。 */
function acceptableDkimKey(spki: Uint8Array): boolean {
  const der = Buffer.from(spki);
  if (der.byteLength === ED25519_SPKI_BYTES) return der.subarray(0, 12).equals(ED25519_SPKI_PREFIX);
  return (
    der.byteLength >= RSA2048_SPKI_MIN_BYTES &&
    der[0] === 0x30 &&
    der[1] === 0x82 &&
    der.subarray(4, 4 + RSA_ALGORITHM_ID.byteLength).equals(RSA_ALGORITHM_ID)
  );
}

function domain(value: unknown): string {
  if (typeof value !== 'string' || !DOMAIN_PATTERN.test(value)) {
    throw new RelayConfigError('ドメインの形が違う');
  }
  return value;
}

export interface ParsedRelayConfig {
  readonly byRelayDomain: ReadonlyMap<string, RelayTenant>;
  readonly tenants: readonly RelayTenant[];
  readonly selector: string;
  readonly authservId: string;
  readonly noticeDomain: string;
  readonly maxMessageBytes: number;
}

export function parseRelayConfig(config: RelayConfig): ParsedRelayConfig {
  const byRelayDomain = new Map<string, RelayTenant>();
  const tenantIds = new Set<string>();
  for (const tenant of config.tenants ?? []) {
    const tenantId = parseTenantId(tenant.tenantId);
    if (tenantIds.has(tenantId)) throw new RelayConfigError('テナントが重複している');
    tenantIds.add(tenantId);
    if (
      typeof tenant.displayName !== 'string' ||
      !DISPLAY_NAME_PATTERN.test(tenant.displayName.trim())
    ) {
      throw new RelayConfigError('企業名の形が違う');
    }
    const relayDomain = domain(tenant.relayDomain);
    if (byRelayDomain.has(relayDomain))
      throw new RelayConfigError('relay のドメインが重複している');
    const senderDomain = domain(tenant.sender?.domain);
    if (
      typeof tenant.sender?.selector !== 'string' ||
      !SELECTOR_PATTERN.test(tenant.sender.selector)
    ) {
      throw new RelayConfigError('セレクタの形が違う');
    }
    let spki: Uint8Array;
    try {
      spki = fromBase64Url(
        tenant.sender.publicKey.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      );
    } catch {
      throw new RelayConfigError('公開鍵の形が違う');
    }
    if (spki.byteLength !== ED25519_SPKI_BYTES && spki.byteLength < RSA2048_SPKI_MIN_BYTES) {
      throw new RelayConfigError('公開鍵の長さが足りない');
    }
    if (!acceptableDkimKey(spki)) {
      throw new RelayConfigError('公開鍵の種類が違う（RSA か Ed25519 だけ）');
    }
    byRelayDomain.set(
      relayDomain,
      Object.freeze({
        tenantId,
        displayName: tenant.displayName.trim(),
        relayDomain,
        sender: Object.freeze({
          domain: senderDomain,
          selector: tenant.sender.selector,
          publicKey: tenant.sender.publicKey,
        }),
      }),
    );
  }
  if (typeof config.selector !== 'string' || !SELECTOR_PATTERN.test(config.selector)) {
    throw new RelayConfigError('relay のセレクタの形が違う');
  }
  const max = config.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  if (!Number.isSafeInteger(max) || max < 1024 || max > 50 * 1024 * 1024) {
    throw new RelayConfigError('大きさの上限が範囲の外');
  }
  return Object.freeze({
    byRelayDomain,
    tenants: Object.freeze([...byRelayDomain.values()]),
    selector: config.selector,
    authservId: domain(config.authservId),
    noticeDomain: domain(config.noticeDomain),
    maxMessageBytes: max,
  });
}
