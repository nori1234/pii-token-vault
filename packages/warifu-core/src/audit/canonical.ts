// 監査ログの MAC にかける形（ADR 0016）。
//
//   scope         = ('tenant', tenant_id) または ('user', user_id)
//   content_mac_i = HMAC(k, lp('warifu/audit/content/v1', scope の種類, scope の ID, scope_seq, occurred_at のミリ秒,
//                              service, event_type, canonicalJson(attrs)))
//   mac_i         = HMAC(k, lp('warifu/audit/link/v1', seq, prev_mac_i, content_mac_i))
//   prev_mac_1    = 32バイトの0
// k は鍵サービスの mac(audit_chain) の鍵。DB だけを持つ攻撃者は、MAC を計算し直せない。

import { canonicalJson, lengthPrefixed, u64be } from '../encoding.ts';
import { uuidBytes } from '../ids.ts';

export const AUDIT_MAC_BYTES = 32;
export const ZERO_MAC: Uint8Array = new Uint8Array(AUDIT_MAC_BYTES);

export interface AuditContent {
  readonly scopeKind: 'tenant' | 'user';
  readonly scopeId: string;
  readonly scopeSeq: bigint;
  readonly occurredAt: Date;
  readonly service: string;
  readonly eventType: string;
  readonly attrs: Readonly<Record<string, string | number | boolean>>;
}

export function contentMessage(content: AuditContent): Uint8Array {
  const millis = content.occurredAt.getTime();
  if (!Number.isSafeInteger(millis) || millis < 0) throw new RangeError('時刻が範囲の外');
  return lengthPrefixed([
    'warifu/audit/content/v1',
    content.scopeKind,
    uuidBytes(content.scopeId),
    u64be(content.scopeSeq),
    u64be(BigInt(millis)),
    content.service,
    content.eventType,
    canonicalJson(content.attrs),
  ]);
}

export function linkMessage(seq: bigint, prevMac: Uint8Array, contentMac: Uint8Array): Uint8Array {
  return lengthPrefixed(['warifu/audit/link/v1', u64be(seq), prevMac, contentMac]);
}
