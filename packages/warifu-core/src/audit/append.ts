// 監査ログへの追記（CAP-17、ADR 0016）。
//
// 1. 属性を定義で検査する。
// 2. pg_advisory_xact_lock で、全体で1つの鍵を取る（追記を直列にする。plan 9章）。
// 3. 全体のチェーンの先頭と、いまの範囲の先頭を読む（READ COMMITTED なので、ロックの後の文は前の追記のコミットを見る）。
// 4. content_mac と mac を鍵サービスで計算し、audit.chain、audit.events の順に INSERT する。
// ロックはコミットまで持つので、追記はトランザクションの最後の文にする。範囲（テナントか利用者）は境界から決まり、
// 呼び出し側は渡せない。

import { sql } from '../db/sql.ts';
import type { Tx } from '../db/types.ts';
import { canonicalJson } from '../encoding.ts';
import { AUDIT_MAC_BYTES, contentMessage, linkMessage, ZERO_MAC } from './canonical.ts';
import { type AuditAttrs, type AuditEventDef, checkAuditAttrs } from './events.ts';

/** 3つの鍵のクライアントは、どれも mac('audit_chain', …) を持つので、そのまま渡せる。 */
export interface AuditMacClient {
  mac(purpose: 'audit_chain', message: Uint8Array): Promise<Uint8Array>;
}

/** 監査ログの追記を直列にするアドバイザリロックの鍵（"WARIFU" と 0x0001）。 */
export const AUDIT_LOCK_KEY = 6287397029451988993n;

export async function auditMac(keys: AuditMacClient, message: Uint8Array): Promise<Uint8Array> {
  const mac = await keys.mac('audit_chain', message);
  if (!(mac instanceof Uint8Array) || mac.byteLength !== AUDIT_MAC_BYTES) {
    throw new RangeError('MAC の長さが違う');
  }
  return mac;
}

/** いまの境界（tx.boundary）の範囲で1件を追記し、全体の通番を返す。 */
export async function appendAudit<D extends AuditEventDef>(
  tx: Tx,
  keys: AuditMacClient,
  def: D,
  attrs: AuditAttrs<D>,
  options?: { readonly now?: () => Date },
): Promise<bigint> {
  const checked = checkAuditAttrs(def, attrs as Readonly<Record<string, unknown>>);
  const boundary = tx.boundary;
  const scopeKind = boundary.kind;
  const scopeId = boundary.kind === 'tenant' ? boundary.tenantId : boundary.userId;
  // ミリ秒に丸める（timestamptz に保存して読み戻しても、同じ値にするため）。
  const occurredAt = new Date((options?.now ?? (() => new Date()))().getTime());

  await tx.query(sql`SELECT pg_catalog.pg_advisory_xact_lock(${AUDIT_LOCK_KEY}) AS locked`);
  const [head] = await tx.query<{ seq: string; mac: Uint8Array }>(
    sql`SELECT seq, mac FROM audit.chain ORDER BY seq DESC LIMIT 1`,
  );
  const [scopeHead] = await tx.query<{ scope_seq: string }>(
    sql`SELECT scope_seq FROM audit.events ORDER BY scope_seq DESC LIMIT 1`,
  );
  const seq = head === undefined ? 1n : BigInt(head.seq) + 1n;
  const prevMac = head === undefined ? ZERO_MAC : new Uint8Array(head.mac);
  const scopeSeq = scopeHead === undefined ? 1n : BigInt(scopeHead.scope_seq) + 1n;

  const contentMac = await auditMac(
    keys,
    contentMessage({
      scopeKind,
      scopeId,
      scopeSeq,
      occurredAt,
      service: tx.service,
      eventType: def.type,
      attrs: checked,
    }),
  );
  const mac = await auditMac(keys, linkMessage(seq, prevMac, contentMac));

  await tx.execute(
    sql`INSERT INTO audit.chain (seq, content_mac, prev_mac, mac)
        VALUES (${seq}, ${contentMac}, ${prevMac}, ${mac})`,
  );
  await tx.execute(
    sql`INSERT INTO audit.events
          (seq, scope_seq, occurred_at, service, event_type, tenant_id, user_id, attrs)
        VALUES (${seq}, ${scopeSeq}, ${occurredAt}, ${tx.service}, ${def.type},
                ${scopeKind === 'tenant' ? scopeId : null}, ${scopeKind === 'user' ? scopeId : null},
                ${canonicalJson(checked)}::jsonb)`,
  );
  return seq;
}
