// 監査ログの検証（CAP-17、テスト8、ADR 0015）。
//
// - 全体のチェーンを seq の順に読み、1から連続していること（gap）、prev_mac が前の mac と一致すること（link）、
//   mac を計算し直して一致すること（mac）を確かめる。
// - いまの範囲の本文を scope_seq の順に読み、1から連続していること（scope_gap）、content_mac を計算し直して、
//   同じ seq のチェーンの行と一致すること（content）を確かめる。形の誤りは malformed。
// 残る弱点（ADR 0015）：全体の末尾の切り詰めと、範囲の最後の本文の行だけの削除は、境界の中の検証では見つからない。

import { sql } from '../db/sql.ts';
import type { Boundary, Tx } from '../db/types.ts';
import type { ServiceName } from '../ids.ts';
import { constantTimeEqual } from '../random.ts';
import { type AuditMacClient, auditMac } from './append.ts';
import { AUDIT_MAC_BYTES, contentMessage, linkMessage, ZERO_MAC } from './canonical.ts';

export type AuditFailureReason = 'gap' | 'link' | 'mac' | 'content' | 'scope_gap' | 'malformed';

export interface AuditChainRow {
  readonly seq: bigint;
  readonly contentMac: Uint8Array;
  readonly prevMac: Uint8Array;
  readonly mac: Uint8Array;
}

export interface AuditEventRow {
  readonly seq: bigint;
  readonly scopeSeq: bigint;
  readonly occurredAt: Date;
  readonly service: ServiceName;
  readonly eventType: string;
  readonly tenantId: string | null;
  readonly userId: string | null;
  readonly attrs: Readonly<Record<string, string | number | boolean>>;
}

export interface AuditVerification {
  readonly ok: boolean;
  readonly chainRows: number;
  readonly scopeEvents: number;
  readonly failure?: { readonly seq: bigint; readonly reason: AuditFailureReason };
}

function fail(
  chainRows: number,
  scopeEvents: number,
  seq: bigint,
  reason: AuditFailureReason,
): AuditVerification {
  return { ok: false, chainRows, scopeEvents, failure: { seq, reason } };
}

function isMac(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.byteLength === AUDIT_MAC_BYTES;
}

/** 行を渡して確かめる純粋な関数（改ざんの検出のテストにも使う）。 */
export async function verifyAuditRows(
  input: {
    readonly chain: readonly AuditChainRow[];
    readonly events: readonly AuditEventRow[];
    readonly boundary: Boundary;
  },
  keys: AuditMacClient,
): Promise<AuditVerification> {
  const { chain, events, boundary } = input;
  const bySeq = new Map<bigint, AuditChainRow>();
  let previous: Uint8Array = ZERO_MAC;
  for (const [index, row] of chain.entries()) {
    if (!isMac(row.contentMac) || !isMac(row.prevMac) || !isMac(row.mac)) {
      return fail(chain.length, events.length, row.seq, 'malformed');
    }
    if (row.seq !== BigInt(index + 1)) return fail(chain.length, events.length, row.seq, 'gap');
    if (!constantTimeEqual(row.prevMac, previous)) {
      return fail(chain.length, events.length, row.seq, 'link');
    }
    const expected = await auditMac(keys, linkMessage(row.seq, row.prevMac, row.contentMac));
    if (!constantTimeEqual(expected, row.mac)) {
      return fail(chain.length, events.length, row.seq, 'mac');
    }
    bySeq.set(row.seq, row);
    previous = row.mac;
  }

  const scopeKind = boundary.kind;
  const scopeId = boundary.kind === 'tenant' ? boundary.tenantId : boundary.userId;
  const sorted = [...events].sort((a, b) => (a.scopeSeq < b.scopeSeq ? -1 : 1));
  for (const [index, event] of sorted.entries()) {
    const inScope =
      scopeKind === 'tenant'
        ? event.tenantId === scopeId && event.userId === null
        : event.userId === scopeId && event.tenantId === null;
    if (!inScope) return fail(chain.length, events.length, event.seq, 'malformed');
    if (event.scopeSeq !== BigInt(index + 1)) {
      return fail(chain.length, events.length, event.seq, 'scope_gap');
    }
    const link = bySeq.get(event.seq);
    if (link === undefined) return fail(chain.length, events.length, event.seq, 'content');
    let message: Uint8Array;
    try {
      message = contentMessage({
        scopeKind,
        scopeId,
        scopeSeq: event.scopeSeq,
        occurredAt: event.occurredAt,
        service: event.service,
        eventType: event.eventType,
        attrs: event.attrs,
      });
    } catch {
      return fail(chain.length, events.length, event.seq, 'malformed');
    }
    const expected = await auditMac(keys, message);
    if (!constantTimeEqual(expected, link.contentMac)) {
      return fail(chain.length, events.length, event.seq, 'content');
    }
  }
  return { ok: true, chainRows: chain.length, scopeEvents: events.length };
}

/** 境界の中で、全体のチェーンと、いまの範囲の本文を読んで確かめる。 */
export async function readAuditRows(tx: Tx): Promise<{
  chain: AuditChainRow[];
  events: AuditEventRow[];
}> {
  const chain = await tx.query<{
    seq: string;
    content_mac: Uint8Array;
    prev_mac: Uint8Array;
    mac: Uint8Array;
  }>(sql`SELECT seq, content_mac, prev_mac, mac FROM audit.chain ORDER BY seq`);
  const events = await tx.query<{
    seq: string;
    scope_seq: string;
    occurred_at: Date;
    service: ServiceName;
    event_type: string;
    tenant_id: string | null;
    user_id: string | null;
    attrs: Record<string, string | number | boolean>;
  }>(
    sql`SELECT seq, scope_seq, occurred_at, service, event_type, tenant_id, user_id, attrs
          FROM audit.events ORDER BY scope_seq`,
  );
  return {
    chain: chain.map((row) => ({
      seq: BigInt(row.seq),
      contentMac: new Uint8Array(row.content_mac),
      prevMac: new Uint8Array(row.prev_mac),
      mac: new Uint8Array(row.mac),
    })),
    events: events.map((row) => ({
      seq: BigInt(row.seq),
      scopeSeq: BigInt(row.scope_seq),
      occurredAt: row.occurred_at,
      service: row.service,
      eventType: row.event_type,
      tenantId: row.tenant_id,
      userId: row.user_id,
      attrs: row.attrs,
    })),
  };
}

export async function verifyAuditChain(tx: Tx, keys: AuditMacClient): Promise<AuditVerification> {
  const rows = await readAuditRows(tx);
  return verifyAuditRows({ ...rows, boundary: tx.boundary }, keys);
}
