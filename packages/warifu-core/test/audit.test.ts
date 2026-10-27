// 偽の MAC のクライアントで、監査ログの検証の各失敗と、属性の検査を確かめる（DB と鍵サービスは使わない）。

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { contentMessage, linkMessage, ZERO_MAC } from '../src/audit/canonical.ts';
import { AuditAttrError, checkAuditAttrs, defineAuditEvent } from '../src/audit/events.ts';
import { type AuditChainRow, type AuditEventRow, verifyAuditRows } from '../src/audit/verify.ts';
import { parseTenantId } from '../src/ids.ts';

const key = randomBytes(32);
const keys = {
  async mac(_purpose: 'audit_chain', message: Uint8Array) {
    return new Uint8Array(createHmac('sha256', key).update(message).digest());
  },
};

const tenant = parseTenantId(randomUUID());

async function build(count: number): Promise<{ chain: AuditChainRow[]; events: AuditEventRow[] }> {
  const chain: AuditChainRow[] = [];
  const events: AuditEventRow[] = [];
  let prev = ZERO_MAC;
  for (let i = 1; i <= count; i += 1) {
    const event: AuditEventRow = {
      seq: BigInt(i),
      scopeSeq: BigInt(i),
      occurredAt: new Date(1_700_000_000_000 + i),
      service: 'idp',
      eventType: 'test.probe',
      tenantId: tenant,
      userId: null,
      attrs: { n: i },
    };
    const contentMac = await keys.mac(
      'audit_chain',
      contentMessage({
        scopeKind: 'tenant',
        scopeId: tenant,
        scopeSeq: event.scopeSeq,
        occurredAt: event.occurredAt,
        service: event.service,
        eventType: event.eventType,
        attrs: event.attrs,
      }),
    );
    const mac = await keys.mac('audit_chain', linkMessage(event.seq, prev, contentMac));
    chain.push({ seq: event.seq, contentMac, prevMac: prev, mac });
    events.push(event);
    prev = mac;
  }
  return { chain, events };
}

const boundary = { kind: 'tenant', tenantId: tenant } as const;

describe('監査ログの検証（純粋な関数）', () => {
  it('正しい行は ok', async () => {
    const rows = await build(4);
    expect(await verifyAuditRows({ ...rows, boundary }, keys)).toEqual({
      ok: true,
      chainRows: 4,
      scopeEvents: 4,
    });
  });

  it.each([
    [
      '属性の書き換え',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.events[1] = { ...(r.events[1] as AuditEventRow), attrs: { n: 99 } };
      },
      'content',
    ],
    [
      '本文の行の削除',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.events.splice(1, 1);
      },
      'scope_gap',
    ],
    [
      'チェーンの途中の行の削除',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.chain.splice(1, 1);
      },
      'gap',
    ],
    [
      'チェーンの2行の入れ替え（通番は残す）',
      (r: Awaited<ReturnType<typeof build>>) => {
        const a = r.chain[1] as AuditChainRow;
        const b = r.chain[2] as AuditChainRow;
        r.chain[1] = { ...b, seq: a.seq };
        r.chain[2] = { ...a, seq: b.seq };
      },
      'link',
    ],
    [
      'mac の差し替え',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.chain[2] = { ...(r.chain[2] as AuditChainRow), mac: new Uint8Array(randomBytes(32)) };
      },
      'mac',
    ],
    [
      '別の範囲の行',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.events[0] = { ...(r.events[0] as AuditEventRow), tenantId: randomUUID() };
      },
      'malformed',
    ],
    [
      '短い MAC',
      (r: Awaited<ReturnType<typeof build>>) => {
        r.chain[0] = { ...(r.chain[0] as AuditChainRow), mac: new Uint8Array(16) };
      },
      'malformed',
    ],
  ])('%s を見つける', async (_label, tamper, reason) => {
    const rows = await build(4);
    tamper(rows);
    const result = await verifyAuditRows({ ...rows, boundary }, keys);
    expect(result.ok).toBe(false);
    expect(result.failure?.reason).toBe(reason);
  });
});

describe('監査の事象の定義と属性', () => {
  const def = defineAuditEvent('test.probe', {
    target: 'uuid',
    count: 'int',
    flag: 'bool',
    kind: { enum: ['a', 'b'] },
  });

  it('定義どおりの属性だけを受け付ける', () => {
    const attrs = { target: randomUUID(), count: 1, flag: true, kind: 'a' };
    expect(checkAuditAttrs(def, attrs)).toEqual(attrs);
  });

  it.each([
    ['知らないキー', { target: randomUUID(), count: 1, flag: true, kind: 'a', email: 'x' }],
    ['足りないキー', { target: randomUUID(), count: 1, flag: true }],
    ['UUID でない', { target: 'someone@example.com', count: 1, flag: true, kind: 'a' }],
    ['小数', { target: randomUUID(), count: 1.5, flag: true, kind: 'a' }],
    ['列挙の外', { target: randomUUID(), count: 1, flag: true, kind: 'c' }],
  ])('%s は AuditAttrError（値を入れない）', (_label, attrs) => {
    expect(() => checkAuditAttrs(def, attrs)).toThrow(AuditAttrError);
    try {
      checkAuditAttrs(def, attrs);
    } catch (error) {
      expect(String(error)).not.toContain('example.com');
    }
  });

  it('事象の名前と、列挙の値の形を確かめる', () => {
    expect(() => defineAuditEvent('probe', {})).toThrow(AuditAttrError);
    expect(() => defineAuditEvent('test.Probe', {})).toThrow(AuditAttrError);
    expect(() => defineAuditEvent('test.probe', { kind: { enum: ['free text'] } })).toThrow(
      AuditAttrError,
    );
  });
});
