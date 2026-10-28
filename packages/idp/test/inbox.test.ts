import { readFileSync } from 'node:fs';
import type { WarifuUserId } from '@pii-token-vault/warifu-core';
import { describe, expect, it } from 'vitest';
import {
  ApprovalTypes,
  approvalChallengeMessage,
  canonicalContent,
  isInboxContent,
  NOTICE_TYPES,
  type PendingApproval,
} from '../src/inbox.ts';

const repoRoot = new URL('../../../', import.meta.url);

describe('受信箱の中身の形（ADR 0023）', () => {
  it('平らなオブジェクトで、短い文字列・整数・真偽値だけを受け付ける', () => {
    expect(isInboxContent({})).toBe(true);
    expect(isInboxContent({ place_kind: 'post_office', count: 2, synced: true })).toBe(true);
    for (const bad of [
      null,
      [],
      'text',
      { nested: { a: 1 } },
      { list: ['a'] },
      { 'Bad-Key': 'x' },
      { long: 'x'.repeat(201) },
      { newline: 'a\nb' },
      { bidi: 'a‮b' },
      { float: 1.5 },
      { huge: 2 ** 60 },
      Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, i])),
    ]) {
      expect(isInboxContent(bad)).toBe(false);
    }
  });

  it('チャレンジの材料はキーの順によらず同じで、内容・決定・乱数のどれが違っても変わる', () => {
    expect(canonicalContent({ b: 1, a: 'x' })).toBe(canonicalContent({ a: 'x', b: 1 }));
    const item = {
      itemId: '00000000-0000-4000-8000-000000000001',
      kind: 'approval',
      type: 'test.pickup_change',
      tenantId: '00000000-0000-4000-8000-000000000002',
      content: { place_kind: 'post_office', place_name: 'A' },
      state: 'pending',
      createdAt: new Date('2026-10-28T00:00:00Z'),
      expiresAt: new Date('2026-10-28T00:05:00Z'),
      decidedAt: null,
      readAt: null,
    } as unknown as PendingApproval;
    const base = {
      item,
      userId: '00000000-0000-4000-8000-000000000003' as WarifuUserId,
      decision: 'approved',
      sessionRef: 'ref',
      nonce: 'n',
    } as const;
    const hex = (input: Parameters<typeof approvalChallengeMessage>[0]) =>
      Buffer.from(approvalChallengeMessage(input)).toString('hex');
    const variants = [
      hex(base),
      hex({ ...base, decision: 'denied' }),
      hex({ ...base, nonce: 'm' }),
      hex({ ...base, sessionRef: 'other' }),
      hex({ ...base, item: { ...item, content: { place_kind: 'post_office', place_name: 'B' } } }),
      hex({ ...base, item: { ...item, itemId: '00000000-0000-4000-8000-000000000009' } }),
      hex({ ...base, userId: '00000000-0000-4000-8000-000000000004' as WarifuUserId }),
    ];
    expect(new Set(variants).size).toBe(variants.length);
  });

  it('承認待ちの型は、名前の重なり、知らせの名前、知らない承認の種類を受け付けない', () => {
    const t = {
      type: 'test.a',
      channel: 'device' as const,
      operation: '操作',
      parse: () => ({}),
      lines: () => [],
    };
    expect(() => new ApprovalTypes([t, t])).toThrow(RangeError);
    expect(() => new ApprovalTypes([{ ...t, type: 'passkey.added' }])).toThrow(RangeError);
    expect(() => new ApprovalTypes([{ ...t, type: 'Bad Type' }])).toThrow(RangeError);
    expect(() => new ApprovalTypes([{ ...t, channel: 'push' as never }])).toThrow(RangeError);
    expect(new ApprovalTypes([t]).get('test.a')?.operation).toBe('操作');
  });
});

describe('画面の固定の文言（DESIGN.md 3章）', () => {
  const design = readFileSync(new URL('DESIGN.md', repoRoot), 'utf8');
  const appJs = readFileSync(new URL('packages/idp/public/app.js', repoRoot), 'utf8');

  it.each(['A-1', 'A-2'])('警告文 %s は、DESIGN.md の文言のまま画面に入っている', (id) => {
    const line = design.split('\n').find((l) => l.startsWith(`- **${id}`));
    const text = line?.match(/「(.+)」/)?.[1];
    expect(text).toBeDefined();
    expect(appJs).toContain(`'${text}'`);
  });

  it('知らせの見出しに、企業名や操作の内容を差し込む場所がない（ロック画面の原則6と同じく、一般的な文言）', () => {
    for (const def of Object.values(NOTICE_TYPES)) {
      expect(def.title).not.toMatch(/〈|\$\{/);
    }
  });
});
