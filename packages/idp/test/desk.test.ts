import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DESK_ACTION_LABELS,
  type DeskHandoff,
  deskChallengeMessage,
  deskDetailFromParam,
  deskDetailJson,
  parseDeskDetail,
  sameDeskDetail,
} from '../src/desk.ts';

const SUB = 'A'.repeat(43);
const ID = 'b'.repeat(22);
const ALL = ['desk.case.status.read', 'desk.order.status.read', 'desk.case.create'] as const;
const repoRoot = new URL('../../../', import.meta.url);

describe('窓口の申請の形（ADR 0026 の O-60）', () => {
  it('決めた形だけを受け付け、キーの順によらず同じ申請とみなす', () => {
    const create = parseDeskDetail(
      {
        subject: SUB,
        choices: { language: 'en', category: 'order' },
        identifier: ID,
        actions: ['desk.case.create'],
        type: 'warifu_desk',
      },
      ALL,
    );
    expect(create).toEqual({
      action: 'desk.case.create',
      identifier: ID,
      subject: SUB,
      choices: { category: 'order', language: 'en' },
    });
    const again = deskDetailFromParam(JSON.stringify([deskDetailJson(create as never)]), ALL);
    expect(again !== undefined && create !== undefined && sameDeskDetail(again, create)).toBe(true);
    const read = parseDeskDetail(
      { type: 'warifu_desk', actions: ['desk.case.status.read'], identifier: ID, subject: SUB },
      ALL,
    );
    expect(read?.choices).toBeNull();
  });

  it('許していない操作、余分な項目、形の違う値は断る', () => {
    const base = { type: 'warifu_desk', identifier: ID, subject: SUB };
    for (const bad of [
      {
        ...base,
        actions: ['desk.case.status.read'],
        choices: { category: 'general', language: 'ja' },
      },
      { ...base, actions: ['desk.case.create'] },
      { ...base, actions: ['desk.case.create'], choices: { category: 'general', language: 'fr' } },
      { ...base, actions: ['desk.case.status.read'], datatypes: ['x'] },
      { ...base, actions: ['desk.case.status.read'], identifier: 'short' },
      { ...base, actions: ['desk.case.status.read'], subject: 'user@example.com' },
      { ...base, actions: ['desk.case.status.read', 'desk.order.status.read'] },
      { ...base, type: 'other', actions: ['desk.case.status.read'] },
    ]) {
      expect(parseDeskDetail(bad, ALL)).toBeUndefined();
    }
    expect(
      parseDeskDetail({ ...base, actions: ['desk.order.status.read'] }, ['desk.case.status.read']),
    ).toBeUndefined();
    expect(deskDetailFromParam('[]', ALL)).toBeUndefined();
    expect(deskDetailFromParam('{"type":"warifu_desk"}', ALL)).toBeUndefined();
  });

  it('チャレンジの材料は、申請の中身と uid と乱数が1つでも違えば変わる', () => {
    const detail = parseDeskDetail(
      { type: 'warifu_desk', actions: ['desk.case.status.read'], identifier: ID, subject: SUB },
      ALL,
    );
    if (detail === undefined) throw new Error('準備に失敗した');
    const handoff: DeskHandoff = {
      uid: 'uid-1',
      tenantId: '00000000-0000-4000-8000-000000000001' as never,
      clientId: 'rp-1',
      detail,
      device: 'windows',
      createdAt: 1,
      expiresAt: 2,
      state: 'pending',
      failures: 0,
    };
    const base = Buffer.from(deskChallengeMessage(handoff, 'n')).toString('hex');
    for (const changed of [
      deskChallengeMessage({ ...handoff, uid: 'uid-2' }, 'n'),
      deskChallengeMessage(handoff, 'm'),
      deskChallengeMessage({ ...handoff, clientId: 'rp-2' }, 'n'),
      deskChallengeMessage({ ...handoff, detail: { ...detail, subject: 'B'.repeat(43) } }, 'n'),
      deskChallengeMessage({ ...handoff, device: 'mac' }, 'n'),
    ]) {
      expect(Buffer.from(changed).toString('hex')).not.toBe(base);
    }
  });

  it('操作ラベルは DESIGN.md 3章の文言のまま', () => {
    const design = readFileSync(new URL('DESIGN.md', repoRoot), 'utf8');
    for (const [action, label] of Object.entries(DESK_ACTION_LABELS)) {
      expect(design).toContain(`\`${action}\`：「${label}」`);
    }
  });

  it('画面の警告文 A-1 と E は、DESIGN.md 3章の文言のまま', () => {
    const design = readFileSync(new URL('DESIGN.md', repoRoot), 'utf8');
    const app = readFileSync(new URL('packages/idp/public/app.js', repoRoot), 'utf8');
    for (const id of ['A-1', 'E']) {
      const match = new RegExp(`\\*\\*${id}（[^）]+）\\*\\*：「([^」]+)」`).exec(design);
      expect(match?.[1]).toBeDefined();
      expect(app).toContain(String(match?.[1]));
    }
  });
});
