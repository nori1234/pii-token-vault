// 回復の値を平文で残さない（不変条件4、plan 11章 テスト7の一部、ADR 0027 の O-73・O-74・O-76・O-83）。
// 回復コード（作成、作り直し、成立の後の新しいコード）、招待コード、結び付けのコード、協力者の表示名を、通常・失敗・
// 期限切れ・取消の経路に通し、DB の行（idp の境界で読める回復の表、パスキー、受信箱、監査ログ）と idp のログを検索する。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseRecoveryCode } from '../../packages/idp/src/recovery.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { TenantId, WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { newApprover } from '../setup/approvals.ts';
import { serviceDb } from '../setup/db.ts';
import { startTestIdp, type TestIdp } from '../setup/idp.ts';
import {
  bindingCodeOf,
  bound,
  cancelRecovery,
  helperApprove,
  issueCode,
  resume,
  startOnNewDevice,
} from '../setup/recovery.ts';

const HOUR = 3600_000;
const DISPLAY_NAME = '回復協力者の表示名テスト';

let t: TestIdp;
let clock = Date.now();

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] }, () => new Date(clock));
});

afterAll(async () => {
  await t?.stop();
});

/** 回復の表、パスキー、受信箱、監査ログの行を、テキストにして返す（アプリと同じ境界で読む）。 */
async function dumpRows(userIds: readonly WarifuUserId[], tenantId: TenantId): Promise<string> {
  const out: string[] = [];
  const idp = await serviceDb('idp');
  try {
    for (const userId of userIds) {
      await idp.withWarifuUser(userId, async (tx) => {
        for (const statement of [
          sql`SELECT row_to_json(t)::text AS line FROM idp.users AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.credentials AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.recovery_codes AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.helpers AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.helper_notice_outbox AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.recovery_attempts AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM idp.inbox AS t`,
          sql`SELECT row_to_json(t)::text AS line FROM audit.events AS t`,
        ]) {
          for (const row of await tx.query<{ line: string }>(statement)) out.push(row.line);
        }
      });
    }
    await idp.withTenant(tenantId, async (tx) => {
      for (const row of await tx.query<{ line: string }>(
        sql`SELECT row_to_json(t)::text AS line FROM audit.events AS t`,
      )) {
        out.push(row.line);
      }
    });
  } finally {
    await idp.close();
  }
  return out.join('\n');
}

/** コードの、区切りあり・なし・小文字の形と、回復コードの秘密の16進と base64url。 */
function formsOf(code: string): string[] {
  const forms = [
    code,
    code.replace(/-/g, ''),
    code.toLowerCase(),
    code.replace(/-/g, '').toLowerCase(),
  ];
  const parsed = parseRecoveryCode(code);
  if (parsed !== undefined) {
    forms.push(
      Buffer.from(parsed.secret).toString('hex'),
      Buffer.from(parsed.secret).toString('base64url'),
    );
  }
  return forms;
}

describe('漏えい：回復の値を平文で残さない（不変条件4）', () => {
  it('作成・作り直し・成立・取消・失敗の後の DB とログに、回復コード・招待コード・結び付けのコード・表示名がない', async () => {
    // 攻撃者が持っている情報：割符の DB を読める立場（pg_dump、ATK-06）と、idp のログを読める立場
    // 試す経路：回復コードを作り、作り直す。協力者を招待して受け入れ（表示名を本文に足して送る）、確定する。回復を始め、
    //           結び付けのコードを出し直し、期限を切らし、協力者が承認し、成立させる。別の回復を始めて取り消す。
    //           形の違うコードと秘密の違うコードで始める。その後で、DB の行とログを検索する
    // 期待する結果：どの値も、DB の行にもログにも出ない（照合用の MAC と、内部 ID だけが残る）
    // plan 11章：テスト7の一部
    const owner = await newApprover(t);
    const helper = await newApprover(t);
    const other = await newApprover(t);
    const needles: string[] = [DISPLAY_NAME];

    const first = await issueCode(owner.approval);
    const code = await issueCode(owner.approval);
    needles.push(...formsOf(first), ...formsOf(code));

    const invite = await owner.approval.post('/api/helpers/invite');
    needles.push(...formsOf(String(invite.json.code)));
    const unused = await owner.approval.post('/api/helpers/invite');
    needles.push(...formsOf(String(unused.json.code)));
    expect(
      (
        await helper.approval.post('/api/helpers/accept', {
          code: unused.json.code,
          name: DISPLAY_NAME,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await bound(owner.approval, '/api/helpers/confirm', {
          code: unused.json.code,
          name: DISPLAY_NAME,
        })
      ).status,
    ).toBe(200);
    // 前の招待は、新しい招待を作ったときに消えている。
    expect(
      (await helper.approval.post('/api/helpers/accept', { code: invite.json.code })).status,
    ).toBe(400);

    await owner.approval.post('/api/recovery/start', { code: 'not-a-code' });
    const device = await startOnNewDevice(t, code);
    const stale = bindingCodeOf(device.register);
    needles.push(...formsOf(stale));
    clock += 11 * 60_000;
    const fresh = bindingCodeOf(await resume(device.browser));
    needles.push(...formsOf(fresh));
    expect((await helper.approval.approvalLogin()).status).toBe(200);
    expect((await helperApprove(helper.approval, stale)).status).toBe(400);
    const approved = await helperApprove(helper.approval, fresh);
    expect(approved.status).toBe(200);
    clock = Date.parse(String(approved.json.readyAt));
    const done = await resume(device.browser);
    expect(done.json.state).toBe('completed');
    needles.push(...formsOf(String(done.json.recoveryCode)));
    const reissued = await issueCode(device.browser);
    needles.push(...formsOf(reissued));

    // 別の利用者の回復を始めて、取り消す（取消で失効したコードも残さない）。
    clock += 2 * HOUR;
    const otherHelper = await newApprover(t);
    expect((await other.approval.approvalLogin()).status).toBe(200);
    const otherCode = await issueCode(other.approval);
    needles.push(...formsOf(otherCode));
    const otherInvite = await other.approval.post('/api/helpers/invite');
    needles.push(...formsOf(String(otherInvite.json.code)));
    await otherHelper.approval.post('/api/helpers/accept', { code: otherInvite.json.code });
    await bound(other.approval, '/api/helpers/confirm', { code: otherInvite.json.code });
    const otherDevice = await startOnNewDevice(t, otherCode);
    needles.push(...formsOf(bindingCodeOf(otherDevice.register)));
    expect((await cancelRecovery(other.approval)).status).toBe(200);

    const tenant = t.tenants[0];
    if (tenant === undefined) throw new Error('準備に失敗した');
    const rows = await dumpRows(
      [owner.userId, helper.userId, other.userId, otherHelper.userId],
      tenant.tenantId as TenantId,
    );
    expect(rows).toContain('"code_mac"');
    expect(rows.length).toBeGreaterThan(0);
    const logs = t.logLines().join('\n');
    for (const needle of needles) {
      expect(rows.includes(needle), `DB の行に値が残っている（${needles.indexOf(needle)}）`).toBe(
        false,
      );
      expect(logs.includes(needle), `ログに値が残っている（${needles.indexOf(needle)}）`).toBe(
        false,
      );
    }
    expect(logs).toContain('idp.recovery_completed');
  });
});
