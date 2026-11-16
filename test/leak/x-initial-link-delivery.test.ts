// 初回紐付けの、送信待ちと鍵の版（ADR 0028 の O-87・O-103）。
// - 待機の知らせの SET を、company-api → sender → 企業の受け口まで実際に通し、202 が返った時刻から待機が始まることを確かめる。
// - 移行専用ID と照合の索引の MAC の鍵を入れ替えた後も、同じ申請ID の再送は同じ移行専用ID を返すことを、
//   このテストで起動した鍵サービスに SIGUSR2 を送って確かめる。

import { randomUUID } from 'node:crypto';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { recordApproval, statusOf } from '../../packages/company-api/src/initial-link.ts';
import { INITIAL_LINK_WAITING_EVENT_URI } from '../../packages/company-api/src/set.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import { parseWarifuUserId, type TenantId } from '../../packages/warifu-core/src/ids.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import type { KeysvcProcess } from '../../scripts/keysvc-up.ts';
import { startKeysvc } from '../../scripts/keysvc-up.ts';
import { startTestCompanyApi, type TestCompanyApi } from '../setup/company-api.ts';
import { serviceDb } from '../setup/db.ts';
import {
  initialLinkProof,
  newMemberRef,
  newRequestId,
  TEST_INITIAL_LINK,
} from '../setup/initial-link.ts';
import { keysvcConnection } from '../setup/keys.ts';
import {
  makeTlsFixture,
  PUBLIC_V4,
  startTestSender,
  type TestSender,
  WEBHOOK_HOST,
} from '../setup/sender.ts';

const HOUR = 3600 * 1000;
let clock = Date.now();
const now = () => new Date(clock);
let sender: TestSender;
let keysvc: KeysvcProcess;
let api: TestCompanyApi;

beforeAll(async () => {
  sender = await startTestSender({ A: { [WEBHOOK_HOST]: [PUBLIC_V4] } }, await makeTlsFixture());
  keysvc = await startKeysvc();
  api = await startTestCompanyApi({
    now,
    keysvc: keysvcConnection('company-api', keysvc),
    sender: { socketPath: sender.sender.socketPath, credential: sender.credentials['company-api'] },
    tenants: [
      {
        scopes: ['initial_link'],
        initialLink: TEST_INITIAL_LINK,
        participation: 'migrating',
        migrationDeadline: '2027-05-14',
        webhookUrl: `https://${WEBHOOK_HOST}/set/a`,
      },
    ],
  });
});

afterAll(async () => {
  await api?.stop();
  await keysvc?.stop();
  await sender?.stop();
});

function tenantA() {
  const t = api.tenants[0];
  const registered = t === undefined ? undefined : api.api.config.tenants.get(t.tenantId);
  if (t === undefined || registered === undefined) throw new Error('準備に失敗した');
  return { t, registered };
}

async function call(path: string, json: unknown) {
  const { t } = tenantA();
  const token = await api.accessToken(t, 'initial_link');
  return api.request({ path: `/v1/initial-link/${path}`, token, json });
}

async function prepare(requestId: string, memberRef: string): Promise<string> {
  const res = await call('prepare', { request_id: requestId, member_ref: memberRef });
  expect(res.status).toBe(200);
  return (res.json() as { initial_link_id: string }).initial_link_id;
}

async function publicIdVersions(tenantId: TenantId): Promise<number[]> {
  const db = await serviceDb('company-api');
  try {
    const rows = await db.withTenant(tenantId, (tx) =>
      tx.query<{ public_id_version: number }>(
        sql`SELECT public_id_version FROM company_api.initial_links ORDER BY created_at, link_ref`,
      ),
    );
    return rows.map((r) => r.public_id_version);
  } finally {
    await db.close();
  }
}

async function rotateKeys(): Promise<void> {
  const before = keysvc.output().split('keysvc.mac_rotated').length;
  process.kill(keysvc.pid, 'SIGUSR2');
  const deadline = Date.now() + 5000;
  while (keysvc.output().split('keysvc.mac_rotated').length === before) {
    if (Date.now() > deadline) throw new Error('鍵の入れ替えが時間内に終わらなかった');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe('初回紐付けの送信待ちと鍵の版（ADR 0028）', () => {
  it('待機の知らせの SET は、受け口が 202 を返した時刻から待機を始める', async () => {
    // 攻撃者が持っている情報：盗んだ旧パスキー。企業の受け口は止まっている（旧会員の側に知らせが出ない）
    // 試す経路：本人の承認の後、受け口が 500 を返す間に送信待ちを回し、時間を進めてから 202 を返させる
    // 期待する結果：500 の間は pending_notice のまま待機が始まらない。202 の後に pending_link になり、待機の終わりは
    //               202 を受けた時刻から24時間後。SET の中身は移行専用ID だけで、会員参照も sub も入らない
    // plan 11章：テスト9（紐付けの攻撃）、テスト12（企業に渡る値）、ADR 0028 の O-103
    const { t, registered } = tenantA();
    const deps = {
      db: api.api.db,
      keys: createCompanyApiKeyClient(keysvcConnection('company-api', keysvc)),
      now,
    };
    const memberRef = newMemberRef();
    const id = await prepare(newRequestId(), memberRef);
    const initial = await call('proofs', {
      proof: await initialLinkProof(
        t,
        { initial_link_id: id, member_ref: memberRef },
        { nowMs: clock },
      ),
    });
    expect(initial.status).toBe(204);
    const userId = parseWarifuUserId(randomUUID());
    const itemRef = randomUUID();
    expect(
      await recordApproval(deps, registered, { userId, itemRef, initialLinkId: id }),
    ).toMatchObject({
      ok: true,
      state: 'pending_notice',
    });

    // 最初の送信は、0〜60秒の乱数だけ遅れる（テスト12。遅れは t12-desk-cancellation-set で確かめる）。
    clock += 61_000;
    sender.respondWith(500);
    const before = sender.requests.length;
    expect(await api.api.deliverDue()).toMatchObject({ delivered: 0, retry: 1 });
    expect(sender.requests.length).toBe(before + 1);
    expect((await statusOf(deps, registered, { userId, itemRefs: [itemRef] }))[0]?.state).toBe(
      'pending_notice',
    );

    clock += HOUR;
    sender.respondWith(202);
    expect(await api.api.deliverDue()).toMatchObject({ delivered: 1 });
    const acceptedAt = clock;
    const [status] = await statusOf(deps, registered, { userId, itemRefs: [itemRef] });
    expect(status?.state).toBe('pending_link');
    expect(status?.waitUntil).toBe(new Date(acceptedAt + 24 * HOUR).toISOString());

    const delivered = sender.requests.at(-1);
    expect(delivered?.url).toBe('/set/a');
    const payload = decodeJwt(String(delivered?.body));
    expect(Object.keys(payload).sort()).toEqual(['aud', 'events', 'iat', 'iss', 'jti']);
    expect(payload.events).toEqual({ [INITIAL_LINK_WAITING_EVENT_URI]: { initial_link_id: id } });
    expect(String(delivered?.body)).not.toContain(memberRef);
  });

  it('MAC の鍵を入れ替えた後も、同じ申請ID の再送は同じ移行専用ID。新しい申請は新しい版', async () => {
    // 攻撃者が持っている情報：なし（運営者の鍵の入れ替えで、企業の再送の扱いが変わらないことを確かめる）
    // 試す経路：仮申請の後に鍵サービスへ SIGUSR2 を送り、同じ申請ID と会員参照で出し直す。別の申請ID でも出す
    // 期待する結果：再送は同じ移行専用ID（古い版で照合して見つける）。別の会員参照なら 409。新しい申請は新しい版で、
    //               古い申請の版は変わらない
    // plan 11章：テスト4（企業に渡る値の独立）、ADR 0028 の O-87
    const { t } = tenantA();
    const requestId = newRequestId();
    const memberRef = newMemberRef();
    const id = await prepare(requestId, memberRef);
    const versionsBefore = await publicIdVersions(t.tenantId);
    const oldVersion = versionsBefore.at(-1);

    await rotateKeys();

    expect(await prepare(requestId, memberRef)).toBe(id);
    const conflict = await call('prepare', { request_id: requestId, member_ref: newMemberRef() });
    expect([conflict.status, conflict.text]).toEqual([409, '{"error":"conflict"}']);
    clock += 1000;
    const fresh = await prepare(newRequestId(), newMemberRef());
    expect(fresh).not.toBe(id);
    const versionsAfter = await publicIdVersions(t.tenantId);
    expect(versionsAfter.slice(0, versionsBefore.length)).toEqual(versionsBefore);
    expect(versionsAfter.at(-1)).toBe((oldVersion ?? 0) + 1);
  });
});
