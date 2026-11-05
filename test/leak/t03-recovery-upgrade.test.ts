// 0009 を流す前に足して消したパスキーも、協力者の14日の判定に入る（plan 11章 テスト3、PRN-87、ADR 0027 の O-76。
// オーナーの6回目のレビュー）。
// 0008 まで流した DB に、更新前の idp と同じ書き方（アプリのロールで、利用者の境界の中）で、利用者、パスキー、監査ログを
// 置く。0009 を流してから、協力者の判定（helperRelationship）を、アプリと同じ境界で呼ぶ。
// DB の作成とマイグレーションは、不変条件8の例外として、ブートストラップのロールで行う（DB の中身は読み書きしない）。

import { randomBytes, randomUUID } from 'node:crypto';
import { copyFile, mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import {
  ACCOUNT_CREATED,
  PASSKEY_ADDED,
  PASSKEY_REMOVED,
} from '../../packages/idp/src/audit-events.ts';
import { helperRelationship } from '../../packages/idp/src/recovery.ts';
import type { RepoDeps } from '../../packages/idp/src/repo.ts';
import { appendAudit } from '../../packages/warifu-core/src/audit/append.ts';
import { createDb } from '../../packages/warifu-core/src/db/boundary.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import type { Db } from '../../packages/warifu-core/src/db/types.ts';
import type { WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { applyDatabaseAcl, MIGRATIONS_DIR, migrate } from '../../scripts/migrate.ts';
import { keysvcConnection } from '../setup/keys.ts';

const DAY = 24 * 3600_000;
const database = `warifu_upgrade_${process.env.VITEST_POOL_ID ?? '1'}`;
const now = Date.now();
const keys = createIdpKeyClient(keysvcConnection('idp'));

let admin: pg.Client;
let bootstrap: pg.Client;
let db: Db;
let dir: string;

beforeAll(async () => {
  const { host, port, user } = inject('pg');
  admin = new pg.Client({ host, port, user, database: 'postgres' });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${database}`);
  await admin.query(`CREATE DATABASE ${database}`);
  await applyDatabaseAcl(admin, database);
  bootstrap = new pg.Client({ host, port, user, database });
  await bootstrap.connect();
  // 0008 まで（M7 の後、M8 の前）を流す。
  dir = await mkdtemp(join(tmpdir(), 'warifu-upgrade-'));
  for (const name of await readdir(MIGRATIONS_DIR)) {
    if (/^\d{4}_.*\.sql$/.test(name) && name < '0009') {
      await copyFile(join(MIGRATIONS_DIR, name), join(dir, name));
    }
  }
  await migrate(bootstrap, dir);
  db = createDb({ service: 'idp', connection: { host, port: Number(port), database } });
});

afterAll(async () => {
  await db?.close();
  await bootstrap?.end();
  await admin?.query(`DROP DATABASE IF EXISTS ${database}`);
  await admin?.end();
  if (dir !== undefined) await rm(dir, { recursive: true, force: true });
});

/** 更新前の idp と同じ書き方で、アカウントと最初のパスキーを置く。added は、足したパスキー（消したものも含む）の時刻。 */
async function seedUser(added: readonly { readonly at: number; readonly removedAt?: number }[]) {
  const userId = randomUUID() as WarifuUserId;
  await db.withWarifuUser(userId, async (tx) => {
    await tx.execute(sql`INSERT INTO idp.users (user_id) VALUES (${userId})`);
    await tx.execute(
      sql`INSERT INTO idp.credentials
            (credential_id, user_id, public_key, alg, rsa_bits, sign_count, transports, backup_eligible,
             backed_up)
          VALUES (${randomBytes(32)}, ${userId}, ${randomBytes(77)}, ${-7}, ${null}, ${0}, ${[]},
                  ${false}, ${false})`,
    );
    await appendAudit(
      tx,
      keys,
      ACCOUNT_CREATED,
      { backup_eligible: false },
      { now: () => new Date(now - 60 * DAY) },
    );
    for (const passkey of added) {
      // 足したパスキーの行は、消したものとして置かない（監査ログだけが残る）。
      await appendAudit(
        tx,
        keys,
        PASSKEY_ADDED,
        { backup_eligible: false, count: 2 },
        { now: () => new Date(passkey.at) },
      );
      if (passkey.removedAt !== undefined) {
        const removedAt = passkey.removedAt;
        await appendAudit(
          tx,
          keys,
          PASSKEY_REMOVED,
          { count: 1 },
          { now: () => new Date(removedAt) },
        );
      }
    }
  });
  return userId;
}

/** 0009 の後に、持ち主を作り、協力者に指名する（0009 の後の idp と同じ境界）。 */
async function ownerOf(helperUserId: WarifuUserId): Promise<WarifuUserId> {
  const owner = randomUUID() as WarifuUserId;
  await db.withWarifuUser(owner, async (tx) => {
    await tx.execute(sql`INSERT INTO idp.users (user_id) VALUES (${owner})`);
    await tx.execute(
      sql`INSERT INTO idp.helpers (relationship_id, owner_user_id, helper_user_id, created_at)
          VALUES (${randomUUID()}, ${owner}, ${helperUserId}, ${new Date(now)})`,
    );
  });
  return owner;
}

describe('漏えい：0009 の前に足して消したパスキー（plan 11章 テスト3）', () => {
  it('0009 を流す前に足して消したパスキーも、監査ログから戻し、足してから14日は協力者として承認できない', async () => {
    // 攻撃者が持っている情報：盗んだ回復コードと、協力者のアカウントに足した攻撃者のパスキー（協力者のなりすまし）。
    //                         更新の前に、足したパスキーを消しておく（パスキーの表に行が残らない）
    // 試す経路：0009（credential_added_at を足す）を流した直後に、その協力者の承認を判定する
    // 期待する結果：足してから14日以内の協力者は eligible が false（承認の画面と儀式は 409 helper_not_eligible）。
    //               足したのが14日より前の協力者と、足したことのない協力者は true
    // plan 11章：テスト3（PRN-87）
    const recent = await seedUser([{ at: now - 3 * DAY, removedAt: now - 2 * DAY }]);
    const old = await seedUser([{ at: now - 20 * DAY, removedAt: now - 19 * DAY }]);
    const both = await seedUser([
      { at: now - 30 * DAY },
      { at: now - 5 * DAY, removedAt: now - 4 * DAY },
    ]);
    const never = await seedUser([]);

    // 0009 を流す（残りのマイグレーション）。
    expect(await migrate(bootstrap)).toEqual(['0009_recovery']);

    const deps: RepoDeps = { db, keys, now: () => new Date(now) };
    const eligible = async (helper: WarifuUserId) =>
      (await helperRelationship(deps, helper, await ownerOf(helper)))?.eligible;
    expect(await eligible(recent)).toBe(false);
    expect(await eligible(both)).toBe(false);
    expect(await eligible(old)).toBe(true);
    expect(await eligible(never)).toBe(true);

    // 戻した時刻は、監査ログのいちばん新しい追加の時刻（ミリ秒）。
    const addedAt = await db.withWarifuUser(recent, (tx) =>
      tx.query<{ credential_added_at: Date | null }>(
        sql`SELECT credential_added_at FROM idp.users`,
      ),
    );
    expect(addedAt[0]?.credential_added_at?.getTime()).toBe(now - 3 * DAY);
  });
});
