// idp の DB の読み書き（不変条件8、ADR 0015、ADR 0018）。
// すべて withWarifuUser か withTenant の中で、sql タグの文だけを使う。監査ログの追記は、トランザクションの最後の文にする。

import type { TenantId, WarifuUserId } from '@pii-token-vault/warifu-core';
import { type AuditMacClient, appendAudit } from '@pii-token-vault/warifu-core/audit';
import { type Db, sql, type Tx } from '@pii-token-vault/warifu-core/db';
import {
  ACCOUNT_CREATED,
  CONNECTION_CONSENTED,
  EMAIL_VERIFICATION_STARTED,
  EMAIL_VERIFIED,
  PASSKEY_ADDED,
  PASSKEY_REMOVED,
} from './audit-events.ts';

export interface NewCredential {
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly signCount: number;
  readonly transports: readonly string[];
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
}

export interface StoredCredential extends NewCredential {
  readonly userId: WarifuUserId;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
}

interface CredentialRow {
  credential_id: Uint8Array;
  user_id: string;
  public_key: Uint8Array;
  sign_count: string;
  transports: string[];
  backup_eligible: boolean;
  backed_up: boolean;
  created_at: Date;
  last_used_at: Date | null;
}

function toCredential(row: CredentialRow): StoredCredential {
  return {
    credentialId: new Uint8Array(row.credential_id),
    userId: row.user_id as WarifuUserId,
    publicKey: new Uint8Array(row.public_key),
    signCount: Number(row.sign_count),
    transports: row.transports,
    backupEligible: row.backup_eligible,
    backedUp: row.backed_up,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

export interface RepoDeps {
  readonly db: Db;
  readonly keys: AuditMacClient;
  readonly now: () => Date;
}

async function insertCredential(tx: Tx, userId: WarifuUserId, c: NewCredential): Promise<void> {
  await tx.execute(
    sql`INSERT INTO idp.credentials
          (credential_id, user_id, public_key, sign_count, transports, backup_eligible, backed_up)
        VALUES (${c.credentialId}, ${userId}, ${c.publicKey}, ${c.signCount}, ${[...c.transports]},
                ${c.backupEligible}, ${c.backedUp})`,
  );
}

/** アカウントと最初のパスキーを、1つのトランザクションで作る。 */
export async function createAccount(
  deps: RepoDeps,
  userId: WarifuUserId,
  credential: NewCredential,
): Promise<void> {
  await deps.db.withWarifuUser(userId, async (tx) => {
    await tx.execute(sql`INSERT INTO idp.users (user_id) VALUES (${userId})`);
    await insertCredential(tx, userId, credential);
    await appendAudit(
      tx,
      deps.keys,
      ACCOUNT_CREATED,
      { backup_eligible: credential.backupEligible },
      { now: deps.now },
    );
  });
}

/**
 * ログインで、資格情報 ID から保存済みの資格情報を引く（ADR 0007 の3、ADR 0018）。
 * 境界は、アサーションの userHandle（= 利用者 ID）。その利用者の資格情報の中で ID が一致しなければ undefined。
 * 別の利用者の資格情報 ID でも、存在しない ID でも、同じ undefined になる。
 */
export async function findCredential(
  deps: RepoDeps,
  userId: WarifuUserId,
  credentialId: Uint8Array,
): Promise<StoredCredential | undefined> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const [row] = await tx.query<CredentialRow>(
      sql`SELECT credential_id, user_id, public_key, sign_count, transports, backup_eligible, backed_up,
                 created_at, last_used_at
            FROM idp.credentials WHERE credential_id = ${credentialId}`,
    );
    return row === undefined ? undefined : toCredential(row);
  });
}

export async function recordCredentialUse(
  deps: RepoDeps,
  userId: WarifuUserId,
  credentialId: Uint8Array,
  signCount: number,
  backedUp: boolean,
): Promise<void> {
  await deps.db.withWarifuUser(userId, async (tx) => {
    await tx.execute(
      sql`UPDATE idp.credentials SET sign_count = ${signCount}, backed_up = ${backedUp},
                 last_used_at = ${deps.now()}
           WHERE credential_id = ${credentialId}`,
    );
  });
}

export async function listCredentials(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<StoredCredential[]> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const rows = await tx.query<CredentialRow>(
      sql`SELECT credential_id, user_id, public_key, sign_count, transports, backup_eligible, backed_up,
                 created_at, last_used_at
            FROM idp.credentials ORDER BY created_at, credential_id`,
    );
    return rows.map(toCredential);
  });
}

/** 利用者が存在するか（境界の中で、自分の行が見えるか）。 */
export async function userExists(deps: RepoDeps, userId: WarifuUserId): Promise<boolean> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const rows = await tx.query(sql`SELECT user_id FROM idp.users`);
    return rows.length === 1;
  });
}

async function countCredentials(tx: Tx): Promise<number> {
  const row = await tx.one<{ count: string }>(
    sql`SELECT pg_catalog.count(*) AS count FROM idp.credentials`,
  );
  return Number(row.count);
}

export async function addCredential(
  deps: RepoDeps,
  userId: WarifuUserId,
  credential: NewCredential,
): Promise<void> {
  await deps.db.withWarifuUser(userId, async (tx) => {
    await insertCredential(tx, userId, credential);
    const count = await countCredentials(tx);
    await appendAudit(
      tx,
      deps.keys,
      PASSKEY_ADDED,
      { backup_eligible: credential.backupEligible, count },
      { now: deps.now },
    );
  });
}

/** 最後の1つは消させない（回復の手段が整うまで、ログインできなくなるため）。消せたら true。 */
export async function deleteCredential(
  deps: RepoDeps,
  userId: WarifuUserId,
  credentialId: Uint8Array,
): Promise<boolean> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const count = await countCredentials(tx);
    if (count <= 1) return false;
    const deleted = await tx.execute(
      sql`DELETE FROM idp.credentials WHERE credential_id = ${credentialId}`,
    );
    if (deleted !== 1) return false;
    await appendAudit(tx, deps.keys, PASSKEY_REMOVED, { count: count - 1 }, { now: deps.now });
    return true;
  });
}

export async function hasConnection(
  deps: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<boolean> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const rows = await tx.query(
      sql`SELECT tenant_id FROM idp.connections WHERE tenant_id = ${tenantId}`,
    );
    return rows.length === 1;
  });
}

export async function listConnections(
  deps: RepoDeps,
  userId: WarifuUserId,
): Promise<{ tenantId: TenantId; consentedAt: Date }[]> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const rows = await tx.query<{ tenant_id: string; consented_at: Date }>(
      sql`SELECT tenant_id, consented_at FROM idp.connections ORDER BY consented_at, tenant_id`,
    );
    return rows.map((row) => ({
      tenantId: row.tenant_id as TenantId,
      consentedAt: row.consented_at,
    }));
  });
}

/** 接続の同意を記録する。初めてのときだけ監査ログに残す。 */
export async function recordConnection(
  deps: RepoDeps,
  userId: WarifuUserId,
  tenantId: TenantId,
): Promise<void> {
  await deps.db.withWarifuUser(userId, async (tx) => {
    const inserted = await tx.execute(
      sql`INSERT INTO idp.connections (tenant_id, user_id) VALUES (${tenantId}, ${userId})
          ON CONFLICT (tenant_id, user_id) DO NOTHING`,
    );
    if (inserted === 1) {
      await appendAudit(
        tx,
        deps.keys,
        CONNECTION_CONSENTED,
        { tenant_id: tenantId },
        { now: deps.now },
      );
    }
  });
}

/** テナントの中で、この利用者の最新の別名の世代（なければ undefined）。 */
export async function latestAliasGeneration(
  deps: RepoDeps,
  tenantId: TenantId,
  userId: WarifuUserId,
): Promise<number | undefined> {
  return deps.db.withTenant(tenantId, async (tx) => {
    const [row] = await tx.query<{ generation: number | null }>(
      sql`SELECT pg_catalog.max(generation) AS generation FROM aliases.generation WHERE user_id = ${userId}`,
    );
    return row?.generation ?? undefined;
  });
}

/** 第1世代を置く。すでにあれば何もしない（同時に2つ来ても、主キーで1つになる）。 */
export async function insertFirstAliasGeneration(
  deps: RepoDeps,
  tenantId: TenantId,
  userId: WarifuUserId,
  lookupMac: Uint8Array,
): Promise<void> {
  await deps.db.withTenant(tenantId, async (tx) => {
    await tx.execute(
      sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
          VALUES (${tenantId}, ${userId}, 1, ${lookupMac})
          ON CONFLICT (tenant_id, user_id, generation) DO NOTHING`,
    );
  });
}

export interface EmailStatus {
  readonly registered: boolean;
  readonly updatedAt: Date | null;
  readonly pendingUntil: Date | null;
}

export async function emailStatus(deps: RepoDeps, userId: WarifuUserId): Promise<EmailStatus> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const [current] = await tx.query<{ updated_at: Date }>(
      sql`SELECT updated_at FROM contacts.email`,
    );
    const [pending] = await tx.query<{ expires_at: Date }>(
      sql`SELECT expires_at FROM contacts.email_pending WHERE expires_at > ${deps.now()} AND attempts < 5`,
    );
    return {
      registered: current !== undefined,
      updatedAt: current?.updated_at ?? null,
      pendingUntil: pending?.expires_at ?? null,
    };
  });
}

/** 宛先確認を始める。前の確認中のものは捨てる。 */
export async function putPendingEmail(
  deps: RepoDeps,
  userId: WarifuUserId,
  input: {
    readonly ciphertext: Uint8Array;
    readonly codeMac: Uint8Array;
    readonly expiresAt: Date;
  },
): Promise<void> {
  await deps.db.withWarifuUser(userId, async (tx) => {
    await tx.execute(sql`DELETE FROM contacts.email_pending`);
    await tx.execute(
      sql`INSERT INTO contacts.email_pending (user_id, ciphertext, code_mac, expires_at)
          VALUES (${userId}, ${input.ciphertext}, ${input.codeMac}, ${input.expiresAt})`,
    );
    const [current] = await tx.query(sql`SELECT user_id FROM contacts.email`);
    await appendAudit(
      tx,
      deps.keys,
      EMAIL_VERIFICATION_STARTED,
      { change: current !== undefined },
      { now: deps.now },
    );
  });
}

export type ConfirmResult = 'registered' | 'changed' | 'invalid';

/**
 * 確認コードを照合する。照合は MAC どうしの比較を SQL の WHERE で行う。試行は5回まで（超えたら確認中のものを捨てる）。
 * 一致したら、確認中の暗号文を現在のものにし、前のものは email_previous に移す（旧アドレスへの知らせのため。M4）。
 */
export async function confirmPendingEmail(
  deps: RepoDeps,
  userId: WarifuUserId,
  codeMac: Uint8Array,
): Promise<ConfirmResult> {
  return deps.db.withWarifuUser(userId, async (tx) => {
    const now = deps.now();
    const [pending] = await tx.query<{ attempts: number; ok: boolean; ciphertext: Uint8Array }>(
      sql`UPDATE contacts.email_pending SET attempts = attempts + 1
           WHERE expires_at > ${now} AND attempts < 5
       RETURNING attempts, code_mac = ${codeMac} AS ok, ciphertext`,
    );
    if (pending === undefined) return 'invalid';
    if (!pending.ok) {
      if (pending.attempts >= 5) await tx.execute(sql`DELETE FROM contacts.email_pending`);
      return 'invalid';
    }
    const [current] = await tx.query<{ ciphertext: Uint8Array }>(
      sql`SELECT ciphertext FROM contacts.email`,
    );
    const ciphertext = new Uint8Array(pending.ciphertext);
    if (current === undefined) {
      await tx.execute(
        sql`INSERT INTO contacts.email (user_id, ciphertext, updated_at) VALUES (${userId}, ${ciphertext}, ${now})`,
      );
    } else {
      await tx.execute(sql`DELETE FROM contacts.email_previous`);
      await tx.execute(
        sql`INSERT INTO contacts.email_previous (user_id, ciphertext, replaced_at)
            VALUES (${userId}, ${new Uint8Array(current.ciphertext)}, ${now})`,
      );
      await tx.execute(
        sql`UPDATE contacts.email SET ciphertext = ${ciphertext}, updated_at = ${now}`,
      );
    }
    await tx.execute(sql`DELETE FROM contacts.email_pending`);
    await appendAudit(
      tx,
      deps.keys,
      EMAIL_VERIFIED,
      { change: current !== undefined },
      { now: deps.now },
    );
    return current === undefined ? 'registered' : 'changed';
  });
}
