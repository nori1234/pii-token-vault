// 企業ごとの別名（不変条件4・5、ADR 0005、ADR 0018）。
// 別名は DB に置かず、鍵サービスの derive_alias で、その都度導く。DB には照合用の mac(alias_lookup) だけを置く。
// 第1世代は、初めての接続の同意で idp が置く。第2世代以降（再発行）は company-api が置く（M5）。

import { aliasLookupMessage, type WarifuUserId } from '@pii-token-vault/warifu-core';
import type { TenantEntry } from './registry.ts';
import { insertFirstAliasGeneration, latestAliasGeneration, type RepoDeps } from './repo.ts';

export interface AliasKeyClient {
  deriveAlias(input: {
    readonly tenantId: TenantEntry['tenantId'];
    readonly userId: WarifuUserId;
    readonly generation: number;
  }): Promise<string>;
  mac(purpose: 'alias_lookup', message: Uint8Array): Promise<Uint8Array>;
}

/** 最新の世代の別名（`<ローカル部>@<テナントの relay ドメイン>`）。まだ世代がなければ undefined。 */
export async function currentAlias(
  repo: RepoDeps,
  keys: AliasKeyClient,
  tenant: TenantEntry,
  userId: WarifuUserId,
): Promise<string | undefined> {
  const generation = await latestAliasGeneration(repo, tenant.tenantId, userId);
  if (generation === undefined) return undefined;
  const local = await keys.deriveAlias({ tenantId: tenant.tenantId, userId, generation });
  return `${local}@${tenant.relayDomain}`;
}

/** 第1世代がなければ置く。 */
export async function ensureFirstAlias(
  repo: RepoDeps,
  keys: AliasKeyClient,
  tenant: TenantEntry,
  userId: WarifuUserId,
): Promise<void> {
  if ((await latestAliasGeneration(repo, tenant.tenantId, userId)) !== undefined) return;
  const local = await keys.deriveAlias({ tenantId: tenant.tenantId, userId, generation: 1 });
  const lookupMac = await keys.mac('alias_lookup', aliasLookupMessage(local));
  await insertFirstAliasGeneration(repo, tenant.tenantId, userId, lookupMac);
}
