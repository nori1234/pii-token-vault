// 企業別ID（sub）の導出（不変条件5、plan 9章、ADR 0006、ADR 0018）。
//
// sub = base64url(HMAC(k_pairwise_sub, lp('warifu/sub/v1', テナント ID の16バイト, 利用者 ID の16バイト)))
// - 鍵は鍵サービスの mac(pairwise_sub)。idp のプロセスに鍵を置かない。
// - クライアントではなくテナントから導くので、同じテナントの別のクライアントでは同じ値、別のテナントでは別の値になる。
// - コードフロー（pairwiseIdentifier）と CIBA（M7 の processLoginHintToken）で、この関数だけを使う。
// - 鍵を入れ替えると全企業の sub が変わるので、入れ替えない（付け替えのイベントと合わせて P1 で決める）。

import {
  lengthPrefixed,
  type TenantId,
  toBase64Url,
  uuidBytes,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';

export const SUB_LABEL = 'warifu/sub/v1';

export interface SubjectMacClient {
  mac(purpose: 'pairwise_sub', message: Uint8Array): Promise<Uint8Array>;
}

export function subjectMessage(tenantId: TenantId, userId: WarifuUserId): Uint8Array {
  return lengthPrefixed([SUB_LABEL, uuidBytes(tenantId), uuidBytes(userId)]);
}

export async function deriveSub(
  keys: SubjectMacClient,
  tenantId: TenantId,
  userId: WarifuUserId,
): Promise<string> {
  const mac = await keys.mac('pairwise_sub', subjectMessage(tenantId, userId));
  if (mac.byteLength !== 32) throw new RangeError('MAC の長さが違う');
  return toBase64Url(mac);
}
