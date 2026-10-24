// 複数のクライアントが共有する操作（mac と derive_alias）。exports に載せない。

import { ALIAS_LOCAL_PART_PATTERN } from '../aliases.ts';
import { parseTenantId, parseWarifuUserId, type TenantId, type WarifuUserId } from '../ids.ts';
import { KeysvcError } from './errors.ts';
import { LIMITS, MAX_ALIAS_GENERATION, type MacPurpose } from './protocol.ts';
import {
  assertOneOf,
  bytesFrom,
  encodeBytes,
  type KeysvcCall,
  MAC_BYTES,
  stringFrom,
} from './transport.ts';

export async function macWith(
  call: KeysvcCall,
  allowed: readonly MacPurpose[],
  purpose: MacPurpose,
  message: Uint8Array,
): Promise<Uint8Array> {
  const response = await call('mac', {
    purpose: assertOneOf(purpose, allowed),
    message: encodeBytes(message, LIMITS.macMessageBytes),
  });
  return bytesFrom(response, 'mac', MAC_BYTES);
}

export async function deriveAliasWith(
  call: KeysvcCall,
  input: {
    readonly tenantId: TenantId;
    readonly userId: WarifuUserId;
    readonly generation: number;
  },
): Promise<string> {
  const { generation } = input;
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > MAX_ALIAS_GENERATION) {
    throw new KeysvcError('invalid_request');
  }
  const response = await call('derive_alias', {
    tenantId: parseTenantId(input.tenantId),
    userId: parseWarifuUserId(input.userId),
    generation,
  });
  return stringFrom(response, 'localPart', ALIAS_LOCAL_PART_PATTERN);
}
