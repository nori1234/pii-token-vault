// 別名の照合用の MAC の入力（ADR 0005）。別名そのものは DB に置かず、mac(alias_lookup) の出力だけを置く。

import { EncodingError, lengthPrefixed } from './encoding.ts';

/** 別名のローカル部の形（鍵サービスの derive_alias の出力。80ビットを base32 の小文字で16文字）。 */
export const ALIAS_LOCAL_PART_PATTERN = /^[a-z2-7]{16}$/;

/** 別名のローカル部から、mac(alias_lookup) にかける入力を作る。 */
export function aliasLookupMessage(localPart: string): Uint8Array {
  if (typeof localPart !== 'string' || !ALIAS_LOCAL_PART_PATTERN.test(localPart)) {
    throw new EncodingError();
  }
  return lengthPrefixed(['warifu/alias-lookup/v1', localPart]);
}
