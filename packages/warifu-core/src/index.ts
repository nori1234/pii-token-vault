// 暗号、DB の境界（withTenant と withWarifuUser）、ログの伏せ字、監査ログ。
// 鍵を使う処理は鍵サービス（packages/keysvc）の中で行う。ここには、ID、乱数、符号化と、各部品の入口を置く。
// 鍵のクライアントは `./keys/*`、DB は `./db`、監査ログは `./audit`、ログは `./log` から import する。

export { ALIAS_LOCAL_PART_PATTERN, aliasLookupMessage } from './aliases.ts';
export {
  canonicalJson,
  concatBytes,
  EncodingError,
  fromBase64Url,
  lengthPrefixed,
  toBase32Lower,
  toBase64Url,
  u32be,
  u64be,
  utf8,
} from './encoding.ts';
export type { Component, ServiceName, TenantId, WarifuUserId } from './ids.ts';
export {
  InvalidIdError,
  isUuid,
  newTenantId,
  newWarifuUserId,
  parseTenantId,
  parseWarifuUserId,
  SERVICE_ROLE,
  uuidBytes,
} from './ids.ts';
export { constantTimeEqual, randomBytesOf, randomUuid } from './random.ts';
