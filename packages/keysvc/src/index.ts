// 鍵サービス（encrypt、mac、derive_alias、decrypt の ACL）。ADR 0012。
// ローカルでは別プロセス（src/main.ts）で立て、KMS の IAM を模す。本番は KMS に置き換える（P1）。
// DB は使わない。外向きの通信もしない。

export type { AclTarget } from './acl.ts';
export { ACL, allowedOp, allowedTarget } from './acl.ts';
export type { KeysvcConfig, KeysvcConfigReason } from './config.ts';
export { KeysvcConfigError, parseKeysvcConfig } from './config.ts';
export type { KeysvcServer } from './server.ts';
export { startKeysvcServer } from './server.ts';
