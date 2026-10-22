// サービスの資格情報の検証（ADR 0012）。
// ヘッダーは `Authorization: Bearer <service>.<32バイトの base64url>`。
// 形が違う、知らないサービス、長さが違うときも、ダミーの32バイトと比べてから失敗にする（所要時間をそろえる）。

import { constantTimeEqual } from '@pii-token-vault/warifu-core';
import {
  CREDENTIAL_SECRET_BYTES,
  KEYSVC_CALLERS,
  type KeysvcCaller,
} from '@pii-token-vault/warifu-core/keys/protocol';
import { randomId } from './crypto.ts';

// 32バイトの base64url（パディングなし）は43文字。最後の文字は余りのビットが0になるものだけ。
const BEARER_PATTERN = /^Bearer ([a-z-]{1,16})\.([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/;

export function createAuthenticator(
  credentials: Readonly<Record<KeysvcCaller, Uint8Array>>,
): (authorization: string | undefined) => KeysvcCaller | undefined {
  const dummy = randomId(CREDENTIAL_SECRET_BYTES);
  const dummyOther = randomId(CREDENTIAL_SECRET_BYTES);
  return (authorization) => {
    const match = typeof authorization === 'string' ? BEARER_PATTERN.exec(authorization) : null;
    const name = match?.[1];
    const caller = KEYSVC_CALLERS.find((c) => c === name);
    if (match === null || caller === undefined) {
      constantTimeEqual(dummy, dummyOther);
      return undefined;
    }
    const presented = new Uint8Array(Buffer.from(match[2] ?? '', 'base64url'));
    if (presented.byteLength !== CREDENTIAL_SECRET_BYTES) {
      constantTimeEqual(dummy, dummyOther);
      return undefined;
    }
    return constantTimeEqual(presented, credentials[caller]) ? caller : undefined;
  };
}
