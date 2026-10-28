// 企業に送る SET（RFC 8417。送り方は RFC 8935 の push。RP-50、ADR 0022）。
//
// - 署名は鍵サービスの set の鍵で ES256（typ は secevent+jwt）。
// - iss は company-api、aud はテナント ID（企業ごとに独立。不変条件5）、jti はイベントごとの乱数（128ビット。
//   テナントをまたいだ通番にしない）、iat は初めて送る時刻。exp は付けない。
// - P0 で送るイベントは、検証のイベント（SSF の verification。企業が受け口を確かめるために頼む）だけ。
//   回復（recovered_at）のイベントは M8 で足す。利用者に結び付くイベントは、テナントごとにランダムに遅らせて送る
//   （企業をまたいだ突き合わせを防ぐ。テスト12）。検証のイベントは企業が自分で頼むものなので、遅らせない。

import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import type { CompanyTenant } from './config.ts';
import { type PublicKeyCache, signJwt } from './jwt.ts';

export const VERIFICATION_EVENT_URI =
  'https://schemas.openid.net/secevent/ssf/event-type/verification';

export type SetEventType = 'verification';

export interface SetContent {
  readonly type: SetEventType;
  readonly state: string | null;
  readonly jti: string;
  readonly issuedAt: Date;
}

export async function signSet(
  keys: CompanyApiKeyClient,
  cache: PublicKeyCache,
  issuer: string,
  tenant: CompanyTenant,
  content: SetContent,
): Promise<string> {
  const events =
    content.type === 'verification'
      ? { [VERIFICATION_EVENT_URI]: content.state === null ? {} : { state: content.state } }
      : {};
  return signJwt(keys, cache, 'set', 'secevent+jwt', {
    iss: issuer,
    aud: tenant.tenantId,
    iat: Math.floor(content.issuedAt.getTime() / 1000),
    jti: content.jti,
    events,
  });
}
