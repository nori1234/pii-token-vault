// 企業に送る SET（RFC 8417。送り方は RFC 8935 の push。RP-50、ADR 0022）。
//
// - 署名は鍵サービスの set の鍵で ES256（typ は secevent+jwt）。
// - iss は company-api、aud はテナント ID（企業ごとに独立。不変条件5）、jti はイベントごとの乱数（128ビット。
//   テナントをまたいだ通番にしない）、iat は初めて送る時刻。exp は付けない。
// - P0 で送るイベントは、検証のイベント（SSF の verification。企業が受け口を確かめるために頼む）と、窓口の取消
//   （ADR 0026 の O-67）。回復（recovered_at）のイベントは M8 で足す。利用者に結び付くイベントは、テナントごとに
//   ランダムに遅らせて送る（企業をまたいだ突き合わせを防ぐ。テスト12）。検証のイベントは企業が自分で頼むものなので、
//   遅らせない。
// - 窓口の取消の中身は、変更ID、取消要求ID、受付期間の中で受理したこと（within_window）だけ。受理した正確な時刻は
//   入れない（企業をまたいだ照合の材料にしない）。

import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import type { CompanyTenant } from './config.ts';
import { type PublicKeyCache, signJwt } from './jwt.ts';

export const VERIFICATION_EVENT_URI =
  'https://schemas.openid.net/secevent/ssf/event-type/verification';

/** 窓口の取消のイベント（割符の製品の中の識別子。ADR 0026 の O-67）。 */
export const DESK_CANCELLATION_EVENT_URI = 'urn:warifu:secevent:desk-cancellation';

export type SetEventType = 'verification' | 'desk_cancellation';

export type SetContent =
  | {
      readonly type: 'verification';
      readonly state: string | null;
      readonly jti: string;
      readonly issuedAt: Date;
    }
  | {
      readonly type: 'desk_cancellation';
      readonly changeId: string;
      readonly cancellationId: string;
      readonly jti: string;
      readonly issuedAt: Date;
    };

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
      : {
          [DESK_CANCELLATION_EVENT_URI]: {
            change_id: content.changeId,
            cancellation_id: content.cancellationId,
            accepted: 'within_window',
          },
        };
  return signJwt(keys, cache, 'set', 'secevent+jwt', {
    iss: issuer,
    aud: tenant.tenantId,
    iat: Math.floor(content.issuedAt.getTime() / 1000),
    jti: content.jti,
    events,
  });
}
