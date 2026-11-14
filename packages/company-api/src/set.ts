// 企業に送る SET（RFC 8417。送り方は RFC 8935 の push。RP-50、ADR 0022）。
//
// - 署名は鍵サービスの set の鍵で ES256（typ は secevent+jwt）。
// - iss は company-api、aud はテナント ID（企業ごとに独立。不変条件5）、jti はイベントごとの乱数（128ビット。
//   テナントをまたいだ通番にしない）、iat は初めて送る時刻。exp は付けない。
// - P0 で送るイベントは、検証のイベント（SSF の verification。企業が受け口を確かめるために頼む）と、窓口の取消
//   （ADR 0026 の O-67）と、回復（ADR 0027 の O-81。宛先の利用者は sub_id の opaque にテナントの sub を入れる。
//   recovered_at は日にまるめた値）。利用者に結び付くイベントは、テナントごとに
//   ランダムに遅らせて送る（企業をまたいだ突き合わせを防ぐ。テスト12）。検証のイベントは企業が自分で頼むものなので、
//   遅らせない。
// - 窓口の取消の中身は、変更ID、取消要求ID、受付期間の中で受理したこと（within_window）だけ。受理した正確な時刻は
//   入れない（企業をまたいだ照合の材料にしない）。
// - 初回紐付けの待機の知らせは移行専用ID だけ、取消は移行専用ID と取消ID だけ（ADR 0028 の O-91・O-103）。

import type { CompanyApiKeyClient } from '@pii-token-vault/warifu-core/keys/company-api';
import type { CompanyTenant } from './config.ts';
import { type PublicKeyCache, signJwt } from './jwt.ts';

export const VERIFICATION_EVENT_URI =
  'https://schemas.openid.net/secevent/ssf/event-type/verification';

/** 窓口の取消のイベント（割符の製品の中の識別子。ADR 0026 の O-67）。 */
export const DESK_CANCELLATION_EVENT_URI = 'urn:warifu:secevent:desk-cancellation';

/** 回復のイベント（割符の製品の中の識別子。ADR 0027 の O-81）。 */
export const ACCOUNT_RECOVERED_EVENT_URI = 'urn:warifu:secevent:account-recovered';

/** 初回紐付けの待機の知らせ（ADR 0028 の O-103）。企業は、受けたら旧会員の側に知らせを出す。 */
export const INITIAL_LINK_WAITING_EVENT_URI = 'urn:warifu:secevent:initial-link-waiting';

/** 初回紐付けの利用者の取消（ADR 0028 の O-91）。 */
export const INITIAL_LINK_CANCELLATION_EVENT_URI = 'urn:warifu:secevent:initial-link-cancellation';

export type SetEventType =
  | 'verification'
  | 'desk_cancellation'
  | 'account_recovered'
  | 'initial_link_waiting'
  | 'initial_link_cancellation';

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
    }
  | {
      readonly type: 'account_recovered';
      readonly sub: string;
      readonly recoveredDay: number;
      readonly jti: string;
      readonly issuedAt: Date;
    }
  | {
      readonly type: 'initial_link_waiting';
      readonly initialLinkId: string;
      readonly jti: string;
      readonly issuedAt: Date;
    }
  | {
      readonly type: 'initial_link_cancellation';
      readonly initialLinkId: string;
      readonly cancellationId: string;
      readonly jti: string;
      readonly issuedAt: Date;
    };

function eventsOf(content: SetContent): Record<string, object> {
  switch (content.type) {
    case 'verification':
      return { [VERIFICATION_EVENT_URI]: content.state === null ? {} : { state: content.state } };
    case 'desk_cancellation':
      return {
        [DESK_CANCELLATION_EVENT_URI]: {
          change_id: content.changeId,
          cancellation_id: content.cancellationId,
          accepted: 'within_window',
        },
      };
    case 'account_recovered':
      return { [ACCOUNT_RECOVERED_EVENT_URI]: { recovered_at: content.recoveredDay } };
    case 'initial_link_waiting':
      return { [INITIAL_LINK_WAITING_EVENT_URI]: { initial_link_id: content.initialLinkId } };
    case 'initial_link_cancellation':
      return {
        [INITIAL_LINK_CANCELLATION_EVENT_URI]: {
          initial_link_id: content.initialLinkId,
          cancellation_id: content.cancellationId,
        },
      };
  }
}

export async function signSet(
  keys: CompanyApiKeyClient,
  cache: PublicKeyCache,
  issuer: string,
  tenant: CompanyTenant,
  content: SetContent,
): Promise<string> {
  const events = eventsOf(content);
  return signJwt(keys, cache, 'set', 'secevent+jwt', {
    iss: issuer,
    aud: tenant.tenantId,
    iat: Math.floor(content.issuedAt.getTime() / 1000),
    jti: content.jti,
    ...(content.type === 'account_recovered'
      ? { sub_id: { format: 'opaque', id: content.sub } }
      : {}),
    events,
  });
}
