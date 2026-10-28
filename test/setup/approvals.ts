// 承認待ちのテストの補助（ADR 0023）。M6 には製品の承認待ちの型がまだないので、テストの型を使う。
// 型は割符のコードとして書くもの（企業の設定からは作らない）なので、テストでも同じ形で書く。

import type { ApprovalType, InboxContent } from '../../packages/idp/src/inbox.ts';
import type { WarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import { Browser, type TestIdp } from './idp.ts';
import type { SoftAuthenticator } from './soft-authenticator.ts';

const PLACE_KINDS: Readonly<Record<string, string>> = Object.freeze({
  convenience_store: 'コンビニエンスストア',
  post_office: '郵便局',
});

/** 端末での承認（step-up）の型の例：受け取り場所の変更。 */
export const TEST_DEVICE_TYPE: ApprovalType = {
  type: 'test.pickup_change',
  channel: 'device',
  operation: '受け取り場所の変更',
  parse(details: unknown): InboxContent | undefined {
    if (typeof details !== 'object' || details === null || Array.isArray(details)) return undefined;
    const { place_kind: kind, place_name: name, ...rest } = details as Record<string, unknown>;
    if (Object.keys(rest).length > 0) return undefined;
    if (typeof kind !== 'string' || !Object.hasOwn(PLACE_KINDS, kind)) return undefined;
    if (typeof name !== 'string' || name.length < 1 || name.length > 40) return undefined;
    return { place_kind: kind, place_name: name };
  },
  lines(content: InboxContent) {
    return [
      { label: '受け取り場所の種類', value: PLACE_KINDS[String(content.place_kind)] ?? '' },
      { label: '受け取り場所の名称', value: String(content.place_name) },
    ];
  },
};

/** 窓口での承認の型の例：照会だけ（中身なし）。 */
export const TEST_DESK_TYPE: ApprovalType = {
  type: 'test.desk_inquiry',
  channel: 'desk',
  operation: '窓口での照会',
  parse(details: unknown): InboxContent | undefined {
    if (typeof details !== 'object' || details === null || Object.keys(details).length > 0) {
      return undefined;
    }
    return {};
  },
  lines: () => [],
};

export const PICKUP_DETAILS = Object.freeze({
  place_kind: 'convenience_store',
  place_name: 'テスト店',
});

/** ソフトウェアの認証器の最後の資格情報の userHandle を、利用者 ID（UUID）にする。 */
export function userIdOf(authenticator: SoftAuthenticator): WarifuUserId {
  const credential = authenticator.credentials.at(-1);
  if (credential === undefined) throw new Error('資格情報がない');
  const hex = Buffer.from(credential.userHandle, 'base64url').toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as WarifuUserId;
}

/** PWA でアカウントを作り、同じ認証器で承認用のオリジンにログインしたブラウザ役を返す。 */
export async function newApprover(t: TestIdp): Promise<{
  pwa: Browser;
  approval: Browser;
  userId: WarifuUserId;
}> {
  const pwa = new Browser(t.origin);
  const created = await pwa.registerAccount();
  if (created.status !== 200) throw new Error('アカウントを作れなかった');
  const approval = new Browser(t.approvalOrigin, pwa.authenticator);
  const login = await approval.approvalLogin();
  if (login.status !== 200) throw new Error('承認用のオリジンにログインできなかった');
  return { pwa, approval, userId: userIdOf(pwa.authenticator) };
}
