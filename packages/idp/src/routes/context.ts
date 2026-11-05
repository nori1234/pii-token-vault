// ルートの群が共有するもの。createIdp が1つ作り、各群の register 関数に渡す。
// ルートは onMain（本来のオリジン）か onApproval（承認用のオリジン）のどちらか一方にだけ登録する（ADR 0023）。

import type { WarifuUserId } from '@pii-token-vault/warifu-core';
import type { DeskClient } from '@pii-token-vault/warifu-core/desk/client';
import type { IdpKeyClient } from '@pii-token-vault/warifu-core/keys/idp';
import type { FastifyInstance, FastifyReply, FastifyRequest, RouteShorthandOptions } from 'fastify';
import type Provider from 'oidc-provider';
import type { EmailFlowDeps } from '../email.ts';
import type { ApprovalTypes } from '../inbox.ts';
import type { Assets } from '../pages.ts';
import type { RateLimiter } from '../rate-limit.ts';
import type { Registry } from '../registry.ts';
import type { findCredential, RepoDeps } from '../repo.ts';
import type { PwaSession, PwaSessions } from '../sessions.ts';
import type { MacMemoryStore } from '../storage.ts';
import type { Ceremonies } from '../webauthn.ts';

export interface CurrentSession {
  readonly session: PwaSession;
  readonly cookie: string;
}

export interface RouteContext {
  readonly app: FastifyInstance;
  /** 本来のオリジンだけのルート。 */
  readonly onMain: RouteShorthandOptions;
  /** 承認用のオリジンだけのルート。 */
  readonly onApproval: RouteShorthandOptions;
  /** 本来のオリジン。 */
  readonly origin: string;
  readonly approvalOrigin: string;
  /** OIDC の issuer（操作ごとの承認の JWT の iss）。 */
  readonly issuer: string;
  readonly registry: Registry;
  readonly keys: IdpKeyClient;
  readonly repo: RepoDeps;
  readonly store: MacMemoryStore;
  /** PWA のセッション（本来のオリジン）。 */
  readonly sessions: PwaSessions;
  /** 承認用のオリジンのセッション。 */
  readonly approvalSessions: PwaSessions;
  readonly approvalTypes: ApprovalTypes;
  readonly limiter: RateLimiter;
  readonly ceremonies: Ceremonies;
  readonly emailDeps: EmailFlowDeps;
  readonly provider: Provider;
  /** company-api の窓口の内部 API（ADR 0026）。なければ、窓口の作成と取消を受け付けない。 */
  readonly desk: DeskClient | undefined;
  readonly assets: Assets;
  readonly nowMs: () => number;
  /** HTML を返す。CSP の nonce を作って、onSend の CSP に渡す。 */
  sendHtml(
    request: FastifyRequest,
    reply: FastifyReply,
    html: (nonce: string) => string,
  ): FastifyReply;
  setCookie(reply: FastifyReply, name: string, value: string): void;
  clearCookie(reply: FastifyReply, name: string): void;
  /**
   * PWA のセッション（本来のオリジンのルートだけが呼ぶ）。なければ 401 を送って undefined を返す。
   * undefined のときは、呼び出し側は reply をそのまま返す。
   */
  requireSession(request: FastifyRequest, reply: FastifyReply): Promise<CurrentSession | undefined>;
  /** step-up（5分以内の認証）が要る操作の前に呼ぶ。足りなければ 401 を送って undefined を返す。 */
  requireFreshSession(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<CurrentSession | undefined>;
  /** 承認用のオリジンのセッション（承認用のルートだけが呼ぶ）。なければ 401 を送って undefined を返す。 */
  requireApprovalSession(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<CurrentSession | undefined>;
  findForLogin(userId: WarifuUserId, credentialId: Uint8Array): ReturnType<typeof findCredential>;
  /** ログインの試行を、利用者と IP の両方のレート制限にかける。 */
  admitLogin(ip: string): (userId: WarifuUserId) => boolean;
  /** アサーションが通ったパスキーの、サインカウントと BS フラグを記録する。 */
  recordUse(result: {
    readonly userId: WarifuUserId;
    readonly credentialId: Uint8Array;
    readonly newSignCount: number;
    readonly backedUp: boolean;
  }): Promise<void>;
}
