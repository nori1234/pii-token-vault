// PWA のセッション（ADR 0018）。クッキーの値は乱数の id で、保存の鍵は MAC（storage.ts）。署名の鍵は持たない。
//
// - 最後の操作から30分、作ってから最長8時間で切れる。
// - step-up（新しい認証）は5分以内。メールの登録と変更、パスキーの追加と削除に求める（plan 4章、DESIGN.md 2章）。
// - パスキーを消したら、その利用者のセッションをすべて消す（plan 2章の「M3 で決める」）。
// - 承認用のオリジンのセッション（ADR 0023）は、同じ仕組みで別のクッキーと別の保存の種類にする。
//   そのオリジンでのパスキーのログインだけで作り、最後の操作から10分、作ってから最長1時間で切れる。

import { randomBytesOf, toBase64Url, type WarifuUserId } from '@pii-token-vault/warifu-core';
import type { MacMemoryStore } from './storage.ts';

export const PWA_SESSION_COOKIE = 'warifu_idp_pwa';
export const SESSION_IDLE_SECONDS = 30 * 60;
export const SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60;
export const STEP_UP_SECONDS = 5 * 60;
export const APPROVAL_SESSION_COOKIE = 'warifu_idp_approval';
export const APPROVAL_SESSION_IDLE_SECONDS = 10 * 60;
export const APPROVAL_SESSION_ABSOLUTE_SECONDS = 60 * 60;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface PwaSession {
  readonly userId: WarifuUserId;
  /** 作った時刻（ミリ秒）。 */
  readonly createdAt: number;
  /** 最後にパスキーで認証した時刻（ミリ秒）。 */
  readonly authTime: number;
  /** セッションを結び付けるための参照（チャレンジの bind）。id そのものではない。 */
  readonly ref: string;
}

export interface SessionPolicy {
  /** 保存の種類（MacMemoryStore の kind）。 */
  readonly kind: 'PwaSession' | 'ApprovalSession';
  readonly idleSeconds: number;
  readonly absoluteSeconds: number;
}

export const PWA_SESSION_POLICY: SessionPolicy = Object.freeze({
  kind: 'PwaSession',
  idleSeconds: SESSION_IDLE_SECONDS,
  absoluteSeconds: SESSION_ABSOLUTE_SECONDS,
});

export const APPROVAL_SESSION_POLICY: SessionPolicy = Object.freeze({
  kind: 'ApprovalSession',
  idleSeconds: APPROVAL_SESSION_IDLE_SECONDS,
  absoluteSeconds: APPROVAL_SESSION_ABSOLUTE_SECONDS,
});

export class PwaSessions {
  readonly #store: MacMemoryStore;
  readonly #now: () => number;
  readonly #policy: SessionPolicy;

  constructor(
    store: MacMemoryStore,
    now: () => number = Date.now,
    policy: SessionPolicy = PWA_SESSION_POLICY,
  ) {
    this.#store = store;
    this.#now = now;
    this.#policy = policy;
  }

  /** 新しいセッションを作り、クッキーの値を返す。 */
  async create(userId: WarifuUserId): Promise<string> {
    const id = toBase64Url(randomBytesOf(32));
    const now = this.#now();
    const session: PwaSession = {
      userId,
      createdAt: now,
      authTime: now,
      ref: toBase64Url(randomBytesOf(16)),
    };
    await this.#store.set(this.#policy.kind, id, session, this.#policy.idleSeconds);
    return id;
  }

  /** 有効なら返し、最後の操作の時刻を進める。 */
  async get(cookie: unknown): Promise<PwaSession | undefined> {
    if (typeof cookie !== 'string' || !SESSION_ID_PATTERN.test(cookie)) return undefined;
    const key = await this.#store.keyOf(this.#policy.kind, cookie);
    const session = this.#store.getByKey<PwaSession>(key);
    if (session === undefined) return undefined;
    const now = this.#now();
    if (now - session.createdAt >= this.#policy.absoluteSeconds * 1000) {
      this.#store.deleteByKey(key);
      return undefined;
    }
    this.#store.setByKey(key, session, this.#policy.idleSeconds);
    return session;
  }

  isFresh(session: PwaSession): boolean {
    return this.#now() - session.authTime <= STEP_UP_SECONDS * 1000;
  }

  /** step-up の後。同じ利用者のときだけ、認証の時刻を進める。 */
  async markAuthenticated(cookie: string, userId: WarifuUserId): Promise<boolean> {
    const key = await this.#store.keyOf(this.#policy.kind, cookie);
    const session = this.#store.getByKey<PwaSession>(key);
    if (session === undefined || session.userId !== userId) return false;
    this.#store.setByKey(key, { ...session, authTime: this.#now() }, this.#policy.idleSeconds);
    return true;
  }

  async destroy(cookie: unknown): Promise<void> {
    if (typeof cookie === 'string' && SESSION_ID_PATTERN.test(cookie)) {
      await this.#store.delete(this.#policy.kind, cookie);
    }
  }

  /** その利用者の PWA のセッションをすべて消す。 */
  revokeUser(userId: WarifuUserId): number {
    return this.#store.deleteWhere(
      this.#policy.kind,
      (value) => (value as PwaSession | undefined)?.userId === userId,
    );
  }
}
