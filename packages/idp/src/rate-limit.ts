// 機能ごとのレート制限（plan 2章、CAP-34、ADR 0018）。プロセスのメモリの固定窓。
// キーは「アカウント」「送信元（IP）」の2つを、機能ごとに組み合わせる。キーそのものは保存の鍵にしか使わない
// （ログに出さない）。値は ADR 0018 の表を正とする。

export interface LimitRule {
  readonly limit: number;
  readonly windowSeconds: number;
}

/** ADR 0018 の表。 */
export const RATE_LIMITS = Object.freeze({
  /** パスキーでアカウントを作る（IP ごと）。 */
  accountCreateByIp: { limit: 10, windowSeconds: 3600 },
  /** パスキーのアサーションの検証（IP ごと）。 */
  loginByIp: { limit: 20, windowSeconds: 60 },
  /** パスキーのアサーションの検証（userHandle の利用者ごと）。 */
  loginByUser: { limit: 10, windowSeconds: 60 },
  /** 確認コードの送信（利用者ごと）。 */
  emailSendByUser: { limit: 3, windowSeconds: 900 },
  /** 確認コードの送信（IP ごと）。 */
  emailSendByIp: { limit: 20, windowSeconds: 3600 },
  /** WebAuthn の選択肢の発行（IP ごと。チャレンジでメモリを埋めさせない）。 */
  ceremonyByIp: { limit: 60, windowSeconds: 60 },
} satisfies Record<string, LimitRule>);

export type LimitName = keyof typeof RATE_LIMITS;

const MAX_KEYS = 100_000;

export class RateLimiter {
  readonly #now: () => number;
  readonly #rules: Readonly<Record<LimitName, LimitRule>>;
  readonly #windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    now: () => number = Date.now,
    rules: Readonly<Record<LimitName, LimitRule>> = RATE_LIMITS,
  ) {
    this.#now = now;
    this.#rules = rules;
  }

  /** 1回分を数え、上限の中なら true。 */
  take(name: LimitName, key: string): boolean {
    const rule = this.#rules[name];
    const now = this.#now();
    const id = `${name}\u0000${key}`;
    let window = this.#windows.get(id);
    if (window === undefined || window.resetAt <= now) {
      if (window === undefined && this.#windows.size >= MAX_KEYS) this.#sweep(now);
      window = { count: 0, resetAt: now + rule.windowSeconds * 1000 };
      this.#windows.set(id, window);
    }
    window.count += 1;
    return window.count <= rule.limit;
  }

  #sweep(now: number): void {
    for (const [id, window] of this.#windows) {
      if (window.resetAt <= now) this.#windows.delete(id);
    }
    // それでも多ければ、古いものから捨てる（制限が緩む方向だが、メモリを使い切らせない）。
    for (const id of this.#windows.keys()) {
      if (this.#windows.size < MAX_KEYS) break;
      this.#windows.delete(id);
    }
  }
}
