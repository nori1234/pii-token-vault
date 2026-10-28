// 機能ごとのレート制限（plan 2章、CAP-34）。プロセスのメモリの固定窓。idp と company-api が使う。
// キーそのものは保存の鍵にしか使わない（ログに出さない）。上限の値は、使う側の ADR の表を正とする
// （idp は ADR 0018、company-api は ADR 0022）。

export interface LimitRule {
  readonly limit: number;
  readonly windowSeconds: number;
}

const MAX_KEYS = 100_000;

export class RateLimiter<N extends string> {
  readonly #now: () => number;
  readonly #rules: Readonly<Record<N, LimitRule>>;
  readonly #windows = new Map<string, { count: number; resetAt: number }>();

  constructor(rules: Readonly<Record<N, LimitRule>>, now: () => number = Date.now) {
    this.#rules = rules;
    this.#now = now;
  }

  /** 1回分を数え、上限の中なら true。 */
  take(name: N, key: string): boolean {
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
