// 捨てスパイク2：窓口コード（CIBA の login_hint_token）の発行と照合。メモリ上の実装。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
//
// - 窓口コードは指名子にすぎない（不変条件1(c)）。これだけでは何も許可しない。承認は端末で行う。
// - 発行先の client_id に結び付け、有効期間は数分にする。
// - 一度照合したら、結果にかかわらず失効させる（別のクライアントからの照合、期限切れを含む）。
// - 平文を保存しない（不変条件4）。HMAC-SHA-256 を索引にする。
// - 桁数は、テナントごとの試行上限から M7 で決める（plan 3-1）。ここでは仮に10桁にする。
// - 本番では、発行は UV 付きのパスキーで行う（plan 3-1）。このスパイクでは発行の手順を省く。
import { createHmac, randomBytes, randomInt } from 'node:crypto';

export type DeskChannel = 'phone' | 'chat' | 'store';

export interface DeskCodeRecord {
  /** 割符の内部の利用者 ID。企業には渡さない。 */
  readonly userId: string;
  readonly clientId: string;
  readonly channel: DeskChannel;
  /** ミリ秒 */
  readonly issuedAt: number;
  /** ミリ秒 */
  readonly expiresAt: number;
}

export interface DeskCodeStoreOptions {
  /** 時刻（ミリ秒）。テストで期限切れを作るために差し替える。 */
  readonly now?: () => number;
  readonly ttlMs?: number;
  readonly digits?: number;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_DIGITS = 10;

export class DeskCodeStore {
  readonly #key = randomBytes(32);
  readonly #records = new Map<string, DeskCodeRecord>();
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #digits: number;
  readonly #pattern: RegExp;

  constructor(options: DeskCodeStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#digits = options.digits ?? DEFAULT_DIGITS;
    this.#pattern = new RegExp(`^[0-9]{${this.#digits}}$`);
  }

  #index(code: string): string {
    return createHmac('sha256', this.#key).update(code).digest('base64url');
  }

  #random(): string {
    return randomInt(0, 10 ** this.#digits)
      .toString()
      .padStart(this.#digits, '0');
  }

  /** 窓口コードを発行する。戻り値のコードは利用者の端末にだけ表示する。 */
  issue(
    userId: string,
    clientId: string,
    channel: DeskChannel,
  ): { code: string; expiresAt: number } {
    let code = this.#random();
    while (this.#records.has(this.#index(code))) {
      code = this.#random();
    }
    const issuedAt = this.#now();
    const expiresAt = issuedAt + this.#ttlMs;
    this.#records.set(this.#index(code), { userId, clientId, channel, issuedAt, expiresAt });
    return { code, expiresAt };
  }

  /**
   * 照合して、同時に失効させる。結び付いた client_id と期限も確かめる。
   * 失敗の理由（存在しない、別のクライアント、期限切れ、使用済み）は区別せず、すべて undefined を返す。
   */
  consume(code: string, clientId: string): DeskCodeRecord | undefined {
    if (!this.#pattern.test(code)) {
      return undefined;
    }
    const index = this.#index(code);
    const record = this.#records.get(index);
    if (record === undefined) {
      return undefined;
    }
    this.#records.delete(index);
    if (record.clientId !== clientId) {
      return undefined;
    }
    if (record.expiresAt <= this.#now()) {
      return undefined;
    }
    return record;
  }

  /** 漏えいの確認用。保存している内容をそのまま文字列にする。 */
  dump(): string {
    return JSON.stringify([...this.#records]);
  }
}
