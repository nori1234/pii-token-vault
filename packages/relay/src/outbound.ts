// relay から外への配送の出口（不変条件7、ADR 0021）。relay は外へつながない。
// M4 では、メモリの送信箱だけを使う（開発とテスト用）。M5 で、送信サービス（packages/sender）の内部 API に差し替える。
// 送信サービスが MX を引き、内部の IP を指す宛先を拒否し、接続する（plan 2章）。
// 渡すのは、封筒（MAIL FROM、RCPT TO）と、署名済みのメッセージだけ。本物のアドレスは、メモリの中だけで扱う。

export interface OutboundMessage {
  /** 封筒の MAIL FROM（relay のドメインの戻りのアドレス）。 */
  readonly mailFrom: string;
  /** 封筒の RCPT TO（本物のアドレス、または企業の側のアドレス）。 */
  readonly rcptTo: string;
  /** 署名と封印を付けたメッセージ。 */
  readonly raw: Buffer;
}

export interface Outbound {
  send(message: OutboundMessage): Promise<void>;
}

/** 開発とテストの送信箱。送らずに、メモリに積む。上限を超えたら古いものから捨てる。 */
export class MemoryOutbound implements Outbound {
  readonly #messages: OutboundMessage[] = [];
  readonly #limit: number;

  constructor(limit = 1000) {
    this.#limit = limit;
  }

  async send(message: OutboundMessage): Promise<void> {
    this.#messages.push(Object.freeze({ ...message }));
    if (this.#messages.length > this.#limit) this.#messages.shift();
  }

  all(): readonly OutboundMessage[] {
    return [...this.#messages];
  }

  /** テストで、その宛先あての最後のものを見る。 */
  lastTo(rcptTo: string): OutboundMessage | undefined {
    return this.#messages.filter((m) => m.rcptTo === rcptTo).at(-1);
  }
}
