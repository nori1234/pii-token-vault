// 本物のアドレスへのメールの出口（不変条件3、plan 10章 M3、ADR 0018）。
//
// idp は本物のアドレスを持たない（暗号文は復号できない）。送り先は利用者 ID だけで指定し、どのアドレス（確認中、現在、
// 変更前）に送るかは種類で決める。M4 で relay の内部配送 API に差し替える。relay は、その利用者の範囲で暗号文を読み、
// 復号して送る。
//
// M3 では、メモリの送信箱だけを使う（開発とテスト用）。メールの本文は relay が固定の文面で作る。idp が渡すのは、
// 種類と、確認コード（宛先確認のときだけ）だけ。旧アドレスへの知らせには、操作のリンクもコードも入れない（plan 4章）。

import type { WarifuUserId } from '@pii-token-vault/warifu-core';

export type MailRequest =
  | {
      readonly kind: 'email_verification';
      readonly userId: WarifuUserId;
      /** 確認中のアドレス（contacts.email_pending）に送る8桁のコード。 */
      readonly code: string;
    }
  | {
      readonly kind: 'email_changed_notice';
      readonly userId: WarifuUserId;
    };

export interface Mailer {
  sendToUser(request: MailRequest): Promise<void>;
}

/** 開発とテストの送信箱。送らずに、メモリに積む。上限を超えたら古いものから捨てる。 */
export class MemoryOutbox implements Mailer {
  readonly #messages: MailRequest[] = [];
  readonly #limit: number;

  constructor(limit = 1000) {
    this.#limit = limit;
  }

  async sendToUser(request: MailRequest): Promise<void> {
    this.#messages.push(Object.freeze({ ...request }));
    if (this.#messages.length > this.#limit) this.#messages.shift();
  }

  /** テストで、その利用者あての最後のものを見る。 */
  lastFor(userId: WarifuUserId, kind?: MailRequest['kind']): MailRequest | undefined {
    return this.#messages
      .filter((m) => m.userId === userId && (kind === undefined || m.kind === kind))
      .at(-1);
  }

  all(): readonly MailRequest[] {
    return [...this.#messages];
  }
}
