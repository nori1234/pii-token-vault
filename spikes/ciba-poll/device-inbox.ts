// 捨てスパイク2：端末の受信箱（メモリ上）。CIBA の承認待ちを、利用者の端末に届ける場所。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
//
// - 表示する文言は、割符が生成したものだけにする。企業が送った binding_message は入れない（plan 3-1、11章 テスト2）。
// - 企業名は、割符の登録簿の値を使う（企業が送った client_name などは使わない）。
// - auth_req_id の平文は持たない（不変条件4）。oidc-provider の保存キー（HMAC）だけを持つ。
// - 本番の受信箱は、M6 で DB と承認画面（DESIGN.md 2章）として作る。ここでは要素を確かめるだけにする。
import { randomUUID } from 'node:crypto';
import type { DeskChannel } from './desk-codes.ts';

/** resolving は、承認か拒否の処理の途中。この間は、同じものへの承認も拒否も受け付けない。 */
export type InboxState = 'pending' | 'resolving' | 'approved' | 'denied';

export interface CibaApprovalEntry {
  readonly entryId: string;
  /** 受信箱の持ち主（割符の内部の利用者 ID）。所有者の照合に使う。 */
  readonly userId: string;
  readonly kind: 'ciba-approval';
  /** 割符の登録簿にある企業名 */
  readonly companyName: string;
  readonly channel: DeskChannel;
  /** 操作の種類 */
  readonly operation: string;
  /** この承認で窓口ができることの範囲 */
  readonly scopeNote: string;
  /** 割符が生成した binding message */
  readonly bindingMessage: string;
  /** 承認画面に出す固定の警告文（文言は DESIGN.md 3章だけを正とする） */
  readonly warning: 'A-1';
  /** 使われた窓口コードの発行時刻（ミリ秒） */
  readonly codeIssuedAt: number;
  /** oidc-provider の保存キー（BackchannelAuthenticationRequest の id の HMAC） */
  readonly requestKey: string;
  state: InboxState;
}

export type NewCibaApprovalEntry = Omit<CibaApprovalEntry, 'entryId' | 'kind' | 'state'>;

export class DeviceInbox {
  readonly #entries = new Map<string, CibaApprovalEntry>();

  push(entry: NewCibaApprovalEntry): CibaApprovalEntry {
    const created: CibaApprovalEntry = {
      ...entry,
      entryId: randomUUID(),
      kind: 'ciba-approval',
      state: 'pending',
    };
    this.#entries.set(created.entryId, created);
    return created;
  }

  /** 利用者の受信箱。持ち主の分だけを返す。 */
  listFor(userId: string): readonly CibaApprovalEntry[] {
    return [...this.#entries.values()].filter((entry) => entry.userId === userId);
  }

  /** 持ち主が一致し、承認待ちのものだけを返す。 */
  pendingFor(entryId: string, userId: string): CibaApprovalEntry | undefined {
    const entry = this.#entries.get(entryId);
    if (entry === undefined || entry.userId !== userId || entry.state !== 'pending') {
      return undefined;
    }
    return entry;
  }

  /** 漏えいの確認用。保存している内容をそのまま文字列にする。 */
  dump(): string {
    return JSON.stringify([...this.#entries]);
  }
}
