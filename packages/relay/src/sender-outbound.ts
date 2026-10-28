// relay から送信サービスへの出口（不変条件7、CAP-24・26、ADR 0021、ADR 0022）。relay は外へつながない。
// - SenderOutbound：署名と封印を付けたメッセージを、sender の内部 API（/v1/mail）に渡す。sender が MX を引き、
//   内部の IP を指す宛先を拒否して接続する。
// - senderResolver：返信の DMARC の判定に使う名前解決を、sender の内部 API（/v1/dns）に渡す（mailauth の resolver）。
//
// 実配送を始める前に、受け取ったメールの永続化と、後の処理と配送の再試行を作る（ADR 0021 の O-19）。
// それまでは、この出口を使うのは開発とテストだけにする。

import type { SenderMailClient } from '@pii-token-vault/warifu-core/sender/client';
import type { DnsType, SenderRejectReason } from '@pii-token-vault/warifu-core/sender/protocol';
import type { DNSResolver } from 'mailauth';
import type { Outbound, OutboundMessage } from './outbound.ts';

/** sender が配送を断った。理由の種類だけを持つ（宛先を入れない）。 */
export class OutboundRejectedError extends Error {
  readonly code: SenderRejectReason;

  constructor(code: SenderRejectReason) {
    super('送信サービスが配送を断った');
    this.name = 'OutboundRejectedError';
    this.code = code;
  }
}

export class SenderOutbound implements Outbound {
  readonly #client: SenderMailClient;

  constructor(client: SenderMailClient) {
    this.#client = client;
  }

  async send(message: OutboundMessage): Promise<void> {
    const result = await this.#client.sendMail({
      mailFrom: message.mailFrom,
      rcptTo: message.rcptTo,
      raw: message.raw.toString('base64'),
    });
    if (!result.ok) throw new OutboundRejectedError(result.reason);
  }
}

const TYPES: ReadonlySet<string> = new Set<DnsType>(['TXT', 'MX', 'A', 'AAAA']);

function dnsError(code: string): Error {
  const error = new Error('名前解決が失敗した') as Error & { code: string };
  error.code = code;
  return error;
}

/** mailauth に渡すリゾルバ。TXT、MX、A、AAAA のほかは引かない（PTR などは ENOTFOUND にする）。 */
export function senderResolver(client: SenderMailClient): DNSResolver {
  return async (name: string, rrtype: string) => {
    const type = rrtype.toUpperCase();
    if (!TYPES.has(type)) throw dnsError('ENOTFOUND');
    const result = await client.resolveDns(name, type as DnsType);
    if (!result.ok) throw dnsError(result.code === 'EBADNAME' ? 'ENOTFOUND' : result.code);
    return result.records as unknown as string[][];
  };
}
