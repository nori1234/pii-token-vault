// relay の返信の DMARC の判定に使う名前解決（不変条件7、CAP-24、ADR 0021、ADR 0022）。relay だけが呼ぶ。
// 答えは mailauth の resolver の形にする（TXT は string[][]、MX は { exchange, priority }[]、A と AAAA は string[]）。
// 名前解決だけで、どこにもつながない。答えの大きさに上限を設ける。

import type {
  DnsErrorCode,
  DnsRecords,
  DnsType,
} from '@pii-token-vault/warifu-core/sender/protocol';
import { isDnsQueryName } from './names.ts';
import { type DnsResolver, dnsCodeOf } from './resolve.ts';

const MAX_RECORDS = 64;
const MAX_ANSWER_BYTES = 32_768;

export type DnsOutcome =
  | { readonly ok: true; readonly records: DnsRecords }
  | { readonly ok: false; readonly code: DnsErrorCode };

function codeOf(error: unknown): DnsErrorCode {
  const code = dnsCodeOf(error);
  if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'ETIMEOUT') return code;
  return 'ESERVFAIL';
}

export async function lookupDns(
  resolver: DnsResolver,
  input: { readonly name: string; readonly type: DnsType },
): Promise<DnsOutcome> {
  const name = input.name.toLowerCase().replace(/\.$/, '');
  if (!isDnsQueryName(name)) return { ok: false, code: 'EBADNAME' };
  let records: DnsRecords;
  try {
    switch (input.type) {
      case 'TXT':
        records = await resolver.resolveTxt(name);
        break;
      case 'MX':
        records = (await resolver.resolveMx(name)).map((r) => ({
          exchange: r.exchange,
          priority: r.priority,
        }));
        break;
      case 'A':
        records = await resolver.resolve4(name);
        break;
      case 'AAAA':
        records = await resolver.resolve6(name);
        break;
    }
  } catch (error) {
    return { ok: false, code: codeOf(error) };
  }
  if (
    records.length > MAX_RECORDS ||
    Buffer.byteLength(JSON.stringify(records)) > MAX_ANSWER_BYTES
  ) {
    return { ok: false, code: 'ESERVFAIL' };
  }
  return { ok: true, records };
}
