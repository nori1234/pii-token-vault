// 名前解決（不変条件7、CAP-22・24、ADR 0022）。sender の中で、注入したリゾルバだけを通す。
// 接続に使う名前は、A と AAAA の答えを全部見て、1つでも公開でないアドレスがあれば、その名前を断る。
// 接続は、ここで確かめたアドレスに直接つなぐ（もう一度名前を引かない。DNS rebinding 対策）。

import { Resolver } from 'node:dns/promises';
import { isPublicAddress } from './address.ts';

/** node:dns/promises の Resolver のうち、sender が使うメソッド。テストでは模擬のものを渡す。 */
export interface DnsResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolveTxt(name: string): Promise<string[][]>;
}

/** 本番の既定のリゾルバ。問い合わせ先は OS の設定。時間切れは2秒、2回まで。 */
export function systemResolver(): DnsResolver {
  return new Resolver({ timeout: 2000, tries: 2 });
}

export type ResolveFailure = 'blocked_address' | 'no_address' | 'dns_failed' | 'timeout';

export class ResolveError extends Error {
  readonly reason: ResolveFailure;

  constructor(reason: ResolveFailure) {
    super('宛先の名前解決が通らない');
    this.name = 'ResolveError';
    this.reason = reason;
  }
}

const EMPTY_ANSWER = new Set(['ENODATA', 'ENOTFOUND']);
const MAX_ADDRESSES = 16;

export function dnsCodeOf(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : 'ESERVFAIL';
}

async function answers(lookup: Promise<string[]>): Promise<string[]> {
  try {
    return await lookup;
  } catch (error) {
    const code = dnsCodeOf(error);
    if (EMPTY_ANSWER.has(code)) return [];
    throw new ResolveError(code === 'ETIMEOUT' ? 'timeout' : 'dns_failed');
  }
}

/** 名前の A と AAAA を引き、すべてが公開のアドレスなら、そのアドレスを返す。 */
export async function resolvePublicAddresses(
  resolver: DnsResolver,
  host: string,
): Promise<readonly string[]> {
  const [v4, v6] = await Promise.all([
    answers(resolver.resolve4(host)),
    answers(resolver.resolve6(host)),
  ]);
  const all = [...v4, ...v6];
  if (all.length === 0) throw new ResolveError('no_address');
  if (all.length > MAX_ADDRESSES || !all.every(isPublicAddress)) {
    throw new ResolveError('blocked_address');
  }
  return Object.freeze(all);
}
