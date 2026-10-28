// 接続してよい IP アドレスか（SSRF 対策。plan 2章、CAP-22、ADR 0022）。
// 公開のユニキャストのアドレスだけを許す。IANA の特殊用途のアドレスの登録簿（IPv4、IPv6）にあるもの、
// プライベート、ループバック、リンクローカル（IMDS の 169.254.169.254 を含む）、CGN、マルチキャスト、
// 文書用、ベンチマーク用、IPv4 を埋め込んだ IPv6（::ffff:0:0/96、NAT64、6to4）は、すべて拒否する。
// IPv6 は、グローバルユニキャスト（2000::/3）の中だけを許す。

import { BlockList, isIP } from 'node:net';

const V4_BLOCKED: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.31.196.0', 24],
  ['192.52.193.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['192.175.48.0', 24],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const V6_BLOCKED: readonly (readonly [string, number])[] = [
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
];

const blocked = new BlockList();
for (const [network, prefix] of V4_BLOCKED) blocked.addSubnet(network, prefix, 'ipv4');
for (const [network, prefix] of V6_BLOCKED) blocked.addSubnet(network, prefix, 'ipv6');
const globalUnicast = new BlockList();
globalUnicast.addSubnet('2000::', 3, 'ipv6');

/** 公開のユニキャストのアドレスなら true。形が違うもの（ゾーン ID 付きなど）は false。 */
export function isPublicAddress(address: string): boolean {
  if (typeof address !== 'string' || address.includes('%')) return false;
  const family = isIP(address);
  if (family === 4) return !blocked.check(address, 'ipv4');
  if (family === 6) {
    return globalUnicast.check(address, 'ipv6') && !blocked.check(address, 'ipv6');
  }
  return false;
}
