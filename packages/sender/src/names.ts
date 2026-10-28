// 宛先の名前と URL の形の検査（CAP-22、ADR 0022）。名前解決の前に、形だけで断れるものを断る。

/** 小文字の ASCII の DNS 名（ラベルは63文字まで、全体で253文字まで、2つ以上のラベル）。localhost は不可。 */
const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
/** 名前解決の口（TXT など）では、_dmarc や _domainkey のような _ で始まるラベルも許す。 */
const DNS_LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

function labelsOf(name: string, pattern: RegExp): string[] | undefined {
  if (typeof name !== 'string' || name.length < 1 || name.length > 253) return undefined;
  const labels = name.split('.');
  if (labels.length < 2 || !labels.every((label) => pattern.test(label))) return undefined;
  const last = labels.at(-1) ?? '';
  if (/^[0-9]+$/.test(last)) return undefined;
  if (last === 'localhost') return undefined;
  return labels;
}

/** 接続先のホスト名として受け付ける形か（IP アドレスの直書きは不可）。 */
export function isHostName(name: string): boolean {
  return labelsOf(name, HOST_LABEL) !== undefined;
}

/** 名前解決の口で受け付ける名前か。 */
export function isDnsQueryName(name: string): boolean {
  return labelsOf(name, DNS_LABEL) !== undefined;
}

export interface WebhookTarget {
  readonly host: string;
  readonly path: string;
}

/**
 * Webhook の URL。https、ポートは 443 だけ、利用者情報とフラグメントなし、ホストは名前（IP の直書きは不可）。
 * 形が違えば undefined。
 */
export function parseWebhookUrl(value: string): WebhookTarget | undefined {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\\]/.test(value)) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') {
    return undefined;
  }
  if (url.port !== '' && url.port !== '443') return undefined;
  if (!isHostName(url.hostname)) return undefined;
  return { host: url.hostname, path: `${url.pathname}${url.search}` };
}

/** 封筒のアドレス（`ローカル部@ドメイン`）。空白、制御文字、山括弧を含まない。ドメインは小文字にして返す。 */
export function parseEnvelopeAddress(
  value: string,
): { readonly local: string; readonly domain: string } | undefined {
  if (typeof value !== 'string' || value.length > 254 || /[\s<>()[\]\\,;:"]/.test(value)) {
    return undefined;
  }
  if (/[\p{Cc}]/u.test(value)) return undefined;
  const at = value.lastIndexOf('@');
  if (at < 1 || at > 64) return undefined;
  const domain = value.slice(at + 1).toLowerCase();
  if (!isHostName(domain)) return undefined;
  return { local: value.slice(0, at), domain };
}
