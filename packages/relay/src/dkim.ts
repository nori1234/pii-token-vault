// relay が中継するメールに付ける DKIM の署名と ARC の封印（plan 8章、ADR 0021）。
//
// 正規化（relaxed/relaxed）、本文のハッシュ（bh=）、ヘッダーの組み立ては mailauth 7.3.1 の部品に任せ、
// 署名（rsa-sha256）だけを鍵サービスの dkim の鍵に頼む。秘密鍵は relay に来ない（CAP-04）。
// 件名と本文は変えない。付けるのはヘッダーだけ（上に足す）。

import body from 'mailauth/lib/dkim/body/index.js';
import header from 'mailauth/lib/dkim/header/index.js';
import tools from 'mailauth/lib/tools.js';

const ALGORITHM = 'rsa-sha256';
const CANONICALIZATION = 'relaxed/relaxed';
const CRLF = Buffer.from('\r\n');

/**
 * DKIM で署名するヘッダー。From、To、Subject は2回書いて重ねて署名する（oversign。後から同じ名前のヘッダーを
 * 足されると、署名が壊れる）。Date と Message-ID も入れる（plan 3-2 の送信元ロックと同じ考え方）。
 */
export const DKIM_SIGNED_HEADERS =
  'From:From:To:To:Subject:Subject:Date:Message-ID:Reply-To:Cc:MIME-Version:Content-Type:' +
  'Content-Transfer-Encoding:In-Reply-To:References:List-Unsubscribe:List-Unsubscribe-Post';

/** ARC-Message-Signature で署名するヘッダー。relay が付けた DKIM-Signature も含める。 */
const ARC_SIGNED_HEADERS = `DKIM-Signature:${DKIM_SIGNED_HEADERS}`;

export type DkimSign = (canonicalized: Uint8Array) => Promise<Uint8Array>;

export interface SignOptions {
  /** 署名のドメイン（d=）。テナントごとの relay のサブドメイン、または割符の知らせのドメイン。 */
  readonly domain: string;
  /** セレクタ（s=）。 */
  readonly selector: string;
  /** 鍵サービスの signDkim。 */
  readonly sign: DkimSign;
  /** 署名の時刻（t=）。 */
  readonly now: Date;
}

export interface SealOptions {
  /** 署名のドメイン（d=）。テナントごとの relay のサブドメイン。 */
  readonly domain: string;
  /** セレクタ（s=）。 */
  readonly selector: string;
  /** 鍵サービスの signDkim。 */
  readonly sign: DkimSign;
  /** 署名の時刻（t=）。 */
  readonly now: Date;
  /** ARC-Authentication-Results の authserv-id。 */
  readonly authservId: string;
  /** ARC-Authentication-Results の結果の部分（例：「dkim=pass header.d=example.com」）。固定の形だけを渡す。 */
  readonly authResults: string;
}

/** ヘッダーと本文の境目（最初の空行）で分ける。空行がなければ、本文は空。 */
export function splitMessage(raw: Buffer): { readonly head: Buffer; readonly body: Buffer } {
  const at = raw.indexOf('\r\n\r\n');
  if (at < 0) return { head: raw, body: Buffer.alloc(0) };
  return { head: raw.subarray(0, at + 2), body: raw.subarray(at + 4) };
}

function bodyHash(content: Buffer): string {
  const hasher = body.dkimBody(CANONICALIZATION, 'sha256');
  hasher.update(content);
  return hasher.digest('base64');
}

async function signLine(
  type: 'DKIM' | 'ARC',
  head: Buffer,
  fieldNames: string,
  options: SignOptions,
  bh: string,
  instance?: number,
): Promise<string> {
  const { parsed } = tools.parseHeaders(head);
  const lines = tools.getSigningHeaderLines(parsed, fieldNames, false);
  const t = Math.floor(options.now.getTime() / 1000);
  const { canonicalizedHeader, dkimHeaderOpts } = header.generateCanonicalizedHeader(type, lines, {
    signingDomain: options.domain,
    selector: options.selector,
    algorithm: ALGORITHM,
    canonicalization: CANONICALIZATION,
    bodyHash: bh,
    timestamp: t,
    instance: instance ?? false,
  });
  const signature = await options.sign(new Uint8Array(canonicalizedHeader));
  return tools.formatSignatureHeaderLine(
    type,
    { ...dkimHeaderOpts, b: Buffer.from(signature).toString('base64') },
    true,
  );
}

async function sealLine(
  aar: string,
  ams: string,
  options: SealOptions,
  instance: number,
): Promise<string> {
  const t = Math.floor(options.now.getTime() / 1000);
  const tags = { i: instance, a: ALGORITHM, t, cv: 'none', d: options.domain, s: options.selector };
  // 封印の対象は、この ARC の組の AAR、AMS と、b= を空にした ARC-Seal（RFC 8617 5.1.1）。
  const draft = tools.formatSignatureHeaderLine('AS', { b: 'a'.repeat(73), ...tags }, true);
  const canonicalized = Buffer.concat([
    tools.formatRelaxedLine(aar, '\r\n'),
    tools.formatRelaxedLine(ams, '\r\n'),
    tools.stripSignatureValue(tools.formatRelaxedLine(draft)),
  ]);
  const signature = await options.sign(new Uint8Array(canonicalized));
  return tools.formatSignatureHeaderLine(
    'AS',
    { ...tags, b: Buffer.from(signature).toString('base64') },
    true,
  );
}

/** relay の DKIM で署名するだけ（割符から利用者への知らせ。中継ではないので ARC は付けない）。 */
export async function signOnly(raw: Buffer, options: SignOptions): Promise<Buffer> {
  const { head, body: content } = splitMessage(raw);
  const dkim = await signLine('DKIM', head, DKIM_SIGNED_HEADERS, options, bodyHash(content));
  return Buffer.concat([Buffer.from(dkim), CRLF, head, CRLF, content]);
}

/**
 * relay の DKIM で署名し、ARC（i=1、cv=none）で封印する。元の ARC の組は、呼ぶ前に取り除いておく
 * （relay は From を自分のドメインに書き換えるので、受信側の DMARC は relay の DKIM で整合する。ADR 0021）。
 * 返すのは、ARC-Seal、ARC-Message-Signature、ARC-Authentication-Results、DKIM-Signature を上に足したもの。
 */
export async function signAndSeal(raw: Buffer, options: SealOptions): Promise<Buffer> {
  const { head, body: content } = splitMessage(raw);
  const bh = bodyHash(content);
  const dkim = await signLine('DKIM', head, DKIM_SIGNED_HEADERS, options, bh);
  const withDkim = Buffer.concat([Buffer.from(dkim), CRLF, head]);
  const aar = `ARC-Authentication-Results: i=1; ${options.authservId}; ${options.authResults}`;
  const ams = await signLine('ARC', withDkim, ARC_SIGNED_HEADERS, options, bh, 1);
  const seal = await sealLine(aar, ams, options, 1);
  return Buffer.concat([
    Buffer.from(seal),
    CRLF,
    Buffer.from(ams),
    CRLF,
    Buffer.from(aar),
    CRLF,
    withDkim,
    CRLF,
    content,
  ]);
}
