// relay が使う mailauth 7.3.1 の内部の部品の型（ADR 0021）。mailauth の公開の API は秘密鍵を受け取って署名するので、
// 正規化と本文のハッシュだけを mailauth に任せ、署名は鍵サービスに頼む。mailauth を更新するときは、この型と、
// packages/relay/src/dkim.ts の単体テストを確かめる（plan 9章「依存の更新」）。

declare module 'mailauth/lib/tools.js' {
  interface ParsedHeader {
    readonly key: string | null;
    readonly casedKey: string | undefined;
    readonly line: Buffer;
  }
  interface SigningHeaderLines {
    readonly keys: string;
    readonly headers: readonly ParsedHeader[];
  }
  const tools: {
    parseHeaders(buf: Buffer): { parsed: ParsedHeader[]; original: Buffer };
    getSigningHeaderLines(
      parsed: readonly ParsedHeader[],
      fieldNames: string,
      verify: boolean,
    ): SigningHeaderLines;
    formatSignatureHeaderLine(
      type: 'DKIM' | 'ARC' | 'AS',
      values: Record<string, string | number | null | undefined>,
      folded: boolean,
    ): string;
    formatRelaxedLine(line: Buffer | string, suffix?: string): Buffer;
    stripSignatureValue(line: Buffer, strict?: boolean): Buffer;
  };
  export = tools;
}

declare module 'mailauth/lib/dkim/header/index.js' {
  import type tools from 'mailauth/lib/tools.js';

  const header: {
    generateCanonicalizedHeader(
      type: 'DKIM' | 'ARC',
      signingHeaderLines: ReturnType<typeof tools.getSigningHeaderLines>,
      options: Record<string, string | number | boolean | null | undefined>,
    ): {
      canonicalizedHeader: Buffer;
      signatureHeaderLine: string;
      dkimHeaderOpts: Record<string, string | number | null | undefined>;
    };
  };
  export = header;
}

declare module 'mailauth/lib/dkim/body/index.js' {
  const body: {
    dkimBody(
      canonicalization: string,
      algorithm: string,
      maxBodyLength?: number,
    ): { update(chunk: Buffer): void; digest(encoding: 'base64'): string };
  };
  export = body;
}
