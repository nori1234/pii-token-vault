// relay の DKIM の署名と ARC の封印が、受信側（mailauth で模擬）で検証できることを確かめる（ADR 0021）。
// 鍵はテストの中で作る（本番は鍵サービスの dkim の鍵）。

import { generateKeyPairSync, sign } from 'node:crypto';
import { authenticate } from 'mailauth';
import { describe, expect, it } from 'vitest';
import { signAndSeal } from '../src/dkim.ts';

const DOMAIN = 'acme.relay.example';
const SELECTOR = 'warifu1';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

function resolver(records: Record<string, string>) {
  return async (name: string, rrtype: string) => {
    const value = records[`${rrtype}:${name.toLowerCase()}`];
    if (value === undefined) {
      const error = new Error('not found') as Error & { code: string };
      error.code = 'ENOTFOUND';
      throw error;
    }
    return [[value]];
  };
}

const DNS = resolver({
  [`TXT:${SELECTOR}._domainkey.${DOMAIN}`]: `v=DKIM1; k=rsa; p=${spki}`,
  [`TXT:_dmarc.${DOMAIN}`]: 'v=DMARC1; p=reject',
});

function message(bodyText: string): Buffer {
  return Buffer.from(
    [
      `From: "Acme" <r-abc@${DOMAIN}>`,
      'To: someone@example.net',
      'Subject: =?UTF-8?B?44GU5LqI57SE?=',
      'Date: Tue, 27 Oct 2026 10:00:00 +0000',
      `Message-ID: <m1@${DOMAIN}>`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      bodyText,
    ].join('\r\n'),
  );
}

async function seal(raw: Buffer): Promise<Buffer> {
  return signAndSeal(raw, {
    domain: DOMAIN,
    selector: SELECTOR,
    sign: async (data) => new Uint8Array(sign('sha256', data, privateKey)),
    now: new Date(),
    authservId: 'relay.example',
    authResults: 'dkim=pass header.d=acme.example',
  });
}

describe('relay の DKIM と ARC', () => {
  it('受信側で DKIM が pass、ARC が pass、DMARC が relay のドメインで pass になる', async () => {
    const sealed = await seal(message('ご予約ありがとうございます。\r\n'));
    const result = await authenticate(sealed, {
      ip: '192.0.2.10',
      helo: 'mx.relay.example',
      mta: 'mx.example.net',
      sender: `bounces@${DOMAIN}`,
      resolver: DNS,
    });
    const dkim = result.dkim.results[0];
    expect(dkim?.status.result).toBe('pass');
    expect(dkim?.signingDomain).toBe(DOMAIN);
    // arc と dmarc は、検証しなかったときに false になる。
    const arc = result.arc || undefined;
    const dmarc = result.dmarc || undefined;
    expect(arc?.status.result).toBe('pass');
    expect(dmarc?.status.result).toBe('pass');
  });

  it('件名と本文のバイト列は変わらない。足すのはヘッダーだけ', async () => {
    const raw = message('本文は\r\nこのまま。\r\n');
    const sealed = await seal(raw);
    expect(sealed.subarray(sealed.length - raw.length).equals(raw)).toBe(true);
    const added = sealed.subarray(0, sealed.length - raw.length).toString();
    expect(
      added
        .split('\r\n')
        .filter((l) => /^[A-Za-z-]+:/.test(l))
        .map((l) => l.split(':')[0]),
    ).toEqual([
      'ARC-Seal',
      'ARC-Message-Signature',
      'ARC-Authentication-Results',
      'DKIM-Signature',
    ]);
  });

  it('署名の後に From を足すと、DKIM が通らない（From を重ねて署名している）', async () => {
    const sealed = await seal(message('x\r\n'));
    const tampered = Buffer.concat([Buffer.from('From: evil@attacker.example\r\n'), sealed]);
    const result = await authenticate(tampered, {
      ip: '192.0.2.10',
      helo: 'mx.relay.example',
      mta: 'mx.example.net',
      sender: `bounces@${DOMAIN}`,
      resolver: DNS,
    });
    expect(result.dkim.results.some((r) => r.status.result === 'pass')).toBe(false);
  });
});
