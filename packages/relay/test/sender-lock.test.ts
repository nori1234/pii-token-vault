// 送信元ロックの方式の検査（不変条件9、ADR 0021）。受け付けるのは rsa-sha256（2048 ビット以上）と ed25519-sha256 だけ。
// relay を立てずに verifySenderLock を直接呼ぶ（SMTP を通した検査は test/leak/t05-relay-sender-lock）。

import { generateKeyPairSync, type KeyObject, randomUUID } from 'node:crypto';
import { parseTenantId } from '@pii-token-vault/warifu-core';
import { dkimSign } from 'mailauth/lib/dkim/sign.js';
import { describe, expect, it } from 'vitest';
import { parseRelayConfig, type RelayTenant } from '../src/config.ts';
import { parseMessage } from '../src/mime.ts';
import { verifySenderLock } from '../src/sender-lock.ts';

const SENDER = 'mail.company.example';
const SELECTOR = 's1';

function tenantWith(key: KeyObject): RelayTenant {
  return {
    tenantId: parseTenantId(randomUUID()),
    displayName: 'テスト企業',
    relayDomain: 'acme.relay.example',
    sender: {
      domain: SENDER,
      selector: SELECTOR,
      publicKey: key.export({ type: 'spki', format: 'der' }).toString('base64'),
    },
  };
}

async function signed(key: KeyObject, algorithm?: string): Promise<Buffer> {
  const raw = Buffer.from(
    [
      `From: <info@${SENDER}>`,
      'To: <aaaaaaaaaaaaaaaa@acme.relay.example>',
      'Subject: test',
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${randomUUID()}@${SENDER}>`,
      '',
      'body',
      '',
    ].join('\r\n'),
  );
  const result = await dkimSign(raw, {
    canonicalization: 'relaxed/relaxed',
    signTime: new Date(),
    signatureData: [
      {
        signingDomain: SENDER,
        selector: SELECTOR,
        privateKey: key.export({ type: 'pkcs8', format: 'pem' }).toString(),
        headerList: 'From:From:To:To:Subject:Subject:Date:Message-ID',
        ...(algorithm === undefined ? {} : { algorithm }),
      },
    ],
  });
  return Buffer.concat([Buffer.from(result.signatures), raw]);
}

async function verify(key: KeyObject, publicKeyOf: KeyObject, algorithm?: string) {
  const raw = await signed(key, algorithm);
  return verifySenderLock(raw, parseMessage(raw), tenantWith(publicKeyOf), new Date());
}

describe('送信元ロックの方式（不変条件9）', () => {
  it('rsa-sha256（2048 ビット）と ed25519-sha256 を受け付ける', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect((await verify(rsa.privateKey, rsa.publicKey)).ok).toBe(true);
    const ed = generateKeyPairSync('ed25519');
    const result = await verify(ed.privateKey, ed.publicKey);
    expect(result.ok).toBe(true);
  });

  it('rsa-sha1 と、2048 ビットに足りない RSA の鍵は受け付けない', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(await verify(rsa.privateKey, rsa.publicKey, 'rsa-sha1')).toEqual({
      ok: false,
      reason: 'no_valid_signature',
    });
    const short = generateKeyPairSync('rsa', { modulusLength: 1024 });
    expect(await verify(short.privateKey, short.publicKey)).toEqual({
      ok: false,
      reason: 'no_valid_signature',
    });
  });

  it('設定は、2048 ビットに足りない RSA の公開鍵を、起動の時点で拒否する', () => {
    const short = generateKeyPairSync('rsa', { modulusLength: 1024 });
    expect(() =>
      parseRelayConfig({
        tenants: [tenantWith(short.publicKey)],
        selector: 'warifu1',
        authservId: 'mx.relay.example',
        noticeDomain: 'notice.relay.example',
      }),
    ).toThrow('公開鍵の長さが足りない');
  });

  it('設定は、RSA と Ed25519 のほかの種類の公開鍵（RSA-PSS、EC）を、起動の時点で拒否する（ADR 0022）', () => {
    for (const [type, options] of [
      ['rsa-pss', { modulusLength: 2048 }],
      ['ec', { namedCurve: 'P-256' }],
      ['ed448', {}],
    ] as const) {
      const { publicKey } = generateKeyPairSync(type as 'rsa-pss', options as never) as unknown as {
        publicKey: KeyObject;
      };
      expect(() =>
        parseRelayConfig({
          tenants: [tenantWith(publicKey)],
          selector: 'warifu1',
          authservId: 'mx.relay.example',
          noticeDomain: 'notice.relay.example',
        }),
      ).toThrow(/公開鍵の(長さが足りない|種類が違う)/);
    }
    for (const key of [
      generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey,
      generateKeyPairSync('ed25519').publicKey,
    ]) {
      expect(() =>
        parseRelayConfig({
          tenants: [tenantWith(key)],
          selector: 'warifu1',
          authservId: 'mx.relay.example',
          noticeDomain: 'notice.relay.example',
        }),
      ).not.toThrow();
    }
  });

  it('設定は、ヘッダーに差し込める企業名を拒否する', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    for (const displayName of ['A\r\nBcc: x@example.com', 'A" <x@example.com>', 'A‮B', '']) {
      expect(() =>
        parseRelayConfig({
          tenants: [{ ...tenantWith(rsa.publicKey), displayName }],
          selector: 'warifu1',
          authservId: 'mx.relay.example',
          noticeDomain: 'notice.relay.example',
        }),
      ).toThrow('企業名の形が違う');
    }
  });
});
