// プロセスの中で鍵サービスを一時的な Unix ソケットに立て、検査の順番とエラーの対応を確かめる。

import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@pii-token-vault/warifu-core/log';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseKeysvcConfig } from '../src/config.ts';
import { type KeysvcServer, startKeysvcServer } from '../src/server.ts';

const USER = '8f14e45f-ceea-467a-9575-0c1f2e3d4b5a';
const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');

let dir: string;
let server: KeysvcServer;
let creds: Record<'idp' | 'relay' | 'company-api', string>;
const logs: string[] = [];

function call(
  op: string,
  body: unknown,
  options: { auth?: string; method?: string; raw?: string } = {},
): Promise<{ status: number; body: string }> {
  const payload = options.raw ?? JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath: server.socketPath,
        path: `/v1/${op}`,
        method: options.method ?? 'POST',
        headers: {
          'content-type': 'application/json',
          ...(options.auth === undefined ? {} : { authorization: `Bearer ${options.auth}` }),
        },
        agent: false,
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          text += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'warifu-ks-test-'));
  const secrets = {
    idp: b64(randomBytes(32)),
    relay: b64(randomBytes(32)),
    'company-api': b64(randomBytes(32)),
  };
  creds = {
    idp: `idp.${secrets.idp}`,
    relay: `relay.${secrets.relay}`,
    'company-api': `company-api.${secrets['company-api']}`,
  };
  server = await startKeysvcServer(
    parseKeysvcConfig(JSON.stringify({ version: 1, socketDir: dir, credentials: secrets })),
    createLogger({ component: 'keysvc', write: (line) => logs.push(line) }),
  );
});

afterAll(async () => {
  await server.close();
  await rm(dir, { recursive: true, force: true });
});

describe('鍵サービスのサーバー', () => {
  it('POST 以外と、知らない形のパスは 404', async () => {
    expect((await call('mac', {}, { method: 'GET', auth: creds.idp })).status).toBe(404);
    expect((await call('Mac', {}, { auth: creds.idp })).status).toBe(404);
    expect((await call('mac?x=1', {}, { auth: creds.idp })).status).toBe(404);
  });

  it('16 KiB を超える本文は 413', async () => {
    const response = await call('mac', undefined, { auth: creds.idp, raw: 'x'.repeat(20_000) });
    expect(response.status).toBe(413);
  });

  it('権限のある操作の、JSON でない本文は 400', async () => {
    const response = await call('mac', undefined, { auth: creds.idp, raw: '{' });
    expect(response).toEqual({ status: 400, body: '{"error":"invalid_request"}' });
  });

  it('権限のない操作は、本文を解析する前に 403', async () => {
    const response = await call('decrypt', undefined, { auth: creds.idp, raw: '{' });
    expect(response).toEqual({ status: 403, body: '{"error":"forbidden"}' });
  });

  it.each([
    ['base64url でない', { purpose: 'alias_lookup', message: 'a+b/' }],
    ['空の入力', { purpose: 'alias_lookup', message: '' }],
    ['余計な項目', { purpose: 'alias_lookup', message: 'YQ', extra: 1 }],
  ])('mac：%s は 400', async (_label, body) => {
    expect((await call('mac', body, { auth: creds.idp })).status).toBe(400);
  });

  it.each([
    ['世代が0', { tenantId: USER, userId: USER, generation: 0 }],
    ['世代が小数', { tenantId: USER, userId: USER, generation: 1.5 }],
    ['世代が範囲の外', { tenantId: USER, userId: USER, generation: 2 ** 31 }],
    ['大文字の UUID', { tenantId: USER.toUpperCase(), userId: USER, generation: 1 }],
  ])('derive_alias：%s は 400', async (_label, body) => {
    expect((await call('derive_alias', body, { auth: creds['company-api'] })).status).toBe(400);
  });

  it('文脈の形が違えば 400', async () => {
    const response = await call(
      'encrypt',
      { keyId: 'contact', plaintext: b64('x'), context: { field: 'phone', user_id: USER } },
      { auth: creds.idp },
    );
    expect(response.status).toBe(400);
  });

  it('暗号化と復号の往復。文脈が違えば decrypt_failed', async () => {
    const encrypted = await call(
      'encrypt',
      { keyId: 'contact', plaintext: b64('payload'), context: { field: 'email', user_id: USER } },
      { auth: creds.idp },
    );
    expect(encrypted.status).toBe(200);
    const { ciphertext } = JSON.parse(encrypted.body) as { ciphertext: string };
    const ok = await call(
      'decrypt',
      { keyId: 'contact', ciphertext, context: { field: 'email', user_id: USER } },
      { auth: creds.relay },
    );
    expect(JSON.parse(ok.body)).toEqual({ plaintext: b64('payload') });
    const other = await call(
      'decrypt',
      {
        keyId: 'contact',
        ciphertext,
        context: { field: 'email', user_id: '8f14e45f-ceea-467a-9575-0c1f2e3d4b5b' },
      },
      { auth: creds.relay },
    );
    expect(other).toEqual({ status: 400, body: '{"error":"decrypt_failed"}' });
  });

  it('derive_alias は16文字、同じ入力なら同じ値、世代が違えば別の値', async () => {
    const derive = async (generation: number) =>
      JSON.parse(
        (
          await call(
            'derive_alias',
            { tenantId: USER, userId: USER, generation },
            { auth: creds.idp },
          )
        ).body,
      ).localPart as string;
    const first = await derive(1);
    expect(first).toMatch(/^[a-z2-7]{16}$/);
    expect(await derive(1)).toBe(first);
    expect(await derive(2)).not.toBe(first);
  });

  it('応答とログに入力の値を入れない', async () => {
    const marker = b64(randomBytes(12));
    await call(
      'mac',
      { purpose: 'alias_lookup', message: marker, extra: marker },
      { auth: creds.idp },
    );
    await call('decrypt', { keyId: marker }, { auth: creds.idp });
    await call(
      marker
        .toLowerCase()
        .replaceAll(/[^a-z_]/g, '_')
        .slice(0, 32),
      {},
      { auth: creds.idp },
    );
    expect(logs.join('')).not.toContain(marker);
    expect(logs.join('')).not.toContain(creds.idp.split('.')[1]);
  });
});
