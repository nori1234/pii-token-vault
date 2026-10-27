// 偽の鍵サービスで、ステータスと本文から KeysvcError への対応と、例外に本文が入らないことを確かめる。

import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeysvcError } from '../src/keys/errors.ts';
import { createIdpKeyClient } from '../src/keys/idp.ts';
import { createRelayKeyClient } from '../src/keys/relay.ts';
import { KeysvcCredentialError } from '../src/keys/transport.ts';

const MARKER = `mk${randomBytes(12).toString('hex')}`;
let base: string;
let server: Server;
let socketPath: string;
let reply: { status: number; body: string } = { status: 200, body: '{}' };

const credential = (service: string) => `${service}.${randomBytes(32).toString('base64url')}`;

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    expect(String(error)).not.toContain(MARKER);
    expect(JSON.stringify(error)).not.toContain(MARKER);
    return error instanceof KeysvcError ? error.code : 'other';
  }
}

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), 'warifu-kt-'));
  await chmod(base, 0o700);
  socketPath = join(base, 'keysvc.sock');
  server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(reply.status, { 'content-type': 'application/json' });
      res.end(reply.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, () => resolve()));
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await rm(base, { recursive: true, force: true });
});

describe('鍵サービスのクライアントのエラー', () => {
  const idp = () => createIdpKeyClient({ socketPath, credential: credential('idp') });
  const mac = () => idp().mac('alias_lookup', new Uint8Array([1]));

  it.each([
    [403, `{"error":"forbidden","x":"${MARKER}"}`, 'forbidden'],
    [400, '{"error":"decrypt_failed"}', 'decrypt_failed'],
    [400, `{"error":"invalid_request","x":"${MARKER}"}`, 'invalid_request'],
    [500, `{"error":"${MARKER}"}`, 'internal'],
    [418, MARKER, 'unavailable'],
    [200, `not json ${MARKER}`, 'internal'],
    [200, `{"mac":"${MARKER}"}`, 'internal'],
  ])('%i %s → %s', async (status, body, code) => {
    reply = { status, body };
    expect(await codeOf(mac())).toBe(code);
  });

  it('型にない用途は、呼ぶ前に forbidden', async () => {
    reply = { status: 200, body: '{}' };
    expect(await codeOf(idp().mac('message_id' as never, new Uint8Array([1])))).toBe('forbidden');
  });

  it('つながらなければ unavailable', async () => {
    const client = createIdpKeyClient({
      socketPath: join(base, 'missing', 'keysvc.sock'),
      credential: credential('idp'),
    });
    expect(await codeOf(client.mac('alias_lookup', new Uint8Array([1])))).toBe('unavailable');
  });

  it('資格情報のサービスが違えば、工場関数が失敗する', () => {
    expect(() => createIdpKeyClient({ socketPath, credential: credential('relay') })).toThrow(
      KeysvcCredentialError,
    );
    expect(() => createRelayKeyClient({ socketPath, credential: 'relay.short' })).toThrow(
      KeysvcCredentialError,
    );
  });
});
