// 暗号文と文脈（AAD）の結び付き（不変条件3・4、plan 11章 テスト8）。globalSetup の鍵サービスを使う。

import { randomBytes, randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, inject, it } from 'vitest';
import { rawKeysvcCall } from '../setup/keys.ts';

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');
const fromB64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

const u1 = randomUUID();
const u2 = randomUUID();
const address1 = `${b64(randomBytes(9))}@example.com`;

function call(caller: 'idp' | 'relay', op: string, body: unknown) {
  const { socketPath, credentials } = inject('keysvc');
  return rawKeysvcCall({ socketPath, authorization: `Bearer ${credentials[caller]}`, op, body });
}

async function encryptContact(userId: string, plaintext: string): Promise<string> {
  const response = await call('idp', 'encrypt', {
    keyId: 'contact',
    plaintext: b64(plaintext),
    context: { field: 'email', user_id: userId },
  });
  expect(response.status).toBe(200);
  return (JSON.parse(response.body) as { ciphertext: string }).ciphertext;
}

function decryptContact(userId: string, ciphertext: string) {
  return call('relay', 'decrypt', {
    keyId: 'contact',
    ciphertext,
    context: { field: 'email', user_id: userId },
  });
}

let ciphertext1: string;

beforeAll(async () => {
  ciphertext1 = await encryptContact(u1, address1);
});

describe('漏えい：暗号文の文脈への結び付き（plan 11章 テスト8）', () => {
  it('U1 の暗号文を U2 の行に移しても、U2 の文脈では復号できない', async () => {
    // 攻撃者が持っている情報：DB の書き込み（SQL インジェクション ATK-02、運用者 ATK-06）と、U1 と U2 の暗号文
    // 試す経路：U1 の暗号文を U2 の行に移したものとして、relay が U2 の文脈で decrypt する
    // 期待する結果：400 decrypt_failed。U1 のアドレスは返らない
    // plan 11章：テスト8
    const ok = await decryptContact(u1, ciphertext1);
    expect(ok.status).toBe(200);
    const moved = await decryptContact(u2, ciphertext1);
    expect(moved).toMatchObject({ status: 400, body: '{"error":"decrypt_failed"}' });
    expect(moved.body).not.toContain(b64(address1));
  });

  it.each([
    ['本文の1ビット反転', (b: Uint8Array) => flip(b, 6 + 12)],
    ['タグの1ビット反転', (b: Uint8Array) => flip(b, b.byteLength - 1)],
    ['IV の1ビット反転', (b: Uint8Array) => flip(b, 6)],
    ['タグを12バイトに切る', (b: Uint8Array) => b.subarray(0, b.byteLength - 4)],
    ['頭の鍵の番号を relay_queue に', (b: Uint8Array) => set(b, 1, 2)],
    ['鍵の版を変える', (b: Uint8Array) => set(b, 5, 2)],
    ['形式の版を変える', (b: Uint8Array) => set(b, 0, 2)],
  ])('%s をした暗号文は、400 decrypt_failed', async (_label, tamper) => {
    // 攻撃者が持っている情報：DB の書き込み（ATK-02、ATK-06）
    // 試す経路：暗号文を書き換えて、relay に正しい文脈で復号させる
    // 期待する結果：どれも 400 decrypt_failed。平文は返らない
    // plan 11章：テスト8
    const tampered = b64(tamper(fromB64(ciphertext1)));
    const response = await decryptContact(u1, tampered);
    expect(response).toMatchObject({ status: 400, body: '{"error":"decrypt_failed"}' });
  });

  it('配送キューの暗号文を、連絡先として復号させられない', async () => {
    // 攻撃者が持っている情報：DB の書き込み（ATK-02、ATK-06）と、配送キューの暗号文
    // 試す経路：relay_queue の暗号文を、contact の鍵と文脈で復号させる
    // 期待する結果：400 decrypt_failed
    // plan 11章：テスト8
    const queueItemId = randomUUID();
    const sealed = await call('relay', 'encrypt', {
      keyId: 'relay_queue',
      plaintext: b64('queued'),
      context: { queue_item_id: queueItemId },
    });
    const { ciphertext } = JSON.parse(sealed.body) as { ciphertext: string };
    const response = await decryptContact(u1, ciphertext);
    expect(response).toMatchObject({ status: 400, body: '{"error":"decrypt_failed"}' });
  });

  it('同じアドレスを2回暗号化しても、同じ暗号文にならない', async () => {
    // 攻撃者が持っている情報：DB の読み出し（ATK-02）
    // 試す経路：同じアドレスを暗号化した2つの暗号文を比べ、同じアドレスの人を見分けようとする
    // 期待する結果：暗号文が違う。長さは 1+1+4+12+平文+16
    // plan 11章：テスト8
    const again = await encryptContact(u1, address1);
    expect(again).not.toBe(ciphertext1);
    expect(fromB64(again).byteLength).toBe(1 + 1 + 4 + 12 + Buffer.byteLength(address1) + 16);
  });
});

function flip(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy[index] = (copy[index] ?? 0) ^ 1;
  return copy;
}

function set(bytes: Uint8Array, index: number, value: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy[index] = value;
  return copy;
}
