// demo-rp の通信の1ファイル（transport.ts）の単体検査（ADR 0029 の O-109）。
// 設定したオリジンにだけ送り、リダイレクトに従わず、利用者などが渡した URL にはつながないことを確かめる。

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTransport, TransportError } from '../src/transport.ts';

let allowed: Server;
let other: Server;
let allowedOrigin = '';
let otherOrigin = '';
const hits: string[] = [];

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, 'localhost', () => {
      resolve(`http://localhost:${(server.address() as AddressInfo).port}`);
    });
  });
}

beforeAll(async () => {
  other = createServer((req, res) => {
    hits.push(`other ${req.url}`);
    res.end('secret');
  });
  otherOrigin = await listen(other);
  allowed = createServer((req, res) => {
    hits.push(`allowed ${req.url}`);
    if (req.url === '/redirect') {
      res.writeHead(302, { location: `${otherOrigin}/internal` });
      res.end();
      return;
    }
    if (req.url === '/huge') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('x'.repeat(256 * 1024 + 1));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  allowedOrigin = await listen(allowed);
});

afterAll(async () => {
  await new Promise((resolve) => allowed.close(resolve));
  await new Promise((resolve) => other.close(resolve));
});

describe('demo-rp の通信（ADR 0029 の O-109）', () => {
  it('設定したオリジンにだけ送り、リダイレクトの先には進まない', async () => {
    // 攻撃者が持っている情報：demo-rp に渡る URL を操れる立場（応答の Location や、画面からの値）
    // 試す経路：設定していないオリジン、利用者情報付きの URL、リダイレクトを返す宛先に送らせる
    // 期待する結果：設定していない宛先には接続しない（TransportError）。302 は、そのまま 302 として返し、先には進まない
    // plan 11章：テスト11（企業の側を SSRF の入り口にしない）
    const send = createTransport([allowedOrigin]);
    const ok = await send({ method: 'GET', url: `${allowedOrigin}/jwks`, headers: {} });
    expect([ok.status, ok.body]).toEqual([200, '{"ok":true}']);
    await expect(
      send({ method: 'GET', url: `${otherOrigin}/internal`, headers: {} }),
    ).rejects.toThrow(TransportError);
    await expect(
      send({
        method: 'GET',
        url: allowedOrigin.replace('http://', 'http://user:pw@'),
        headers: {},
      }),
    ).rejects.toThrow(TransportError);
    await expect(
      send({ method: 'GET', url: 'http://169.254.169.254/latest/meta-data', headers: {} }),
    ).rejects.toThrow(TransportError);
    const redirected = await send({ method: 'GET', url: `${allowedOrigin}/redirect`, headers: {} });
    expect(redirected.status).toBe(302);
    // 上限（256 KiB）を超える応答は、読み切らずに失敗にする。
    await expect(
      send({ method: 'GET', url: `${allowedOrigin}/huge`, headers: {} }),
    ).rejects.toThrow(TransportError);
    expect(hits).toEqual(['allowed /jwks', 'allowed /redirect', 'allowed /huge']);
    expect(() => createTransport(['https://idp.example/path'])).toThrow(TransportError);
    expect(() => createTransport(['ftp://idp.example'])).toThrow(TransportError);
    // http（平文）は、ループバックだけ。
    expect(() => createTransport(['http://idp.example'])).toThrow(TransportError);
  });
});
