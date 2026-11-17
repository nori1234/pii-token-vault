// 外へのつなぎの見張り（test/setup/egress.ts）の自己検査（M10 の SSRF の横断。不変条件7、plan 2章「SSRF を防ぐ」）。
// 見張りは、setupFiles（test/setup/egress-guard.ts）で、すべてのテストのファイルに入り、ファイルの最後に、止めた
// つなぎと名前解決が0件であることを確かめる。見張りが働いていなければ、その「0件」に意味がないので、ここで、
// 見張りが入っていること、どの経路のつなぎと名前解決も見つけて止めること、記録に URL のパスやクエリを残さないこと、
// ループバックと Unix ソケットへのつなぎは止めないことを確かめる。

import dgram from 'node:dgram';
import dns, { lookup as namedLookup, resolveMx as namedResolveMx } from 'node:dns';
import { readdirSync, readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import {
  createServer as createHttpServer,
  get as httpGet,
  request as httpRequest,
} from 'node:http';
import { get as httpsGet } from 'node:https';
import { connect as netConnect, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import config from '../../vitest.config.ts';
import {
  egressGuardInstalled,
  isEgressBlocked,
  isLoopbackHost,
  takeEgressAttempts,
} from '../setup/egress.ts';

// 文書用のアドレス（RFC 5737、RFC 3849）と、予約済みの名前（RFC 2606）。見張りが止めるので、実際には送らない。
const TEST_NET = '192.0.2.1';
const TEST_NET6 = '2001:db8::1';
const NAME = 'example.com';

type Outcome = 'blocked' | 'connected' | string;

function socketOutcome(socket: Socket): Promise<Outcome> {
  return new Promise((resolve) => {
    socket.once('error', (error) => {
      resolve(isEgressBlocked(error) ? 'blocked' : String((error as { code?: unknown }).code));
    });
    socket.once('connect', () => {
      socket.destroy();
      resolve('connected');
    });
  });
}

function httpOutcome(get: typeof httpGet, url: string): Promise<Outcome> {
  return new Promise((resolve) => {
    get(url, (res) => {
      res.resume();
      resolve(`status ${res.statusCode}`);
    }).once('error', (error) => {
      resolve(isEgressBlocked(error) ? 'blocked' : String((error as { code?: unknown }).code));
    });
  });
}

const settle = (promise: Promise<unknown>): Promise<Outcome> =>
  promise.then(
    () => 'ok',
    (error: unknown) =>
      isEgressBlocked(error) ? 'blocked' : String((error as { code?: unknown }).code),
  );

describe('M10：外へのつなぎの見張り（SSRF の横断）', () => {
  // 見張りが入っていなければ、外へつなぐ試みをする前に止める（文書用のアドレスと予約済みの名前でも、送らない）。
  beforeEach(() => {
    expect(egressGuardInstalled()).toBe(true);
    takeEgressAttempts();
  });

  it('見張りは、vitest の setupFiles ですべてのテストのファイルに入り、E2E のファイルも自分で入れている', () => {
    // 攻撃者が持っている情報：なし（見張りの配線の確かめ。外すと、ほかのテストの「0件」の検査が消えるため）
    // 試す経路：vitest.config.ts の setupFiles を読み、このファイルで見張りが入っているかを見る。Playwright の
    //           E2E のファイル（setupFiles がない）を読み、見張りを入れて0件を確かめているかを見る
    // 期待する結果：setupFiles に test/setup/egress-guard.ts があり、このファイルの中で見張りが入っている。
    //               E2E のファイルは、どれも beforeAll で見張りを入れ、afterAll で0件を確かめている
    // plan 11章：テスト11（M10 の SSRF の横断）
    expect(config.test?.setupFiles).toContain('test/setup/egress-guard.ts');
    expect(egressGuardInstalled()).toBe(true);
    const here = dirname(fileURLToPath(import.meta.url));
    const e2e = readdirSync(here).filter((file) => file.endsWith('.e2e.ts'));
    expect(e2e.length).toBeGreaterThan(0);
    for (const file of e2e) {
      const source = readFileSync(join(here, file), 'utf8');
      expect([file, source.includes('installEgressGuard();')]).toEqual([file, true]);
      expect([file, source.includes('expectNoEgress();')]).toEqual([file, true]);
    }
  });

  it('ループバックと Unix ソケットのほかへの TCP と TLS の接続は、つながずに止めて、宛先だけを記録する', async () => {
    // 攻撃者が持っている情報：なし（見張りの自己検査）
    // 試す経路：net、tls、http、https、fetch で、文書用のアドレスと予約済みの名前へつなぐ。URL にパスとクエリを付ける
    // 期待する結果：どれも止まり（EGRESS_BLOCKED_IN_TESTS）、宛先（ホストとポート）と入口だけが残る。名前は引かない。
    //               URL のパスとクエリは記録に残らない
    // plan 11章：テスト11（M10 の SSRF の横断）
    expect(await socketOutcome(netConnect(80, TEST_NET))).toBe('blocked');
    expect(await socketOutcome(netConnect({ host: NAME, port: 25 }))).toBe('blocked');
    expect(await socketOutcome(netConnect({ host: TEST_NET6, port: 443 }))).toBe('blocked');
    expect(await socketOutcome(tlsConnect({ host: TEST_NET, port: 443, servername: NAME }))).toBe(
      'blocked',
    );
    expect(await httpOutcome(httpGet, `http://${TEST_NET}/secret-path?token=t0ken`)).toBe(
      'blocked',
    );
    expect(await httpOutcome(httpsGet, `https://${NAME}/secret-path?token=t0ken`)).toBe('blocked');
    expect(await settle(fetch(`http://${TEST_NET}/secret-path?token=t0ken`))).toBe('blocked');
    expect(await settle(fetch(`https://${NAME}/secret-path?token=t0ken`))).toBe('blocked');
    const attempts = takeEgressAttempts();
    expect(attempts.map(({ kind, destination, via }) => [kind, destination, via])).toEqual([
      ['tcp', `${TEST_NET}:80`, 'net.Socket.connect'],
      ['tcp', `${NAME}:25`, 'net.Socket.connect'],
      ['tcp', `${TEST_NET6}:443`, 'net.Socket.connect'],
      ['tcp', `${TEST_NET}:443`, 'net.Socket.connect'],
      ['tcp', `${TEST_NET}:80`, 'net.Socket.connect'],
      ['tcp', `${NAME}:443`, 'net.Socket.connect'],
      ['tcp', `${TEST_NET}:80`, 'net.Socket.connect'],
      ['tcp', `${NAME}:443`, 'net.Socket.connect'],
    ]);
    expect(attempts.every((a) => a.origin.length > 0)).toBe(true);
    expect(JSON.stringify(attempts)).not.toMatch(/secret-path|token|t0ken/);
  });

  it('注入したリゾルバを通さない名前解決は、ループバックの名前でも止めて、名前だけを記録する', async () => {
    // 攻撃者が持っている情報：なし（見張りの自己検査。割符の名前解決は、送信サービスの注入したリゾルバだけを通す）
    // 試す経路：dns.promises、コールバックの dns（名前付きの import を含む）、Resolver、dns.lookup で名前を引く
    // 期待する結果：c-ares の問い合わせは ECONNREFUSED で、localhost も含めて止まる。dns.lookup は、localhost の
    //               ほかを止める。どれも、名前と入口が記録に残る
    // plan 11章：テスト11（M10 の SSRF の横断）
    expect(await settle(dns.promises.resolveTxt(NAME))).toBe('ECONNREFUSED');
    expect(
      await settle(
        new Promise((resolve, reject) => {
          namedResolveMx(NAME, (error, records) => (error ? reject(error) : resolve(records)));
        }),
      ),
    ).toBe('ECONNREFUSED');
    expect(await settle(new dns.promises.Resolver().resolve4(NAME))).toBe('ECONNREFUSED');
    expect(await settle(dns.promises.resolve4('localhost'))).toBe('ECONNREFUSED');
    expect(await settle(dns.promises.reverse(TEST_NET))).toBe('ECONNREFUSED');
    expect(
      await settle(
        new Promise((resolve, reject) => {
          dns.lookup(NAME, (error, address) => (error ? reject(error) : resolve(address)));
        }),
      ),
    ).toBe('blocked');
    expect(
      await settle(
        new Promise((resolve, reject) => {
          namedLookup(NAME, (error, address) => (error ? reject(error) : resolve(address)));
        }),
      ),
    ).toBe('blocked');
    expect(await settle(dns.promises.lookup(NAME))).toBe('blocked');
    expect(await settle(dns.promises.lookup('localhost'))).toBe('ok');
    expect(
      takeEgressAttempts().map(({ kind, destination, via }) => [kind, destination, via]),
    ).toEqual([
      ['dns', NAME, 'dns.queryTxt'],
      ['dns', NAME, 'dns.queryMx'],
      ['dns', NAME, 'dns.queryA'],
      ['dns', 'localhost', 'dns.queryA'],
      ['dns', TEST_NET, 'dns.getHostByAddr'],
      ['dns', NAME, 'dns.lookup'],
      ['dns', NAME, 'dns.lookup'],
      ['dns', NAME, 'dns.promises.lookup'],
    ]);
  });

  it('ループバックと Unix ソケットのほかへの UDP の送信は、送らずに止める', () => {
    // 攻撃者が持っている情報：なし（見張りの自己検査）
    // 試す経路：dgram で、文書用のアドレスの53番に送る。connect してから送る
    // 期待する結果：どちらも止まり、宛先と入口が記録に残る
    // plan 11章：テスト11（M10 の SSRF の横断）
    const socket = dgram.createSocket('udp4');
    try {
      expect(() => socket.send('x', 53, TEST_NET)).toThrow(/外へつながない/);
      expect(() => socket.connect(53, TEST_NET)).toThrow(/外へつながない/);
    } finally {
      socket.close();
    }
    expect(
      takeEgressAttempts().map(({ kind, destination, via }) => [kind, destination, via]),
    ).toEqual([
      ['udp', `${TEST_NET}:53`, 'dgram.send'],
      ['udp', `${TEST_NET}:53`, 'dgram.connect'],
    ]);
  });

  it('ループバック（localhost、127.0.0.1）と Unix ソケットへのつなぎは止めず、記録もしない', async () => {
    // 攻撃者が持っている情報：なし（見張りの自己検査。テストの中で立てたサーバーと、割符の内部の Unix ソケットの
    //                         通信は、そのまま通ることを確かめる）
    // 試す経路：127.0.0.1 で待ち受ける HTTP のサーバーに、localhost と 127.0.0.1 の名前で、fetch と http でつなぐ。
    //           Unix ソケットで待ち受けるサーバーに、socketPath でつなぐ
    // 期待する結果：どれも 200 で、記録は0件
    // plan 11章：テスト11（M10 の SSRF の横断）
    const server = createHttpServer((_req, res) => res.end('ok'));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const dir = await mkdtemp(join(tmpdir(), 'warifu-egress-'));
    const unix = createHttpServer((_req, res) => res.end('ok'));
    const socketPath = join(dir, 'guard.sock');
    await new Promise<void>((resolve) => unix.listen(socketPath, resolve));
    try {
      const { port } = server.address() as { port: number };
      expect((await fetch(`http://localhost:${port}/`)).status).toBe(200);
      expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(200);
      expect(await httpOutcome(httpGet, `http://127.0.0.1:${port}/`)).toBe('status 200');
      const viaSocket = await new Promise<number | undefined>((resolve, reject) => {
        httpRequest({ socketPath, path: '/' }, (res) => {
          res.resume();
          resolve(res.statusCode);
        })
          .once('error', reject)
          .end();
      });
      expect(viaSocket).toBe(200);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await new Promise<void>((resolve) => unix.close(() => resolve()));
      await rm(dir, { recursive: true, force: true });
    }
    expect(takeEgressAttempts()).toEqual([]);
    for (const host of [
      'localhost',
      '127.0.0.1',
      '127.1.2.3',
      '::1',
      '[::1]',
      '::ffff:127.0.0.1',
    ]) {
      expect([host, isLoopbackHost(host)]).toEqual([host, true]);
    }
    for (const host of ['0.0.0.0', '10.0.0.1', '169.254.169.254', '::', 'fd00::1', 'x.localhost']) {
      expect([host, isLoopbackHost(host)]).toEqual([host, false]);
    }
  });
});
