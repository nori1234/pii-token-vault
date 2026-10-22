// テストの中で立てた Unix ソケットの HTTP サーバーで、udsPost の往復、時間切れ、応答の上限、ソケットの検査を確かめる。

import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type RequestListener, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { UdsError, udsPost } from '../src/internal/uds-client.ts';

let base: string;
let server: Server;
let socketPath: string;

function listen(path: string, handler: RequestListener): Promise<Server> {
  const s = createServer(handler);
  return new Promise((resolve) => s.listen(path, () => resolve(s)));
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error instanceof UdsError ? error.code : 'other';
  }
}

const post = (overrides: Partial<Parameters<typeof udsPost>[0]> = {}) =>
  udsPost({
    socketPath,
    path: '/v1/echo',
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode('{"x":1}'),
    timeoutMs: 1000,
    maxResponseBytes: 1024,
    ...overrides,
  });

beforeAll(async () => {
  base = await mkdtemp(join(tmpdir(), 'warifu-uds-'));
  await chmod(base, 0o700);
  socketPath = join(base, 'keysvc.sock');
  server = await listen(socketPath, (req, res) => {
    if (req.url === '/v1/slow') return; // 応答しない
    if (req.url === '/v1/big') {
      res.end('x'.repeat(4096));
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(Buffer.concat(chunks));
    });
  });
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await rm(base, { recursive: true, force: true });
});

describe('udsPost', () => {
  it('往復する', async () => {
    const response = await post();
    expect(response.status).toBe(201);
    expect(new TextDecoder().decode(response.body)).toBe('{"x":1}');
  });

  it('時間切れ', async () => {
    expect(await codeOf(post({ path: '/v1/slow', timeoutMs: 200 }))).toBe('timeout');
  });

  it('応答の上限を超えたら too_large', async () => {
    expect(await codeOf(post({ path: '/v1/big' }))).toBe('too_large');
  });

  it.each([
    ['クエリ付き', '/v1/echo?x=1'],
    ['版のないパス', '/echo'],
    ['大文字', '/v1/Echo'],
  ])('パスの形が違う（%s）', async (_label, path) => {
    expect(await codeOf(post({ path }))).toBe('invalid_path');
  });

  it.each([
    ['相対パス', () => 'keysvc.sock'],
    ['.. を含む', () => `${base}/../${base.split('/').pop()}/keysvc.sock`],
    ['名前の一覧の外', () => join(base, 'docker.sock')],
  ])('ソケットの検査に通らない（%s）', async (_label, path) => {
    expect(await codeOf(post({ socketPath: path() }))).toBe('invalid_socket');
  });

  it('group と other の権限があるディレクトリのソケットは使わない', async () => {
    const loose = join(base, 'loose');
    await mkdir(loose, { mode: 0o755 });
    await chmod(loose, 0o755);
    const s = await listen(join(loose, 'keysvc.sock'), (_req, res) => res.end('{}'));
    try {
      expect(await codeOf(post({ socketPath: join(loose, 'keysvc.sock') }))).toBe('invalid_socket');
    } finally {
      await new Promise((resolve) => s.close(resolve));
    }
  });

  it('ソケットでないファイルは使わない', async () => {
    const dir = join(base, 'file');
    await mkdir(dir, { mode: 0o700 });
    await writeFile(join(dir, 'keysvc.sock'), 'not a socket');
    expect(await codeOf(post({ socketPath: join(dir, 'keysvc.sock') }))).toBe('invalid_socket');
  });

  it('待ち受けていないソケットは unavailable', async () => {
    const dir = join(base, 'gone');
    await mkdir(dir, { mode: 0o700 });
    const s = await listen(join(dir, 'keysvc.sock'), (_req, res) => res.end('{}'));
    const path = join(dir, 'keysvc.sock');
    expect((await post({ socketPath: path })).status).toBe(200);
    // close() はソケットのファイルを消すので、同じパスに普通のファイルを置いて「つながらない」を作る。
    await new Promise((resolve) => s.close(resolve));
    await writeFile(path, '');
    expect(await codeOf(post({ socketPath: path }))).toBe('unavailable');
  });
});
