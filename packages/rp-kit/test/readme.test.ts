// rp-kit の README のコードの例が、SDK の型と合っていることを確かめる（企業は、README の例を写して使う）。
// README の ```ts のブロックを1つずつ別のファイルにし、リポジトリと同じ設定の tsc で型を確かめる。
// 通信の関数の例は、型だけでは分からない動き（大きな応答を、読んでいる途中で止めること）も、そのまま動かして確かめる。
// 例の中で、企業が自分で持っている値（秘密鍵、通信の関数、戻りの URL など）は、宣言だけの型定義で補う
// （ブロックの中で同じ名前を宣言したときは、ブロックの宣言が優先される）。

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { guardedSend, type HttpRequest, type Send } from '../src/transport.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const README = readFileSync(join(ROOT, 'packages', 'rp-kit', 'README.md'), 'utf8');

/** 企業が自分で持っている値（例の中で、宣言せずに使っているもの）。 */
const AMBIENT = `
declare const privateKey: import('jose').JWK;
declare const send: import('@pii-token-vault/rp-kit').Send;
declare const warifu: import('@pii-token-vault/rp-kit').WarifuClient;
declare const callbackUrl: string;
declare const requestId: string;
declare const session: { readonly sub: string };
declare const fixedContent: import('@pii-token-vault/rp-kit').PayoutDestinationContent;
declare const body: string;
declare const clientId: string;
declare const redirectUri: string;
declare function signInOnTestRp(
  persona: import('@pii-token-vault/rp-kit/kit').MockPersona,
  complete: (authorizationUrl: string) => string,
): Promise<string>;
`;

/** README の ```ts のブロック（順番どおり）。 */
function codeBlocksOf(markdown: string): string[] {
  return [...markdown.matchAll(/^```ts\n([\s\S]*?)^```$/gm)].map((match) => match[1] ?? '');
}

// 依存（@pii-token-vault/rp-kit と jose）を、リポジトリの node_modules から解決できるように、その中に作る。
const work = mkdtempSync(join(ROOT, 'node_modules', '.rp-kit-readme-test-'));
// 動かして確かめる例を置く場所（node_modules の外。Vitest が .ts のまま読み込めるように）。
const runDir = mkdtempSync(join(tmpdir(), 'rp-kit-readme-run-'));

afterAll(() => {
  rmSync(work, { recursive: true, force: true });
  rmSync(runDir, { recursive: true, force: true });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const ORIGIN = 'https://idp.warifu.example';
const REQUEST: HttpRequest = {
  method: 'GET',
  url: `${ORIGIN}/jwks`,
  headers: { accept: 'application/json' },
};
const KIB = 1024;

/** README の最初のブロック（通信の関数）を、書いてあるとおりに読み込む。 */
async function readmeSend(): Promise<Send> {
  const block = codeBlocksOf(README)[0] ?? '';
  expect(block).toContain('const send: Send');
  const path = join(runDir, 'send.ts');
  writeFileSync(path, `${block}\nexport { send };\n`);
  return ((await import(pathToFileURL(path).href)) as { send: Send }).send;
}

/** size バイトの本文を、読まれた分だけ chunk バイトずつ出す模擬の応答（出したバイト数と、取消を記録する）。 */
function streamedResponse(size: number, chunk: number) {
  const source = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (source.pulled >= size) {
          controller.close();
          return;
        }
        const length = Math.min(chunk, size - source.pulled);
        source.pulled += length;
        controller.enqueue(new Uint8Array(length).fill(0x61));
      },
      cancel() {
        source.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const response = new Response(stream, {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  return { response, source };
}

describe('rp-kit の README のコードの例', () => {
  it('```ts のブロックを、README から取り出せる', () => {
    expect(codeBlocksOf('a\n```ts\nconst x = 1;\n```\n```\nnot ts\n```\n')).toEqual([
      'const x = 1;\n',
    ]);
    // 通信の関数、ログイン、高リスクの操作、SET の受け口、適合テストキットの5つ。
    expect(codeBlocksOf(README)).toHaveLength(5);
  });

  it('どのブロックも、リポジトリと同じ設定の tsc で型が通る', () => {
    const files = codeBlocksOf(README).map((block, index) => {
      const path = join(work, `block-${index + 1}.ts`);
      // モジュールとして扱う（ブロックの宣言を、ほかのブロックと分ける）。
      writeFileSync(path, `${block}\nexport {};\n`);
      return path;
    });
    const ambient = join(work, 'ambient.d.ts');
    writeFileSync(ambient, AMBIENT);
    const config = join(work, 'tsconfig.json');
    writeFileSync(
      config,
      JSON.stringify({ extends: join(ROOT, 'tsconfig.json'), files: [ambient, ...files] }),
    );
    let output = '';
    try {
      execFileSync(
        process.execPath,
        [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', config],
        { cwd: ROOT, encoding: 'utf8' },
      );
    } catch (error) {
      output = String((error as { stdout?: unknown }).stdout ?? error);
    }
    expect(output).toBe('');
  }, 120_000);

  it('通信の関数の例は、大きな応答を、上限（256 KiB）を超えたところで読むのをやめる', async () => {
    // 割符のサーバーや、間のプロキシが、1 MiB の応答を返したときを模す（オーナーのレビュー、#64）。
    // response.text() で全部を読む例では、SDK が大きすぎると断る前に、1 MiB を全部読み込んでいた。
    const send = await readmeSend();
    const { response, source } = streamedResponse(1024 * KIB, 64 * KIB);
    vi.stubGlobal('fetch', async () => response);
    // SDK の通信の守り（guardedSend）を通すと、unavailable になる。
    await expect(guardedSend(send, [ORIGIN])(REQUEST)).rejects.toMatchObject({
      code: 'unavailable',
    });
    // 上限を超えた最初の塊で読むのをやめ、残りは取り消す（1 MiB の全体は読まない）。
    expect(source.cancelled).toBe(true);
    expect(source.pulled).toBe(256 * KIB + 64 * KIB);
  });

  it('通信の関数の例は、上限までの応答を、そのまま返し、リダイレクトに従わない', async () => {
    const send = await readmeSend();
    const exact = streamedResponse(256 * KIB, 64 * KIB);
    const calls: RequestInit[] = [];
    vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
      calls.push(init);
      return exact.response;
    });
    const result = await send(REQUEST);
    expect(result.status).toBe(200);
    expect(result.headers).toEqual({ 'content-type': 'application/json' });
    expect(result.body).toBe('a'.repeat(256 * KIB));
    expect(exact.source.cancelled).toBe(false);
    expect(calls.map((init) => init.redirect)).toEqual(['manual']);

    vi.stubGlobal('fetch', async () => new Response(null, { status: 204 }));
    expect(await send(REQUEST)).toEqual({
      status: 204,
      headers: { 'content-type': '' },
      body: '',
    });
  });
});
