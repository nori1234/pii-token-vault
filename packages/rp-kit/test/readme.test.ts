// rp-kit の README のコードの例が、SDK の型と合っていることを確かめる（企業は、README の例を写して使う）。
// README の ```ts のブロックを1つずつ別のファイルにし、リポジトリと同じ設定の tsc で型を確かめる。
// 例の中で、企業が自分で持っている値（秘密鍵、通信の関数、戻りの URL など）は、宣言だけの型定義で補う
// （ブロックの中で同じ名前を宣言したときは、ブロックの宣言が優先される）。

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

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

afterAll(() => {
  rmSync(work, { recursive: true, force: true });
});

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
});
