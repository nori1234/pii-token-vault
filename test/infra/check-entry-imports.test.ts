// scripts/check-entry-imports.ts の検査が、Node が実際に読み込むファイルを、書き方によらずたどることを確かめる。
// 正規表現や、tsc と字句解析の組み合わせでは見逃していた書き方も含める。

import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { findViolations } from '../../scripts/check-entry-imports.ts';

let root: string;

// ルートの package.json は、指定がなければ ES モジュールにする（リポジトリと同じ）。
function write(files: Record<string, string>) {
  root = mkdtempSync(join(tmpdir(), 'entry-imports-test-'));
  const all = { 'package.json': JSON.stringify({ type: 'module' }), ...files };
  for (const [path, text] of Object.entries(all)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const HELPER = { 'packages/x/src/helper.test.ts': 'export const a = 1;\n' };

describe('本体のコードから、lint の制限を外したファイルへの import', () => {
  it.each([
    ['名前付きの import', "import { a } from './helper.test.ts';\nexport { a };\n"],
    ['副作用だけの import', "import './helper.test.ts';\n"],
    ['改行をはさむ import', "import { a } from\n  './helper.test.ts';\nexport { a };\n"],
    ['改行をはさむ動的な import', "await import(\n  './helper.test.ts'\n);\n"],
    ['export … from', "export * from './helper.test.ts';\n"],
    // Node は、URL のクエリとフラグメントを取り除き、%XX を元の文字に直して読み込む。
    ['クエリを付けた import', "import './helper.test.ts?x';\n"],
    ['クエリを付けた動的な import', "await import('./helper.test.ts?x');\n"],
    ['フラグメントを付けた import', "import './helper.test.ts#x';\n"],
    ['%2E で書いた import', "import './helper%2Etest.ts';\n"],
    [
      '型だけを取り除いた後に残る import',
      "import { type A } from './helper.test.ts';\nexport type { A };\n",
    ],
  ])('%s を拒否する', (_name, text) => {
    const violations = findViolations(write({ ...HELPER, 'packages/x/src/a.ts': text }));
    expect(violations).toEqual([
      'packages/x/src/helper.test.ts：本体のコードから import されている',
    ]);
  });

  it('間接の import と、scripts/・test/・ルートの *.config.ts も拒否する', () => {
    const violations = findViolations(
      write({
        'packages/x/src/a.ts': "import './b.ts';\n",
        'packages/x/src/b.ts':
          "import '../../../scripts/s.ts';\nimport '../../../test/setup/t.ts';\nimport '../../../vitest.config.ts';\n",
        'scripts/s.ts': 'export {};\n',
        'test/setup/t.ts': 'export {};\n',
        'vitest.config.ts': 'export {};\n',
      }),
    );
    expect(violations.sort()).toEqual([
      'scripts/s.ts：本体のコードから import されている',
      'test/setup/t.ts：本体のコードから import されている',
      'vitest.config.ts：本体のコードから import されている',
    ]);
  });

  it('package.json の imports で、テストに向けた名前も拒否する', () => {
    const violations = findViolations(
      write({
        ...HELPER,
        'packages/x/package.json': JSON.stringify({
          name: 'x',
          type: 'module',
          imports: { '#helper': './src/helper.test.ts' },
        }),
        'packages/x/src/a.ts': "import '#helper';\n",
      }),
    );
    expect(violations).toEqual([
      'packages/x/src/helper.test.ts：本体のコードから import されている',
    ]);
  });

  it('ワークスペースのパッケージの exports で、テストに向けた名前も拒否する', () => {
    write({
      'packages/y/package.json': JSON.stringify({
        name: '@t/y',
        type: 'module',
        exports: './src/helper.test.ts',
      }),
      'packages/y/src/helper.test.ts': 'export {};\n',
      'packages/x/src/a.ts': "import '@t/y';\n",
    });
    // npm のワークスペースと同じく、node_modules の下にリンクを置く。Node は実体のパスに直す。
    mkdirSync(join(root, 'node_modules/@t'), { recursive: true });
    symlinkSync(join(root, 'packages/y'), join(root, 'node_modules/@t/y'));
    expect(findViolations(root)).toEqual([
      'packages/y/src/helper.test.ts：本体のコードから import されている',
    ]);
  });

  it.each([
    ['data: の URL', "await import('data:text/javascript,export default 1');\n", 'data:'],
    ['https: の URL', "import 'https://example.com/a.js';\n", 'https:'],
  ])('%s を読み込む import を拒否する', (_name, text) => {
    const violations = findViolations(write({ 'packages/x/src/a.ts': text }));
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatch(
      /^packages\/x\/src\/a\.ts：ファイル以外（data: や https: など）を読み込む import/,
    );
  });

  it.each([
    ['存在しないファイル', "import './missing.ts';\n", './missing.ts'],
    ['存在しないパッケージ', "import 'no-such-package';\n", 'no-such-package'],
  ])('%s を読み込む import を拒否する', (_name, text, specifier) => {
    const violations = findViolations(write({ 'packages/x/src/a.ts': text }));
    expect(violations).toEqual([
      `packages/x/src/a.ts：読み込み先を解決できない import（${specifier}）`,
    ]);
  });

  const NON_LITERAL = '引用符で囲んだ文字列リテラル1つ以外を渡す動的な import';

  it.each([
    ['変数', "const path = './helper.test.ts';\nawait import( path);\n"],
    ['文字列の連結', "await import('./helper' + '.test.ts');\n"],
    ['型の注釈をはさむ連結', "await import('./helper' + ('.test.ts' as string));\n"],
    [
      'import と括弧の間のコメント',
      "const path = './helper.test.ts';\nawait import /* c */ (path);\n",
    ],
    ['三項演算子', "await import(Math.random() > 1 ? './a.ts' : './helper.test.ts');\n"],
    ['括弧で包んだ文字列', "await import(('./helper.test.ts'));\n"],
    // テンプレート文字列（\x24 は $）。置き換えのないものも拒否する。
    ['置き換えのあるテンプレート文字列', 'await import(`./\x24{name}.ts`);\n'],
    ['置き換えのないテンプレート文字列', 'await import(`./helper.test.ts`);\n'],
    // 括弧の中の型の構文。型を取り除くと文字列リテラル1つに見えるが、元のコードではそうでない。
    ['as string を付けた文字列', "await import('./helper.test.ts' as string);\n"],
    ['as const を付けた文字列', "await import('./helper.test.ts' as const);\n"],
    ['satisfies を付けた文字列', "await import('./helper.test.ts' satisfies string);\n"],
    [
      '型の構文を付けた2つ目の引数',
      "await import('./d.json', { with: { type: 'json' } } as const);\n",
    ],
  ])('%s を渡す動的な import を拒否する', (_name, text) => {
    const violations = findViolations(write({ ...HELPER, 'packages/x/src/a.ts': text }));
    expect(violations).toEqual([`packages/x/src/a.ts：${NON_LITERAL}`]);
  });

  it('走査しないディレクトリ（. で始まる）のファイルも、本体のコードから import されれば調べる', () => {
    const violations = findViolations(
      write({
        'packages/x/src/c.ts': "import './.hidden/d.ts';\n",
        'packages/x/src/.hidden/d.ts': 'await import(path);\n',
      }),
    );
    expect(violations).toEqual([`packages/x/src/.hidden/d.ts：${NON_LITERAL}`]);
  });

  it('CommonJS として読み込まれるファイルを拒否する', () => {
    const violations = findViolations(
      write({
        'packages/x/src/a.ts': "import './b.cjs';\n",
        'packages/x/src/b.cjs': "require('./helper' + '.test.ts');\n",
        'packages/y/package.json': JSON.stringify({ name: 'y' }),
        'packages/y/src/c.ts': 'export const c = 1;\n',
      }),
    );
    expect(violations.sort()).toEqual([
      'packages/x/src/b.cjs：CommonJS として読み込まれる（require() は、この検査でたどらない）',
      'packages/y/src/c.ts：CommonJS として読み込まれる（require() は、この検査でたどらない）',
    ]);
  });

  it('構文を解析できないファイルを拒否する', () => {
    const violations = findViolations(
      write({ 'packages/x/src/a.ts': 'enum Mode {\n  A,\n}\nexport { Mode };\n' }),
    );
    expect(violations).toEqual([
      'packages/x/src/a.ts：構文を解析できない（読み込み先を確かめられない）',
    ]);
  });

  it('本体のコードどうしの import、文字列リテラル1つの動的な import、テストからの import は通す', () => {
    const violations = findViolations(
      write({
        ...HELPER,
        'packages/x/src/a.ts':
          "import './b.ts';\nimport { readFileSync } from 'node:fs';\nexport { readFileSync };\n",
        'packages/x/src/b.ts':
          "export const loader = () => import( './c.ts');\nobj.import(x);\nconst s = 'import(x)'; // import(y)\n",
        'packages/x/src/c.ts':
          "export const load = async <T,>(): Promise<T> =>\n  (await import /* c */ (\n    './d.json', { with: { type: 'json' } })) as T;\n",
        'packages/x/src/d.json': '{ "a": "import(x)" }\n',
        'packages/x/src/a.test.ts': "import './helper.test.ts';\n",
      }),
    );
    expect(violations).toEqual([]);
  });
});
