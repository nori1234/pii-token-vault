// scripts/check-entry-imports.ts の検査が、正規表現では見逃していた import の書き方も拒否することを確かめる。

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { findViolations } from '../../scripts/check-entry-imports.ts';

let root: string;

function write(files: Record<string, string>) {
  root = mkdtempSync(join(tmpdir(), 'entry-imports-test-'));
  for (const [path, text] of Object.entries(files)) {
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

  it('文字列リテラル以外を渡す動的な import を拒否する', () => {
    const violations = findViolations(
      write({
        'packages/x/src/a.ts': "const path = './helper.test.ts';\nawait import( path);\n",
        // テンプレート文字列（\x24 は $）。
        'packages/x/src/b.ts': 'await import(`./\x24{name}.ts`);\n',
        // 走査しないディレクトリ（. で始まる）のファイルも、本体のコードから import されれば調べる。
        'packages/x/src/c.ts': "import './.hidden/d.ts';\n",
        'packages/x/src/.hidden/d.ts': 'await import(path);\n',
      }),
    );
    expect(violations.sort()).toEqual([
      'packages/x/src/.hidden/d.ts：文字列リテラル以外を渡す動的な import',
      'packages/x/src/a.ts：文字列リテラル以外を渡す動的な import',
      'packages/x/src/b.ts：文字列リテラル以外を渡す動的な import',
    ]);
  });

  it('本体のコードどうしの import、文字列リテラルの動的な import、テストからの import は通す', () => {
    const violations = findViolations(
      write({
        ...HELPER,
        'packages/x/src/a.ts':
          "import './b.ts';\nimport { readFileSync } from 'node:fs';\nexport { readFileSync };\n",
        'packages/x/src/b.ts': "export const loader = () => import( './c.ts');\nobj.import(x);\n",
        'packages/x/src/c.ts': 'export {};\n',
        'packages/x/src/a.test.ts': "import './helper.test.ts';\n",
      }),
    );
    expect(violations).toEqual([]);
  });
});
