// 本体のコードから、lint の制限を外したファイル（テスト、scripts/、test/、ルートの *.config.ts）に
// import でたどり着けないことを確かめる。CI の check ジョブで実行する（CLAUDE.md「コマンド」、不変条件7と9）。
//
// - 本体のコード：packages/ と spikes/ の中の .ts と .js（*.test.ts、*.e2e.ts、node_modules を除く）。
// - 正規表現ではなく、tsc（--listFilesOnly）が解決した import のグラフを見る。副作用だけの import、
//   改行をはさむ import、export … from、package.json の exports と imports、間接の import も含む。
// - tsc は、文字列リテラル以外を渡す動的な import（import(path) など）をたどれない。
//   そのため、本体のコードと、そこから import でたどり着くファイルでは、その書き方そのものを拒否する。
//
// 使い方：node scripts/check-entry-imports.ts [リポジトリのルート]

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ENTRY_DIRS = ['packages', 'spikes'];
const SOURCE = /\.(ts|mts|cts|js|mjs|cjs)$/;
const TEST = /\.(test|e2e)\.ts$/;
// lint の制限を外したファイル（biome.json の overrides の最後の項目）。パスはリポジトリのルートから。
const EXEMPT = [TEST, /^scripts\//, /^test\//, /^[^/]+\.config\.ts$/];
// 文字列リテラル以外を渡す動的な import。`obj.import(` は除く。
const NON_LITERAL_DYNAMIC_IMPORT = /(?<![.\w$])import\s*\((?!\s*['"])/;

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../..');
const TSC = join(REPO_ROOT, 'node_modules/typescript/bin/tsc');

function toPosix(path: string): string {
  return path.split(sep).join('/');
}

export function entryFiles(root: string): string[] {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile() && SOURCE.test(entry.name) && !TEST.test(entry.name))
        files.push(path);
    }
  };
  for (const dir of ENTRY_DIRS) {
    try {
      walk(join(root, dir));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  return files.sort();
}

export function findViolations(root: string): string[] {
  const absRoot = resolve(root);
  const entries = entryFiles(absRoot);
  const violations: string[] = [];
  if (entries.length === 0) return violations;

  const dir = mkdtempSync(join(tmpdir(), 'entry-imports-'));
  try {
    const config = join(dir, 'tsconfig.json');
    writeFileSync(
      config,
      JSON.stringify({
        compilerOptions: {
          module: 'nodenext',
          moduleResolution: 'nodenext',
          allowJs: true,
          allowImportingTsExtensions: true,
          resolveJsonModule: true,
          noEmit: true,
          types: [],
        },
        files: entries,
      }),
    );
    // 型の誤りは typecheck で見るので、終了コードは見ずに、一覧だけを使う。
    const result = spawnSync(process.execPath, [TSC, '-p', config, '--listFilesOnly'], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    const listed = result.stdout.split('\n').filter((line) => isAbsolute(line.trim()));
    if (listed.length === 0) throw new Error(`tsc の一覧が空だった：${result.stderr}`);
    for (const line of listed) {
      const file = line.trim();
      const rel = toPosix(relative(absRoot, file));
      if (rel.startsWith('../') || rel.split('/').includes('node_modules')) continue;
      if (EXEMPT.some((pattern) => pattern.test(rel))) {
        violations.push(`${rel}：本体のコードから import されている`);
      } else if (NON_LITERAL_DYNAMIC_IMPORT.test(readFileSync(file, 'utf8'))) {
        violations.push(`${rel}：文字列リテラル以外を渡す動的な import`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return violations;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const violations = findViolations(process.argv[2] ?? process.cwd());
  if (violations.length > 0) {
    for (const violation of violations) console.error(violation);
    console.error(
      '::error::本体のコードから、テスト、scripts/、test/、*.config.ts を import しない。動的な import には文字列リテラルだけを渡す（不変条件7と9）',
    );
    process.exit(1);
  }
}
