// 本体のコードから、lint の制限を外したファイル（テスト、scripts/、test/、ルートの *.config.ts）に
// import でたどり着けないことを確かめる。CI の check ジョブで実行する（CLAUDE.md「コマンド」、不変条件7と9）。
//
// - 本体のコード：packages/ と spikes/ の中の .ts と .js（*.test.ts、*.e2e.ts、node_modules を除く）。
// - 正規表現ではなく、tsc（--listFilesOnly）が解決した import のグラフを見る。副作用だけの import、
//   改行をはさむ import、export … from、package.json の exports と imports、間接の import も含む。
// - tsc がたどれない読み込み方は、本体のコードと、そこから import でたどり着くファイルでは、書き方そのものを拒否する。
//   - 動的な import の引数は、引用符で囲んだ文字列リテラル1つだけにする（import(path)、'./a' + b、三項演算子、
//     テンプレート文字列を拒否する）。正規表現ではなく、型を取り除いてから es-module-lexer で字句を解析して判定する。
//     解析できないファイルは、違反として扱う。
//   - CommonJS として読み込まれるファイル（.cjs、.cts、type が module でない package.json の下のファイル）を拒否する。
//     require() は、tsc の import のグラフに載らないため。
// - コードの文字列を実行するもの（Function、node:vm）と、ファイルを別に起動するもの（node:worker_threads）は、
//   この検査では見ない。principle-review の観点7と9で点検する。
//
// 使い方：node scripts/check-entry-imports.ts [リポジトリのルート]

import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initSync, parse } from 'es-module-lexer';

const ENTRY_DIRS = ['packages', 'spikes'];
const SOURCE = /\.(ts|mts|cts|js|mjs|cjs)$/;
const TEST = /\.(test|e2e)\.ts$/;
// lint の制限を外したファイル（biome.json の overrides の最後の項目）。パスはリポジトリのルートから。
const EXEMPT = [TEST, /^scripts\//, /^test\//, /^[^/]+\.config\.ts$/];
const TYPESCRIPT = /\.(ts|mts|cts)$/;
const COMMONJS = /\.(cjs|cts)$/;
const ES_MODULE = /\.(mjs|mts)$/;
// 動的な import の引数として許す形：引用符で囲んだ文字列リテラル1つ（エスケープと改行を含まないもの）。
const STRING_LITERAL = /^(['"])[^'"\\\r\n]*\1$/;

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

// 動的な import の引数が、引用符で囲んだ文字列リテラル1つでなければ、理由を返す。
function dynamicImportProblem(file: string, text: string): string | undefined {
  let code: string;
  let imports: ReturnType<typeof parse>[0];
  try {
    // 型を空白に置き換えるので、位置はずれない。
    code = TYPESCRIPT.test(file) ? stripTypeScriptTypes(text, { mode: 'strip' }) : text;
    [imports] = parse(code, file);
  } catch {
    return '構文を解析できない（tsc がたどれない import を確かめられない）';
  }
  for (const entry of imports) {
    // d が -1 なら静的な import、-2 なら import.meta。それ以外は動的な import。
    if (entry.d < 0) continue;
    if (entry.n === undefined || !STRING_LITERAL.test(code.slice(entry.s, entry.e))) {
      return '引用符で囲んだ文字列リテラル1つ以外を渡す動的な import';
    }
  }
  return undefined;
}

// Node が CommonJS として読み込むファイルか。拡張子と、いちばん近い package.json の type で決まる。
function isCommonJs(absRoot: string, file: string): boolean {
  if (COMMONJS.test(file)) return true;
  if (ES_MODULE.test(file)) return false;
  for (let dir = dirname(file); ; dir = dirname(dir)) {
    const manifest = join(dir, 'package.json');
    if (existsSync(manifest)) return JSON.parse(readFileSync(manifest, 'utf8')).type !== 'module';
    if (dir === absRoot || dir === dirname(dir)) return true;
  }
}

export function findViolations(root: string): string[] {
  const absRoot = resolve(root);
  const entries = entryFiles(absRoot);
  const violations: string[] = [];
  if (entries.length === 0) return violations;
  initSync();

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
        continue;
      }
      // JSON など、コードでないファイルは、読み込みの書き方を調べない。
      if (!SOURCE.test(file)) continue;
      if (isCommonJs(absRoot, file)) {
        violations.push(
          `${rel}：CommonJS として読み込まれる（require は tsc の import のグラフに載らない）`,
        );
      }
      const problem = dynamicImportProblem(file, readFileSync(file, 'utf8'));
      if (problem) violations.push(`${rel}：${problem}`);
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
      '::error::本体のコードから、テスト、scripts/、test/、*.config.ts を import しない。動的な import には、引用符で囲んだ文字列リテラル1つだけを渡す。本体のコードは ES モジュールにする（不変条件7と9）',
    );
    process.exit(1);
  }
}
