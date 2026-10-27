// 本体のコードから、lint の制限を外したファイル（テスト、scripts/、test/、ルートの *.config.ts）に
// import でたどり着けないことを確かめる。CI の check ジョブで実行する（CLAUDE.md「コマンド」、不変条件7と9）。
//
// - 本体のコード：packages/ と spikes/ の中の .ts と .js（*.test.ts、*.e2e.ts、node_modules を除く）。
// - Node が実際に読み込むのと同じ方法で、import をたどる。tsc のように元のコードを見る道具と組み合わせると、
//   型の構文（'./a.ts' as string など）や URL の書き方（?x、%2E）で、見え方が食い違うため。
//   - 型の除去：Node 自身の stripTypeScriptTypes（node:module）。取り除いた後のコードを es-module-lexer で字句解析する
//     （minimal の版。v2 と同じ形の記録を返す。Node では、init を待たなくても、parse が同期でコンパイルする）。
//   - 読み込み先の解決：Node 自身の import.meta.resolve（子プロセスで動かす。読み込み先のコードは実行しない）。
//     package.json の exports と imports、ワークスペースのパッケージ（実体のパスに直す）も、Node と同じに解決する。
// - 次の書き方は、本体のコードと、そこから import でたどり着くファイルでは、そのものを拒否する。
//   - 動的な import の引数が、引用符で囲んだ文字列リテラル1つでないもの（import(path)、'./a' + b、三項演算子、
//     テンプレート文字列）と、括弧の中に型の構文があるもの（as、satisfies）。
//   - ファイルでも node: の組み込みでもないもの（data: や https:）を読み込む import と、解決できない import。
//   - CommonJS として読み込まれるファイル（.cjs、.cts、type が module でない package.json の下のファイル）。
//     require() は、この検査ではたどらないため。
//   - 解析できないファイル。
// - コードの文字列を実行するもの（Function、node:vm）と、ファイルを別に起動するもの（node:worker_threads）は、
//   この検査では見ない。principle-review の観点7と9で点検する。
//
// 使い方：node scripts/check-entry-imports.ts [リポジトリのルート]

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse } from 'es-module-lexer/minimal';

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

const NON_LITERAL = '引用符で囲んだ文字列リテラル1つ以外を渡す動的な import';
const UNPARSABLE = '構文を解析できない（読み込み先を確かめられない）';

// 子プロセスで、[読み込み先の文字列, 読み込む側の URL] の一覧を、Node の解決のしかたで URL に直す。
// 解決できないものは null にする。import.meta.resolve の第2引数は、このフラグを付けたときだけ使える。
const RESOLVER = `
import { readFileSync } from 'node:fs';
const requests = JSON.parse(readFileSync(0, 'utf8'));
const results = requests.map(([specifier, parent]) => {
  try {
    return import.meta.resolve(specifier, parent);
  } catch {
    return null;
  }
});
process.stdout.write(JSON.stringify(results));
`;

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

// 型を取り除いたコードを字句解析し、読み込み先の文字列を返す。調べられない書き方があれば、その理由も返す。
function scan(file: string, text: string): { specifiers: string[]; problem?: string } {
  let code: string;
  let imports: ReturnType<typeof parse>[0];
  try {
    // 型を空白に置き換えるので、位置はずれない。
    code = TYPESCRIPT.test(file) ? stripTypeScriptTypes(text, { mode: 'strip' }) : text;
    [imports] = parse(code, file);
  } catch {
    return { specifiers: [], problem: UNPARSABLE };
  }
  const specifiers: string[] = [];
  let problem: string | undefined;
  for (const entry of imports) {
    // d が -2 なら import.meta、-1 なら静的な import、それ以外は動的な import。
    if (entry.d === -2) continue;
    if (entry.n === undefined) {
      problem = entry.d >= 0 ? NON_LITERAL : UNPARSABLE;
      continue;
    }
    // 動的な import は、括弧の中（ss から se まで）が型を取り除く前と後で同じで、引数が文字列リテラル1つのものだけを許す。
    if (
      entry.d >= 0 &&
      (!STRING_LITERAL.test(text.slice(entry.s, entry.e)) ||
        text.slice(entry.ss, entry.se) !== code.slice(entry.ss, entry.se))
    ) {
      problem = NON_LITERAL;
      continue;
    }
    specifiers.push(entry.n);
  }
  return { specifiers, problem };
}

function resolveAll(requests: [string, string][]): (string | null)[] {
  if (requests.length === 0) return [];
  const result = spawnSync(
    process.execPath,
    ['--experimental-import-meta-resolve', '--input-type=module', '-e', RESOLVER],
    { input: JSON.stringify(requests), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`読み込み先の解決に失敗した：${result.stderr}`);
  return JSON.parse(result.stdout);
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
  // Node は読み込み先を実体のパスに直すので、ルートも実体のパスにそろえる。
  const absRoot = realpathSync(resolve(root));
  const entries = entryFiles(absRoot);
  const violations = new Set<string>();
  if (entries.length === 0) return [];
  const rel = (file: string) => toPosix(relative(absRoot, file));

  const seen = new Set(entries);
  let frontier = entries;
  while (frontier.length > 0) {
    const requests: { specifier: string; importer: string }[] = [];
    for (const file of frontier) {
      if (isCommonJs(absRoot, file)) {
        violations.add(
          `${rel(file)}：CommonJS として読み込まれる（require() は、この検査でたどらない）`,
        );
      }
      const { specifiers, problem } = scan(file, readFileSync(file, 'utf8'));
      if (problem) violations.add(`${rel(file)}：${problem}`);
      for (const specifier of specifiers) requests.push({ specifier, importer: file });
    }

    const next: string[] = [];
    const urls = resolveAll(
      requests.map(({ specifier, importer }) => [specifier, pathToFileURL(importer).href]),
    );
    requests.forEach(({ specifier, importer: file }, i) => {
      const importer = rel(file);
      const url = urls[i] ?? null;
      if (url?.startsWith('node:')) return;
      if (url && !url.startsWith('file:')) {
        violations.add(
          `${importer}：ファイル以外（data: や https: など）を読み込む import（${specifier}）`,
        );
        return;
      }
      // ?x や #x は取り除かれ、%2E などは元の文字に直る（Node が読み込むファイルと同じになる）。
      const target = url ? fileURLToPath(url) : undefined;
      if (!target || !existsSync(target)) {
        violations.add(`${importer}：読み込み先を解決できない import（${specifier}）`);
        return;
      }
      const targetRel = rel(target);
      if (targetRel.startsWith('../') || targetRel.split('/').includes('node_modules')) return;
      if (EXEMPT.some((pattern) => pattern.test(targetRel))) {
        violations.add(`${targetRel}：本体のコードから import されている`);
        return;
      }
      if (seen.has(target)) return;
      seen.add(target);
      // JSON など、コードでないファイルは、その先をたどらない。
      if (SOURCE.test(target)) next.push(target);
    });
    frontier = next;
  }
  return [...violations];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const violations = findViolations(process.argv[2] ?? process.cwd());
  if (violations.length > 0) {
    for (const violation of violations) console.error(violation);
    console.error(
      '::error::本体のコードから、テスト、scripts/、test/、*.config.ts を import しない。動的な import には、型の構文を付けない、引用符で囲んだ文字列リテラル1つだけを渡す。読み込み先はファイルか node: の組み込みにし、本体のコードは ES モジュールにする（不変条件7と9）',
    );
    process.exit(1);
  }
}
