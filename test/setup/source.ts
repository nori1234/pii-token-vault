// ソースの静的な点検の補助（t08-crypto-allowlist、t08-key-client-surface、x-db-boundary）。
// 正規表現による簡易な解析なので、ここで見つからないことは「ない」ことの証明にはならない。lint、型の検査、
// principle-review と合わせて使う。

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** dir の下の .ts のファイル（リポジトリの根からの相対パス）。node_modules は見ない。 */
export function tsFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (abs: string) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue;
      const path = join(abs, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(relative(REPO_ROOT, path));
    }
  };
  walk(join(REPO_ROOT, dir));
  return out.sort();
}

/** packages/<name>/src の下の .ts（テストを除く）。 */
export function packageSourceFiles(): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(REPO_ROOT, 'packages'), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    for (const file of tsFiles(join('packages', entry.name, 'src'))) {
      if (!/\.(test|e2e)\.ts$/.test(file)) out.push(file);
    }
  }
  return out.sort();
}

export function read(file: string): string {
  return readFileSync(join(REPO_ROOT, file), 'utf8');
}

/** コメントを空白に置き換える（文字列とテンプレートの中は残す）。 */
export function stripComments(code: string): string {
  let out = '';
  let i = 0;
  let quote: string | undefined;
  while (i < code.length) {
    const c = code[i] ?? '';
    const next = code[i + 1] ?? '';
    if (quote !== undefined) {
      out += c;
      if (c === '\\') {
        out += next;
        i += 2;
        continue;
      }
      if (c === quote) quote = undefined;
      i += 1;
      continue;
    }
    if (c === '/' && next === '/') {
      while (i < code.length && code[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && next === '*') {
      const end = code.indexOf('*/', i + 2);
      i = end === -1 ? code.length : end + 2;
      out += ' ';
      continue;
    }
    if (c === "'" || c === '"' || c === '`') quote = c;
    out += c;
    i += 1;
  }
  return out;
}

export interface ImportInfo {
  readonly specifier: string;
  /** 名前付きの import の名前（`type` を除いた元の名前）。既定と名前空間の import は '*default*' と '*namespace*'。 */
  readonly names: readonly string[];
  readonly kind: 'static' | 'dynamic' | 'reexport';
}

export function importsOf(source: string): ImportInfo[] {
  const code = stripComments(source);
  const out: ImportInfo[] = [];
  const parseNames = (clause: string): string[] => {
    const names: string[] = [];
    const braces = /\{([^}]*)\}/.exec(clause);
    if (braces?.[1] !== undefined) {
      for (const part of braces[1].split(',')) {
        const name = part
          .trim()
          .replace(/^type\s+/, '')
          .split(/\s+as\s+/)[0]
          ?.trim();
        if (name) names.push(name);
      }
    }
    const outside = clause.replace(/\{[^}]*\}/, '').trim();
    if (/\*\s+as\s+\w+/.test(outside)) names.push('*namespace*');
    else if (/^(type\s+)?[A-Za-z_$][\w$]*/.test(outside.replace(/,$/, '').trim())) {
      names.push('*default*');
    }
    return names;
  };
  for (const match of code.matchAll(/\bimport\s+(type\s+)?([^'";]*?)\s+from\s+['"]([^'"]+)['"]/g)) {
    out.push({ specifier: match[3] ?? '', names: parseNames(match[2] ?? ''), kind: 'static' });
  }
  for (const match of code.matchAll(/\bimport\s+['"]([^'"]+)['"]/g)) {
    out.push({ specifier: match[1] ?? '', names: [], kind: 'static' });
  }
  for (const match of code.matchAll(
    /\bexport\s+(type\s+)?(\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g,
  )) {
    out.push({ specifier: match[3] ?? '', names: parseNames(match[2] ?? ''), kind: 'reexport' });
  }
  for (const match of code.matchAll(/\bimport\s*\(\s*(['"`]?)([^'"`)]*)\1\s*\)/g)) {
    out.push({
      specifier: match[1] === '' ? '*expression*' : (match[2] ?? ''),
      names: [],
      kind: 'dynamic',
    });
  }
  return out;
}

/** 文字列リテラル（' と " だけ）。 */
export function stringLiterals(source: string): string[] {
  const code = stripComments(source);
  return [...code.matchAll(/'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"/g)].map(
    (m) => m[1] ?? m[2] ?? '',
  );
}
