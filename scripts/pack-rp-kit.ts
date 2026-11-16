// rp-kit を npm に公開できる形にまとめる（plan 10章「公開の順番」。公開そのものは、M9 のマージの後にメンテナーが行う）。
//
// このリポジトリの中では、Node が .ts をそのまま動かすので、パッケージの exports は src の .ts を指している。
// Node は、node_modules の中の .ts を動かさない。そのため、公開するものは、ここで JavaScript と型定義に変換して作る。
//
// - packages/rp-kit/tsconfig.build.json で、src を JavaScript（.js）と型定義（.d.ts）に変換する。
// - 型定義の中の相対 import（'./x.ts'）を、'./x.js' に書き換える（tsc は、型定義の中の拡張子を書き換えない）。
// - 公開用の package.json を作る（private を外し、exports を変換したファイルに向ける）。README と LICENSE を入れる。
// - テスト、tsconfig、変換の前の .ts は入れない。
//
// このスクリプトは、公開（npm publish）をしない。ネットワークにもつながない。出力先のディレクトリを作るだけである。
//
// 使い方：npm run pack:rp-kit -- [出力先のディレクトリ]
//   出力先を省くと、一時的なディレクトリを作って、その場所を表示する。出力先は、空か、まだないディレクトリにする。

import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE_DIR = join(ROOT, 'packages', 'rp-kit');
/** 公開するものに入れる、変換の結果以外のファイル。 */
const EXTRA_FILES = Object.freeze([
  { from: join(PACKAGE_DIR, 'README.md'), to: 'README.md' },
  { from: join(ROOT, 'LICENSE'), to: 'LICENSE' },
]);

export interface PackedRpKit {
  readonly dir: string;
  readonly name: string;
  readonly version: string;
  /** 出力先からの相対パス（並べ替え済み）。 */
  readonly files: readonly string[];
}

function listFiles(dir: string, base = dir): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(dir, entry.name);
      return entry.isDirectory() ? listFiles(path, base) : [relative(base, path)];
    })
    .sort();
}

/** 型定義の中の相対 import の拡張子を、.ts から .js に書き換える。 */
export function rewriteDeclarationImports(source: string): string {
  return source.replace(/(from\s+['"])(\.{1,2}\/[^'"]+)\.ts(['"])/g, '$1$2.js$3');
}

/** 公開用の package.json（リポジトリの中の package.json から作る）。 */
export function publishManifest(source: Record<string, unknown>): Record<string, unknown> {
  return {
    name: source.name,
    version: source.version,
    description: source.description,
    license: source.license,
    repository: source.repository,
    type: 'module',
    engines: source.engines,
    sideEffects: false,
    // スコープ付きのパッケージは、既定では公開されない（有料の組織だけの restricted になる）。公開の範囲を固定する。
    publishConfig: { access: 'public' },
    exports: {
      '.': { types: './index.d.ts', default: './index.js' },
      './kit': { types: './kit/index.d.ts', default: './kit/index.js' },
    },
    dependencies: source.dependencies,
  };
}

export function packRpKit(outDir?: string): PackedRpKit {
  const dir = outDir === undefined ? mkdtempSync(join(tmpdir(), 'rp-kit-pack-')) : resolve(outDir);
  if (existsSync(dir) && readdirSync(dir).length > 0) {
    throw new Error('出力先は、空か、まだないディレクトリにする');
  }
  mkdirSync(dir, { recursive: true });
  execFileSync(
    process.execPath,
    [
      join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'),
      '-p',
      join(PACKAGE_DIR, 'tsconfig.build.json'),
      '--outDir',
      dir,
    ],
    { cwd: ROOT, stdio: ['ignore', 'inherit', 'inherit'] },
  );
  for (const file of listFiles(dir)) {
    if (!file.endsWith('.d.ts')) continue;
    const path = join(dir, file);
    writeFileSync(path, rewriteDeclarationImports(readFileSync(path, 'utf8')));
  }
  const source = JSON.parse(readFileSync(join(PACKAGE_DIR, 'package.json'), 'utf8')) as Record<
    string,
    unknown
  >;
  const manifest = publishManifest(source);
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const { from, to } of EXTRA_FILES) copyFileSync(from, join(dir, to));
  return {
    dir,
    name: String(manifest.name),
    version: String(manifest.version),
    files: listFiles(dir),
  };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const packed = packRpKit(process.argv[2]);
  console.log(
    `${packed.name}@${packed.version} を、次の場所にまとめました（公開はしていません）。`,
  );
  console.log(packed.dir);
  for (const file of packed.files) console.log(`  ${file}`);
  if (packed.version === '0.0.0') {
    console.log(
      '版が 0.0.0 のままです。公開の前に、packages/rp-kit/package.json の version を決めてください。',
    );
  }
}
