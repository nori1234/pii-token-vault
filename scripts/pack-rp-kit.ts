// rp-kit を npm に公開できる形にまとめる（plan 10章「公開の順番」。公開そのものは、M9 のマージの後にメンテナーが行う）。
//
// このリポジトリの中では、Node が .ts をそのまま動かすので、パッケージの exports は src の .ts を指している。
// Node は、node_modules の中の .ts を動かさない。そのため、公開するものは、ここで JavaScript と型定義に変換して作る。
//
// - packages/rp-kit/tsconfig.build.json で、src を JavaScript（.js）と型定義（.d.ts）に変換する。
// - 型定義の中の相対 import（'./x.ts'）を、'./x.js' に書き換える（tsc は、型定義の中の拡張子を書き換えない）。
// - 公開用の package.json を作る（private を外し、exports を変換したファイルに向ける）。README と LICENSE を入れる。
// - README の相対のリンク（../../docs/… など）は、npm のページでも開けるように、GitHub の main の URL に書き換える。
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
/** 公開するものに、そのまま入れるファイル（README は、リンクを書き換えて入れる）。 */
const EXTRA_FILES = Object.freeze([{ from: join(ROOT, 'LICENSE'), to: 'LICENSE' }]);

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

/**
 * README の中で、前から順に、コードブロック（同じ長さの ``` で閉じるまで）、インラインのコード、リンクの先
 * （](…) の中）のどれかに当たる。リンクの先だけが、2つ目の組（target）に入る。
 */
const README_LINK_PATTERN =
  /^[ \t]*(`{3,})[^\n]*\n[\s\S]*?^[ \t]*\1[ \t]*$|`[^`\n]*`|\]\(([^)\s]+)\)/gm;

/**
 * README の相対のリンク（[…](../../docs/x.md) など）を、GitHub の main の URL に書き換える。
 * npm のページでは、相対のリンクが、パッケージのディレクトリ（packages/rp-kit）を基準に開くとは限らないため。
 * スキーム付きの URL（https: など）、ページの中の位置（#）、ルートからのパス（/）は変えない。
 * コードブロック（```）とインラインのコード（`…`）の中は、リンクではないので変えない（コードの例の
 * `handlers[name](request)` のような書き方を、URL に書き換えないため）。
 * リポジトリの外を指すリンクは、壊れたリンクを公開しないように、失敗にする。
 */
export function rewriteReadmeLinks(markdown: string, repository: unknown): string {
  const { root, dir } = readmeLinkBase(repository);
  return markdown.replace(
    README_LINK_PATTERN,
    (match, _fence: string | undefined, target: string | undefined) => {
      // コードブロックとインラインのコードは、そのまま返す。
      if (target === undefined) return match;
      if (/^(?:[a-z][a-z\d+.-]*:|#|\/)/i.test(target)) return match;
      const url = new URL(target, dir).href;
      if (!url.startsWith(root)) {
        throw new Error('README の相対のリンクが、リポジトリの外を指している');
      }
      return `](${url})`;
    },
  );
}

/** package.json の repository（GitHub の URL と、パッケージのディレクトリ）から、リンクの基準を作る。 */
function readmeLinkBase(repository: unknown): { readonly root: string; readonly dir: string } {
  const { url, directory } = (repository ?? {}) as {
    readonly url?: unknown;
    readonly directory?: unknown;
  };
  const match =
    typeof url === 'string'
      ? /^git\+https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(url)
      : null;
  if (match === null || typeof directory !== 'string' || directory === '') {
    throw new Error('package.json の repository の形が違う（GitHub の URL と directory が要る）');
  }
  const root = `https://github.com/${match[1]}/${match[2]}/blob/main/`;
  return { root, dir: new URL(directory.endsWith('/') ? directory : `${directory}/`, root).href };
}

/** 公開用の package.json（リポジトリの中の package.json から作る）。 */
export function publishManifest(source: Record<string, unknown>): Record<string, unknown> {
  return {
    name: source.name,
    version: source.version,
    description: source.description,
    // npm のページの検索の語と、リポジトリの README、イシューへのリンク。
    keywords: source.keywords,
    homepage: source.homepage,
    bugs: source.bugs,
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
  writeFileSync(
    join(dir, 'README.md'),
    rewriteReadmeLinks(readFileSync(join(PACKAGE_DIR, 'README.md'), 'utf8'), source.repository),
  );
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
