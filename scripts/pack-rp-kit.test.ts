// rp-kit を公開用にまとめるスクリプト（scripts/pack-rp-kit.ts）の検査。
// まとめたものを、別のプロセスの Node で（.ts を動かさずに）読み込めること、テストや変換の前の .ts を入れないこと、
// 公開用の package.json が private を外し、変換したファイルを指していること、README のリンクが npm のページでも
// 開けることを確かめる。公開はしない。

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type PackedRpKit,
  packRpKit,
  rewriteDeclarationImports,
  rewriteReadmeLinks,
} from './pack-rp-kit.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let work = '';
let packed: PackedRpKit;

beforeAll(() => {
  // 依存（jose）を、リポジトリの node_modules から解決できるように、その中に作る。
  work = mkdtempSync(join(ROOT, 'node_modules', '.rp-kit-pack-test-'));
  packed = packRpKit(join(work, 'out'));
}, 120_000);

afterAll(() => {
  if (work !== '') rmSync(work, { recursive: true, force: true });
});

describe('rp-kit の公開の準備（plan 10章「公開の順番」）', () => {
  it('変換した .js と .d.ts、公開用の package.json、README、LICENSE だけを入れる', () => {
    expect(packed.name).toBe('@pii-token-vault/rp-kit');
    expect(packed.files).toContain('index.js');
    expect(packed.files).toContain('index.d.ts');
    expect(packed.files).toContain('kit/index.js');
    expect(packed.files).toContain('kit/index.d.ts');
    expect(packed.files).toContain('README.md');
    expect(packed.files).toContain('LICENSE');
    for (const file of packed.files) {
      expect(file.endsWith('.ts') && !file.endsWith('.d.ts')).toBe(false);
      expect(file).not.toMatch(/(^|\/)test\/|\.test\.|tsconfig/);
    }
    const manifest = JSON.parse(readFileSync(join(packed.dir, 'package.json'), 'utf8'));
    expect(manifest.private).toBeUndefined();
    expect(manifest.publishConfig).toEqual({ access: 'public' });
    expect(manifest.exports).toEqual({
      '.': { types: './index.d.ts', default: './index.js' },
      './kit': { types: './kit/index.d.ts', default: './kit/index.js' },
    });
    expect(Object.keys(manifest.dependencies)).toEqual(['jose']);
    expect(manifest.devDependencies).toBeUndefined();
    expect(manifest.scripts).toBeUndefined();
  });

  it('型定義と JavaScript の中の相対 import は、.js を指す', () => {
    for (const file of packed.files) {
      if (!file.endsWith('.js') && !file.endsWith('.d.ts')) continue;
      const source = readFileSync(join(packed.dir, file), 'utf8');
      expect(source).not.toMatch(/from\s+['"]\.{1,2}\/[^'"]+\.ts['"]/);
    }
    expect(
      rewriteDeclarationImports("import { a } from './x.ts';\nexport * from '../y/z.ts';"),
    ).toBe("import { a } from './x.js';\nexport * from '../y/z.js';");
    // パッケージの名前や、.ts で終わらない指定は変えない。
    expect(rewriteDeclarationImports("import { b } from 'jose';\nimport c from './c.js';")).toBe(
      "import { b } from 'jose';\nimport c from './c.js';",
    );
  });

  it('別のプロセスの Node で、SDK とキットを読み込んで使える', () => {
    const index = pathToFileURL(join(packed.dir, 'index.js')).href;
    const kit = pathToFileURL(join(packed.dir, 'kit', 'index.js')).href;
    const script = `
      const sdk = await import(${JSON.stringify(index)});
      const kit = await import(${JSON.stringify(kit)});
      const report = kit.judge({
        sameAliasAccounts: ['a', 'b'],
        legacyLogin: 'absent',
        legacyReset: 'absent',
        linkAttack: 'refused',
        routes: [{ method: 'GET', path: '/health', tags: ['other'] }],
      }, { mode: 'full' });
      console.log(JSON.stringify({
        createWarifuClient: typeof sdk.createWarifuClient,
        createCompanyApiClient: typeof sdk.createCompanyApiClient,
        setRefusalOf: typeof sdk.setRefusalOf,
        error: new sdk.RpKitError('replayed').code,
        runConformanceKit: typeof kit.runConformanceKit,
        outcome: report.outcome,
      }));
    `;
    const output = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
      cwd: packed.dir,
      encoding: 'utf8',
    });
    expect(JSON.parse(output)).toEqual({
      createWarifuClient: 'function',
      createCompanyApiClient: 'function',
      setRefusalOf: 'function',
      error: 'replayed',
      runConformanceKit: 'function',
      outcome: 'pass',
    });
  });

  it('README の相対のリンクは、GitHub の main の URL に書き換え、どれもリポジトリにあるファイルを指す', () => {
    const repo = 'https://github.com/nori1234/pii-token-vault/blob/main/';
    const readme = readFileSync(join(packed.dir, 'README.md'), 'utf8');
    const targets = [...readme.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1] ?? '');
    expect(targets.length).toBeGreaterThan(0);
    for (const target of targets) {
      // 相対のリンクを残さない（npm のページで、どこを基準に開くかが決まらない）。
      expect(target).toMatch(/^(https:\/\/|#)/);
      if (!target.startsWith(repo)) continue;
      expect(existsSync(join(ROOT, target.slice(repo.length).replace(/#.*$/, '')))).toBe(true);
    }
    // リンクの先のほかは、リポジトリの README のまま。
    const source = readFileSync(join(ROOT, 'packages', 'rp-kit', 'README.md'), 'utf8');
    const withoutTargets = (markdown: string): string => markdown.replace(/\]\([^)\s]+\)/g, ']()');
    expect(withoutTargets(readme)).toBe(withoutTargets(source));
  });

  it('README のリンクの書き換えは、URL とページの中の位置を変えず、リポジトリの外を指すリンクを断る', () => {
    const repository = { type: 'git', url: 'git+https://github.com/o/r.git', directory: 'pkgs/p' };
    expect(
      rewriteReadmeLinks(
        '[a](../../docs/x.md#s) [b](./y.md) [c](https://e.example/z) [d](#k)',
        repository,
      ),
    ).toBe(
      '[a](https://github.com/o/r/blob/main/docs/x.md#s) [b](https://github.com/o/r/blob/main/pkgs/p/y.md) [c](https://e.example/z) [d](#k)',
    );
    expect(() => rewriteReadmeLinks('[a](../../../x.md)', repository)).toThrow();
    expect(() =>
      rewriteReadmeLinks('[a](x.md)', { url: 'git+https://gitlab.example/o/r.git' }),
    ).toThrow();
  });

  it('空でない出力先には書かない', () => {
    expect(() => packRpKit(packed.dir)).toThrow();
  });
});
