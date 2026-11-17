import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'packages/*/src/**/*.test.ts',
      'packages/*/test/**/*.test.ts',
      'spikes/**/*.test.ts',
      'scripts/**/*.test.ts',
      'test/**/*.test.ts',
    ],
    exclude: ['**/node_modules/**'],
    globalSetup: ['test/setup/global-pg.ts', 'test/setup/global-keysvc.ts'],
    // テストのファイルごとに、外へのつなぎの見張りを入れる（ループバックと Unix ソケットのほかへの接続と、
    // 注入したリゾルバを通さない名前解決を止め、ファイルの最後に0件を確かめる。M10 の SSRF の横断）。
    setupFiles: ['test/setup/egress-guard.ts'],
    testTimeout: 20_000,
    hookTimeout: 60_000,
  },
});
