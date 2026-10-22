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
    globalSetup: ['test/setup/global-pg.ts'],
    testTimeout: 20_000,
    hookTimeout: 60_000,
  },
});
