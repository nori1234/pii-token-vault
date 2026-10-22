// Playwright の設定。@playwright/test は 1.56.1 に完全固定する（この環境の Chromium は revision 1194）。
// この環境では `npx playwright install` を実行しない。CI では `npx playwright install --with-deps chromium`。
import { defineConfig, devices } from '@playwright/test';

const isCI = Boolean(process.env.CI);
const passkeySpikePort = process.env.SPIKE_PASSKEY_PORT ?? '4101';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.e2e.ts',
  testIgnore: '**/node_modules/**',
  forbidOnly: isCI,
  // 再試行は、ローカルでも CI でもしない。認証や承認の分岐が不安定なとき、再試行で通ってしまうと、
  // その不安定さ（競合やチャレンジの使い回しなど）自体を見逃すため。
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    // トレースには、リクエストの本文（チャレンジや資格情報 ID）が入る。既定では取らず、
    // 調べるときだけ、ローカルで `--trace on` を付ける。
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      // 捨てスパイク1（spikes/passkey）。M3 で packages/idp に置き換える。
      command: 'node spikes/passkey/server.ts',
      env: { SPIKE_PASSKEY_PORT: passkeySpikePort },
      url: `http://localhost:${passkeySpikePort}/`,
      reuseExistingServer: !isCI,
      timeout: 30_000,
      stdout: 'ignore',
      stderr: 'pipe',
    },
  ],
});
