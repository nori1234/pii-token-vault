// Playwright の設定。@playwright/test は 1.56.1 に完全固定する（この環境の Chromium は revision 1194）。
// この環境では `npx playwright install` を実行しない。CI では `npx playwright install --with-deps chromium`。
import { defineConfig, devices } from '@playwright/test';

const isCI = Boolean(process.env.CI);

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
  // サーバー（一時的な Postgres、鍵サービス、idp）は、各 E2E のファイルが自分のワーカーの中で起動する
  // （test/e2e/idp.e2e.ts）。企業の鍵をテストが持つため、webServer は使わない。
});
