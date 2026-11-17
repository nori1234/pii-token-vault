// idp の API のルートが、どれも、ルート一覧のテスト（x-idp-routes）のほかに、少なくとも1つのテストか補助から呼ばれて
// いることを確かめる（M10 の横断の検査。どのテストも呼ばないルートには、利用者どうしの BOLA や漏えいの検査が届かない
// ため）。ルートを足したら、そのルートを呼ぶテストを足す（足さないと、このテストが落ちる）。
// 画面の枠（GET /、/desk など）、静的なファイル、公開鍵は、利用者のものに触れないので、ここでは数えない。

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestIdp, type TestIdp } from '../setup/idp.ts';

const LEAK = dirname(fileURLToPath(import.meta.url));
const SETUP = join(LEAK, '..', 'setup');
const SELF = 'x-route-coverage.test.ts';

/** 文字としては現れず、応答の redirectTo をたどって通るルート（どのテストが通るか）。 */
const INDIRECT: Readonly<Record<string, string>> = {
  'GET /interaction/:uid/operation/finish':
    't01-operation-step-up と t07-approvals-leak（承認の応答の redirectTo をたどる）',
};

let t: TestIdp;

beforeAll(async () => {
  t = await startTestIdp({ tenants: 1, clients: [{ tenant: 0 }] });
});

afterAll(async () => {
  await t?.stop();
});

describe('M10：idp の API のルートを呼ぶテストがある', () => {
  it('どの API のルートも、ルート一覧のほかのテストか補助から呼ばれている', () => {
    // 攻撃者が持っている情報：なし（検査の届かないルートを残さないための、横断の確かめ）
    // 試す経路：idp が実際に持つルートの一覧を取り、test/leak と test/setup の中で、そのパスを呼んでいるかを探す
    //           （`:uid` を含むルートは、`/interaction/` の後ろに付けて呼ぶ補助があるので、`:uid` の後ろの文字で探す）
    // 期待する結果：呼ばれていないルートがない。文字として現れないルートは、INDIRECT に、通すテストを書いて残す
    // plan 11章：テスト6（M10 の横断の BOLA）の土台
    const sources = [
      ...readdirSync(LEAK)
        .filter((f) => /\.(test|e2e)\.ts$/.test(f) && f !== 'x-idp-routes.test.ts' && f !== SELF)
        .map((f) => join(LEAK, f)),
      ...readdirSync(SETUP)
        .filter((f) => f.endsWith('.ts'))
        .map((f) => join(SETUP, f)),
    ]
      .map((path) => readFileSync(path, 'utf8'))
      .join('\n');
    const routes = t.idp.routes().filter((route) => !route.startsWith('HEAD '));
    const api = routes.filter((route) => / \/(api|interaction)\//.test(route));
    expect(api.length).toBeGreaterThan(60);
    const uncovered = api.filter((route) => {
      if (INDIRECT[route] !== undefined) return false;
      const path = route.replace(/^[A-Z]+ /, '').replace(/ \(approval\)$/, '');
      const at = path.indexOf(':uid');
      const literal = at < 0 ? path : path.slice(at + ':uid'.length) || '/interaction/';
      return !sources.includes(literal);
    });
    expect(uncovered).toEqual([]);
    // もう無いルートを、INDIRECT に残さない。
    for (const route of Object.keys(INDIRECT)) expect(routes).toContain(route);
  });
});
