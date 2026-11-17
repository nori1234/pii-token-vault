// Vitest の setupFiles（vitest.config.ts）。テストのファイルごとに、外へのつなぎの見張り（test/setup/egress.ts）を
// 入れ、ファイルの最後に、止めたつなぎと名前解決が0件であることを確かめてから外す（M10 の SSRF の横断）。
// 見張りが止めたものを確かめるテストは、そのテストの中で takeEgressAttempts で取り出す（x-egress-guard）。

import { afterAll, expect } from 'vitest';
import { installEgressGuard, takeEgressAttempts, uninstallEgressGuard } from './egress.ts';

installEgressGuard();

afterAll(() => {
  const attempts = takeEgressAttempts();
  uninstallEgressGuard();
  expect(
    attempts,
    'テストの中で、ループバックと Unix ソケットのほかへつなごうとしたか、注入したリゾルバを通さずに名前を引こうとした',
  ).toEqual([]);
});
