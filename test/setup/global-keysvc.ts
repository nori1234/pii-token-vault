// Vitest の globalSetup。鍵サービスを1つ起動し、終わったら止める（ADR 0013）。
// DB を使うテストは、この1つを使う。ワーカーの DB はファイルの間で共有されるので、監査ログのチェーンを
// 全体で検証するには、実行全体で鍵が同じでなければならない。資格情報は、ワーカーへメモリで渡るだけ。

import type { TestProject } from 'vitest/node';
import type { KeysvcCaller } from '../../packages/warifu-core/src/keys/protocol.ts';
import { startKeysvc } from '../../scripts/keysvc-up.ts';

export interface ProvidedKeysvc {
  socketPath: string;
  credentials: Record<KeysvcCaller, string>;
}

declare module 'vitest' {
  export interface ProvidedContext {
    keysvc: ProvidedKeysvc;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const keysvc = await startKeysvc();
  project.provide('keysvc', {
    socketPath: keysvc.socketPath,
    credentials: { ...keysvc.credentials },
  });
  return async () => {
    await keysvc.stop();
  };
}
