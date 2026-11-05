// 利用者ごとの直列化（ADR 0027 の O-76）。同じ利用者の処理は呼ばれた順に1つずつ、別の利用者の処理は並べて実行し、
// 前の処理が失敗しても次の処理を止めない。

import { describe, expect, it } from 'vitest';
import type { WarifuUserId } from '../../warifu-core/src/ids.ts';
import { createUserSerial } from '../src/user-serial.ts';

const A = '00000000-0000-4000-8000-00000000000a' as WarifuUserId;
const B = '00000000-0000-4000-8000-00000000000b' as WarifuUserId;

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe('createUserSerial', () => {
  it('同じ利用者の処理は、前の処理が終わるまで始めない', async () => {
    const serial = createUserSerial();
    const events: string[] = [];
    const gate = deferred();
    const first = serial.run(A, async () => {
      events.push('first:start');
      await gate.promise;
      events.push('first:end');
      return 1;
    });
    const second = serial.run(A, async () => {
      events.push('second:start');
      return 2;
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(events).toEqual(['first:start']);
    gate.resolve();
    expect(await Promise.all([first, second])).toEqual([1, 2]);
    expect(events).toEqual(['first:start', 'first:end', 'second:start']);
  });

  it('別の利用者の処理は待たない', async () => {
    const serial = createUserSerial();
    const gate = deferred();
    const blocked = serial.run(A, () => gate.promise);
    expect(await serial.run(B, async () => 'b')).toBe('b');
    gate.resolve();
    await blocked;
  });

  it('前の処理が失敗しても、その失敗は呼んだ側にだけ返り、次の処理は実行する', async () => {
    const serial = createUserSerial();
    const failed = serial.run(A, async () => {
      throw new Error('失敗');
    });
    const next = serial.run(A, async () => 'next');
    await expect(failed).rejects.toThrow('失敗');
    expect(await next).toBe('next');
  });
});
