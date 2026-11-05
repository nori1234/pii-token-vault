// 利用者ごとに、プロセスの中で処理を直列にする（ADR 0027 の O-76）。
//
// 協力者の資格（PRN-87）は、協力者の範囲の値（パスキーを足した時刻、回復した時刻）で決まる。一方、承認の記録は、
// 持ち主の範囲（回復の記録）に書く。DB の境界は入れ子にしないので（不変条件8）、資格の判定と承認の記録は、1つの
// トランザクションにまとめられない。そこで、協力者の資格を変える書き込み（パスキーの追加、回復の成立）と、協力者の
// 承認（資格の判定から記録まで）を、同じ利用者の中で、この直列化に通す。
//
// 効くのはプロセスの中だけ。P0 の idp は1つのプロセスで動く（回復の結び付けと招待も、プロセスのメモリに置く。
// ADR 0018 の O-10）。複数のプロセスにするときは、保存先の永続化と一緒に P1 で決め直す。
// 直列にした処理の中では、ほかの利用者の直列化を待たない（待ち合わせが輪にならない）。

import type { WarifuUserId } from '@pii-token-vault/warifu-core';

export interface UserSerial {
  /** 同じ利用者の fn を、呼ばれた順に1つずつ実行する。前の fn が失敗しても、次の fn は実行する。 */
  run<T>(userId: WarifuUserId, fn: () => Promise<T>): Promise<T>;
}

export function createUserSerial(): UserSerial {
  const tails = new Map<string, Promise<void>>();
  return {
    run<T>(userId: WarifuUserId, fn: () => Promise<T>): Promise<T> {
      const previous = tails.get(userId) ?? Promise.resolve();
      const result = previous.then(fn);
      const tail: Promise<void> = result
        .then(
          () => undefined,
          () => undefined,
        )
        .then(() => {
          // 後に続く処理がなければ、利用者の項目を消す（メモリを残さない）。
          if (tails.get(userId) === tail) tails.delete(userId);
        });
      tails.set(userId, tail);
      return result;
    },
  };
}
