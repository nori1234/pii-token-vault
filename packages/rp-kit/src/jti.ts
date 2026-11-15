// 承認の JWT の jti を、一度しか使わせないための置き場所（RP-12）。企業は、複数のサーバーで動かすなら、共有の置き場所
// （DB など）で同じ形を作って渡す。値は jti だけで、トークンそのものは置かない。

export interface JtiStore {
  /** まだ使っていなければ使ったことにして true。使い済みなら false。expiresAt（ミリ秒）を過ぎたら忘れてよい。 */
  use(jti: string, expiresAt: number): Promise<boolean>;
}

/** 1つのプロセスの中だけの置き場所（参照実装とテスト用）。 */
export function memoryJtiStore(now: () => number = Date.now): JtiStore {
  const seen = new Map<string, number>();
  return {
    async use(jti, expiresAt) {
      const current = now();
      for (const [key, until] of seen) if (until <= current) seen.delete(key);
      if (seen.has(jti)) return false;
      seen.set(jti, expiresAt);
      return true;
    },
  };
}
