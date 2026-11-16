// demo-rp の保存（メモリ）。企業の DB の代わり。割符の DB は使わない（spec 04）。
//
// 変更は、transaction の中でだけ行う。transaction は、状態の写しの上で動き、最後まで成功したときだけ、まとめて確定する。
// 途中で例外が出たら、何も残さない。同時に来た transaction は、1つずつ順に動かす。
// 本番の企業は、DB のトランザクション（と行のロック）で同じことをする（spec 02 の RP-09）。

export interface StoreOptions {
  /** 確定の直前に呼ぶ（障害の注入。テスト用）。例外を投げると、その transaction は何も残さない。 */
  readonly beforeCommit?: () => void;
}

export class MemoryStore<S> {
  #state: S;
  #tail: Promise<unknown> = Promise.resolve();
  readonly #beforeCommit: (() => void) | undefined;

  constructor(initial: S, options: StoreOptions = {}) {
    this.#state = structuredClone(initial);
    this.#beforeCommit = options.beforeCommit;
  }

  /** 状態の写しの上で fn を動かし、成功したら確定する。fn の中で受け取った写しは、外に持ち出さない。 */
  transaction<T>(fn: (draft: S) => T | Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const draft = structuredClone(this.#state);
      const result = await fn(draft);
      this.#beforeCommit?.();
      this.#state = draft;
      // 呼び出し元が、確定した状態を後から書き換えられないよう、結果も写しで返す。
      return structuredClone(result);
    };
    const next = this.#tail.then(run, run);
    this.#tail = next.catch(() => undefined);
    return next;
  }

  /** 読むだけ（写しを返す）。 */
  read<T>(fn: (state: S) => T): Promise<T> {
    return this.transaction((draft) => fn(draft));
  }
}
