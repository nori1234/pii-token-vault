// idp の短命な保存先（ADR 0018）。プロセスのメモリに置き、id は鍵サービスの mac(oidc_storage_id) にしてから鍵にする。
//
// 置くもの：oidc-provider の保存物（Session、Interaction、Grant、AuthorizationCode、AccessToken）、PWA のセッション、
// WebAuthn のチャレンジ。どれも数分〜数時間で消える。
//
// - DB に置かないのは、Session と Interaction を、境界（テナントも利用者も）が決まる前に引くため。不変条件8に
//   新しい例外を作らない。本番の永続化（複数のプロセス、再起動）は P1 で決める。
// - 不変条件4：oidc-provider の不透明なトークン（認可コード、アクセストークン）と、セッションの id は、値そのものが id。
//   鍵は MAC にし、payload からも jti を取り除く（ADR 0006 の捨てスパイク2と同じ）。
// - 動的なクライアントは保存しない（Client は常に見つからない）。

import { lengthPrefixed, toBase64Url } from '@pii-token-vault/warifu-core';
import type { Adapter, AdapterPayload } from 'oidc-provider';

export interface StorageMacClient {
  mac(purpose: 'oidc_storage_id', message: Uint8Array): Promise<Uint8Array>;
}

export const STORAGE_LABEL = 'warifu/storage/v1';
/** これを超えたら、期限切れを掃除しても空きがなければ、新しい行を受け付けない（メモリを使い切らせない）。 */
export const MAX_ROWS = 100_000;

export class StorageFullError extends Error {
  override name = 'StorageFullError';
}

interface Row {
  readonly value: unknown;
  readonly expiresAt: number;
}

export class MacMemoryStore {
  readonly #keys: StorageMacClient;
  readonly #now: () => number;
  readonly #rows = new Map<string, Row>();

  constructor(keys: StorageMacClient, now: () => number = Date.now) {
    this.#keys = keys;
    this.#now = now;
  }

  /** `<種類>:<MAC>`。同じ id でも、種類が違えば別の鍵になる。 */
  /** いまの時刻（秒）。 */
  nowSeconds(): number {
    return Math.floor(this.#now() / 1000);
  }

  async keyOf(kind: string, id: string): Promise<string> {
    const mac = await this.#keys.mac('oidc_storage_id', lengthPrefixed([STORAGE_LABEL, kind, id]));
    return `${kind}:${toBase64Url(mac)}`;
  }

  getByKey<T>(key: string): T | undefined {
    const row = this.#rows.get(key);
    if (row === undefined) return undefined;
    if (row.expiresAt <= this.#now()) {
      this.#rows.delete(key);
      return undefined;
    }
    return structuredClone(row.value) as T;
  }

  setByKey(key: string, value: unknown, ttlSeconds: number): void {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) throw new RangeError('期限の形が違う');
    if (!this.#rows.has(key) && this.#rows.size >= MAX_ROWS) {
      this.#sweep();
      if (this.#rows.size >= MAX_ROWS) throw new StorageFullError();
    }
    this.#rows.set(key, {
      value: structuredClone(value),
      expiresAt: this.#now() + ttlSeconds * 1000,
    });
  }

  deleteByKey(key: string): void {
    this.#rows.delete(key);
  }

  async get<T>(kind: string, id: string): Promise<T | undefined> {
    return this.getByKey<T>(await this.keyOf(kind, id));
  }

  async set(kind: string, id: string, value: unknown, ttlSeconds: number): Promise<void> {
    this.setByKey(await this.keyOf(kind, id), value, ttlSeconds);
  }

  /** 読んで消す（チャレンジなど、一度だけ使うもの）。 */
  async take<T>(kind: string, id: string): Promise<T | undefined> {
    const key = await this.keyOf(kind, id);
    const value = this.getByKey<T>(key);
    this.#rows.delete(key);
    return value;
  }

  async delete(kind: string, id: string): Promise<void> {
    this.#rows.delete(await this.keyOf(kind, id));
  }

  /** 種類が kind で、predicate に合う行を消す（パスキーを削除したときのセッションの失効など）。 */
  deleteWhere(kind: string, predicate: (value: unknown) => boolean): number {
    let count = 0;
    for (const [key, row] of this.#rows) {
      if (key.startsWith(`${kind}:`) && predicate(row.value)) {
        this.#rows.delete(key);
        count += 1;
      }
    }
    return count;
  }

  /** 漏えいの確認用。保存している内容をそのまま文字列にする（DB のダンプに当たる）。 */
  dump(): string {
    return JSON.stringify([...this.#rows]);
  }

  #sweep(): void {
    const now = this.#now();
    for (const [key, row] of this.#rows) {
      if (row.expiresAt <= now) this.#rows.delete(key);
    }
  }

  adapterFactory(): (model: string) => Adapter {
    return (model: string) => new MacAdapter(model, this);
  }
}

function scrub(payload: AdapterPayload): AdapterPayload {
  const { jti: _jti, ...rest } = payload;
  return rest;
}

class MacAdapter implements Adapter {
  readonly #model: string;
  readonly #store: MacMemoryStore;

  constructor(model: string, store: MacMemoryStore) {
    this.#model = model;
    this.#store = store;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    if (this.#model === 'Client') throw new Error('動的なクライアントは保存しない');
    const ttl = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 600;
    await this.#store.set(this.#model, id, scrub(payload), ttl);
    if (this.#model === 'Session' && typeof payload.uid === 'string') {
      // findByUid のための索引。uid も MAC にする。
      await this.#store.set('Session.uid', payload.uid, { id }, ttl);
    }
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    if (this.#model === 'Client' || typeof id !== 'string') return undefined;
    const row = await this.#store.get<AdapterPayload>(this.#model, id);
    return row === undefined ? undefined : { ...row, jti: id };
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    if (this.#model !== 'Session' || typeof uid !== 'string') return undefined;
    const index = await this.#store.get<{ id: string }>('Session.uid', uid);
    return index === undefined ? undefined : this.find(index.id);
  }

  async findByUserCode(): Promise<undefined> {
    // デバイスフローを使わない。
    return undefined;
  }

  async consume(id: string): Promise<void> {
    const key = await this.#store.keyOf(this.#model, id);
    const row = this.#store.getByKey<AdapterPayload>(key);
    if (row !== undefined) {
      // 期限は元の行に合わせる必要はない（消費済みの印が付けば、それ以上は使われない）。短く保つ。
      this.#store.setByKey(key, { ...row, consumed: this.#store.nowSeconds() }, 600);
    }
  }

  async destroy(id: string): Promise<void> {
    await this.#store.delete(this.#model, id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    this.#store.deleteWhere(
      this.#model,
      (value) => (value as AdapterPayload | undefined)?.grantId === grantId,
    );
  }
}
