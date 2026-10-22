// 捨てスパイク2：oidc-provider の保存アダプタ（メモリ上）。id を HMAC にしてから保存する。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
//
// 不変条件4：トークン（auth_req_id、アクセストークンなど）を平文で保存しない。
// oidc-provider 9.12.2 の不透明なトークンは、値そのものが id（jti）になる（lib/models/formats/opaque.js の
// getValueAndPayload が `value: token.jti` を返す）。アダプタの upsert(id, payload) には、
// この id がそのまま渡り、payload にも jti として入る。そこで、次のようにする。
// - 保存キーは HMAC-SHA-256(鍵, model + ':' + id)。payload からは jti を取り除き、find で受け取った id を戻す。
// - CIBA の要求（BackchannelAuthenticationRequest）の params から、窓口コード（login_hint_token）、
//   企業が送った binding_message などを取り除く（lib/actions/authorization/ciba.js が
//   `params: ctx.oidc.params.toPlainObject()` をそのまま保存するため）。
// - Client は保存しない。oidc-provider は、静的なクライアントに見つからない client_id を
//   アダプタから探す（lib/models/client.js の Client.find）。動的な登録をしない割符では、常に undefined を返す。
import { createHmac, randomBytes } from 'node:crypto';
import type { Adapter, AdapterPayload } from 'oidc-provider';

/**
 * 保存キーそのものを指す参照。承認の経路で、auth_req_id の平文を持たずに
 * BackchannelAuthenticationRequest を保存し直すために使う。
 * 文字列ではないので、外から届いた値（auth_req_id など）がこれになることはない
 * （lib/models/base_model.js の find は、文字列でない値を受け付けない）。
 */
export class StorageKeyRef {
  readonly key: string;

  constructor(key: string) {
    this.key = key;
  }
}

/** BackchannelAuthenticationRequest の params から取り除く項目。 */
const SCRUBBED_CIBA_PARAMS: readonly string[] = [
  'login_hint_token',
  'binding_message',
  'request_context',
  'client_notification_token',
  'login_hint',
  'id_token_hint',
  'user_code',
];

function epochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export class HmacMemoryStore {
  readonly #key = randomBytes(32);
  readonly #rows = new Map<string, AdapterPayload>();

  storageKey(model: string, id: string): string {
    const mac = createHmac('sha256', this.#key).update(`${model}:${id}`).digest('base64url');
    return `${model}:${mac}`;
  }

  get(key: string): AdapterPayload | undefined {
    const row = this.#rows.get(key);
    return row === undefined ? undefined : structuredClone(row);
  }

  set(key: string, payload: AdapterPayload): void {
    this.#rows.set(key, structuredClone(payload));
  }

  delete(key: string): void {
    this.#rows.delete(key);
  }

  keysWhere(model: string, predicate: (payload: AdapterPayload) => boolean): string[] {
    const keys: string[] = [];
    for (const [key, payload] of this.#rows) {
      if (key.startsWith(`${model}:`) && predicate(payload)) {
        keys.push(key);
      }
    }
    return keys;
  }

  /** 漏えいの確認用。保存している内容をそのまま文字列にする（DB のダンプに当たる）。 */
  dump(): string {
    return JSON.stringify([...this.#rows]);
  }

  adapterFactory(): (model: string) => Adapter {
    return (model: string) => new HmacAdapter(model, this);
  }
}

function scrub(model: string, payload: AdapterPayload): AdapterPayload {
  const { jti: _jti, ...rest } = payload;
  if (model === 'BackchannelAuthenticationRequest' && rest.params !== undefined) {
    const params: Record<string, unknown> = { ...rest.params };
    for (const name of SCRUBBED_CIBA_PARAMS) {
      delete params[name];
    }
    rest.params = params;
  }
  return rest;
}

class HmacAdapter implements Adapter {
  readonly #model: string;
  readonly #store: HmacMemoryStore;

  constructor(model: string, store: HmacMemoryStore) {
    this.#model = model;
    this.#store = store;
  }

  #keyFor(id: string | StorageKeyRef): string {
    if (id instanceof StorageKeyRef) {
      if (!id.key.startsWith(`${this.#model}:`)) {
        throw new Error('保存キーの種類が一致しない');
      }
      return id.key;
    }
    return this.#store.storageKey(this.#model, id);
  }

  async upsert(id: string | StorageKeyRef, payload: AdapterPayload): Promise<void> {
    if (this.#model === 'Client') {
      throw new Error('動的なクライアントは保存しない');
    }
    this.#store.set(this.#keyFor(id), scrub(this.#model, payload));
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    if (this.#model === 'Client' || typeof id !== 'string') {
      return undefined;
    }
    const row = this.#store.get(this.#keyFor(id));
    return row === undefined ? undefined : { ...row, jti: id };
  }

  async findByUid(): Promise<undefined> {
    // Session を使わない（CIBA だけの構成）。M3 で Session を使うときは、uid も HMAC にして索引を持つ。
    return undefined;
  }

  async findByUserCode(): Promise<undefined> {
    // デバイスフローを使わない。
    return undefined;
  }

  async consume(id: string | StorageKeyRef): Promise<void> {
    const key = this.#keyFor(id);
    const row = this.#store.get(key);
    if (row !== undefined) {
      this.#store.set(key, { ...row, consumed: epochSeconds() });
    }
  }

  async destroy(id: string | StorageKeyRef): Promise<void> {
    this.#store.delete(this.#keyFor(id));
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    for (const key of this.#store.keysWhere(this.#model, (row) => row.grantId === grantId)) {
      this.#store.delete(key);
    }
  }
}
