// 鍵サービスの能力の表（不変条件3、plan 11章 テスト8）。
// このファイルは自分の鍵サービスを起動する（出力を、ほかのファイルの要求と混ぜないため）。DB は使わない。
// 期待の表はテストの中に書き、packages/keysvc/src/acl.ts から作らない（表の誤りを、表で確かめないため）。

import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type KeysvcProcess, startKeysvc } from '../../scripts/keysvc-up.ts';
import { rawKeysvcCall } from '../setup/keys.ts';

type Caller = 'idp' | 'relay' | 'company-api';
type Combo =
  | 'encrypt/contact'
  | 'encrypt/relay_queue'
  | 'decrypt/contact'
  | 'decrypt/relay_queue'
  | 'mac/alias_lookup'
  | 'mac/audit_chain'
  | 'mac/pairwise_sub'
  | 'mac/oidc_storage_id'
  | 'mac/email_verify_code'
  | 'mac/approval_challenge'
  | 'mac/desk_id'
  | 'mac/desk_lookup'
  | 'mac/relay_replay'
  | 'mac/relay_thread'
  | 'mac/message_id'
  | 'derive_alias'
  | 'sign/id_token'
  | 'public_keys/id_token'
  | 'sign/dkim'
  | 'public_keys/dkim'
  | 'sign/tenant_jwt'
  | 'public_keys/tenant_jwt'
  | 'sign/set'
  | 'public_keys/set'
  | 'sign/op_approval'
  | 'public_keys/op_approval';

const COMBOS: readonly Combo[] = [
  'encrypt/contact',
  'encrypt/relay_queue',
  'decrypt/contact',
  'decrypt/relay_queue',
  'mac/alias_lookup',
  'mac/audit_chain',
  'mac/pairwise_sub',
  'mac/oidc_storage_id',
  'mac/email_verify_code',
  'mac/approval_challenge',
  'mac/desk_id',
  'mac/desk_lookup',
  'mac/relay_replay',
  'mac/relay_thread',
  'mac/message_id',
  'derive_alias',
  'sign/id_token',
  'public_keys/id_token',
  'sign/dkim',
  'public_keys/dkim',
  'sign/tenant_jwt',
  'public_keys/tenant_jwt',
  'sign/set',
  'public_keys/set',
  'sign/op_approval',
  'public_keys/op_approval',
];

// plan 8章と spec 04 2章の表を、操作と対象の単位にしたもの。ここにないものは、すべて 403。
const ALLOWED: Readonly<Record<Caller, readonly Combo[]>> = {
  idp: [
    'encrypt/contact',
    'mac/alias_lookup',
    'mac/audit_chain',
    'mac/pairwise_sub',
    'mac/oidc_storage_id',
    'mac/email_verify_code',
    'mac/approval_challenge',
    'derive_alias',
    'sign/id_token',
    'public_keys/id_token',
    'sign/op_approval',
    'public_keys/op_approval',
  ],
  'company-api': [
    'mac/alias_lookup',
    'mac/audit_chain',
    'mac/desk_id',
    'mac/desk_lookup',
    'derive_alias',
    'sign/tenant_jwt',
    'public_keys/tenant_jwt',
    'sign/set',
    'public_keys/set',
  ],
  relay: [
    'encrypt/relay_queue',
    'decrypt/contact',
    'decrypt/relay_queue',
    'mac/alias_lookup',
    'mac/audit_chain',
    'mac/relay_replay',
    'mac/relay_thread',
    'mac/message_id',
    'sign/dkim',
    'public_keys/dkim',
  ],
};

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');
const userId = randomUUID();
const tenantId = randomUUID();
const queueItemId = randomUUID();
const contactPlaintext = `${b64(randomBytes(9))}@example.com`;

let keysvc: KeysvcProcess;
let contactCiphertext: string;
let queueCiphertext: string;

function bodyFor(combo: Combo): { op: string; body: unknown } {
  switch (combo) {
    case 'encrypt/contact':
      return {
        op: 'encrypt',
        body: {
          keyId: 'contact',
          plaintext: b64(contactPlaintext),
          context: { field: 'email', user_id: userId },
        },
      };
    case 'encrypt/relay_queue':
      return {
        op: 'encrypt',
        body: {
          keyId: 'relay_queue',
          plaintext: b64('queued'),
          context: { queue_item_id: queueItemId },
        },
      };
    case 'decrypt/contact':
      return {
        op: 'decrypt',
        body: {
          keyId: 'contact',
          ciphertext: contactCiphertext,
          context: { field: 'email', user_id: userId },
        },
      };
    case 'decrypt/relay_queue':
      return {
        op: 'decrypt',
        body: {
          keyId: 'relay_queue',
          ciphertext: queueCiphertext,
          context: { queue_item_id: queueItemId },
        },
      };
    case 'mac/alias_lookup':
      return { op: 'mac', body: { purpose: 'alias_lookup', message: b64('m') } };
    case 'mac/audit_chain':
      return { op: 'mac', body: { purpose: 'audit_chain', message: b64('m') } };
    case 'mac/pairwise_sub':
      return { op: 'mac', body: { purpose: 'pairwise_sub', message: b64('m') } };
    case 'mac/oidc_storage_id':
      return { op: 'mac', body: { purpose: 'oidc_storage_id', message: b64('m') } };
    case 'mac/email_verify_code':
      return { op: 'mac', body: { purpose: 'email_verify_code', message: b64('m') } };
    case 'mac/approval_challenge':
      return { op: 'mac', body: { purpose: 'approval_challenge', message: b64('m') } };
    case 'mac/desk_id':
      return { op: 'mac', body: { purpose: 'desk_id', message: b64('m') } };
    case 'mac/desk_lookup':
      return { op: 'mac', body: { purpose: 'desk_lookup', message: b64('m') } };
    case 'mac/relay_replay':
      return { op: 'mac', body: { purpose: 'relay_replay', message: b64('m') } };
    case 'mac/relay_thread':
      return { op: 'mac', body: { purpose: 'relay_thread', message: b64('m') } };
    case 'mac/message_id':
      return { op: 'mac', body: { purpose: 'message_id', message: b64('m') } };
    case 'derive_alias':
      return { op: 'derive_alias', body: { tenantId, userId, generation: 1 } };
    case 'sign/id_token':
      return { op: 'sign', body: { keyId: 'id_token', message: b64('header.payload') } };
    case 'public_keys/id_token':
      return { op: 'public_keys', body: { keyId: 'id_token' } };
    case 'sign/dkim':
      return { op: 'sign', body: { keyId: 'dkim', message: b64('dkim-signature:') } };
    case 'public_keys/dkim':
      return { op: 'public_keys', body: { keyId: 'dkim' } };
    case 'sign/tenant_jwt':
      return { op: 'sign', body: { keyId: 'tenant_jwt', message: b64('header.payload') } };
    case 'public_keys/tenant_jwt':
      return { op: 'public_keys', body: { keyId: 'tenant_jwt' } };
    case 'sign/set':
      return { op: 'sign', body: { keyId: 'set', message: b64('header.payload') } };
    case 'public_keys/set':
      return { op: 'public_keys', body: { keyId: 'set' } };
    case 'sign/op_approval':
      return { op: 'sign', body: { keyId: 'op_approval', message: b64('header.payload') } };
    case 'public_keys/op_approval':
      return { op: 'public_keys', body: { keyId: 'op_approval' } };
  }
}

function call(caller: Caller | undefined, op: string, body: unknown, authorization?: string) {
  return rawKeysvcCall({
    socketPath: keysvc.socketPath,
    authorization:
      authorization ?? (caller === undefined ? undefined : `Bearer ${keysvc.credentials[caller]}`),
    op,
    body,
  });
}

beforeAll(async () => {
  keysvc = await startKeysvc();
  const contact = await call('idp', 'encrypt', bodyFor('encrypt/contact').body);
  contactCiphertext = JSON.parse(contact.body).ciphertext;
  const queue = await call('relay', 'encrypt', bodyFor('encrypt/relay_queue').body);
  queueCiphertext = JSON.parse(queue.body).ciphertext;
});

afterAll(async () => {
  await keysvc.stop();
});

/** 鍵サービスは応答を送った後にログを書くので、出力が増えなくなるまで待つ。 */
async function settle(): Promise<void> {
  let last = -1;
  while (keysvc.output().length !== last) {
    last = keysvc.output().length;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

const MATRIX = (['idp', 'relay', 'company-api'] as const).flatMap((caller) =>
  COMBOS.map((combo) => ({ caller, combo, allowed: ALLOWED[caller].includes(combo) })),
);

describe('漏えい：鍵サービスの能力の表（plan 11章 テスト8）', () => {
  it.each(MATRIX)(
    '$caller が $combo を呼ぶ → 許可は $allowed',
    async ({ caller, combo, allowed }) => {
      // 攻撃者が持っている情報：侵害した1つのサービス（idp、company-api、relay）の鍵サービスの資格情報（ATK-07）
      // 試す経路：自分の資格情報で、6つの操作とすべての対象を、正しい形の本文で呼ぶ
      // 期待する結果：能力の表で ○ の組み合わせだけが 200。ほかは、すべて 403 {"error":"forbidden"}
      // plan 11章：テスト8
      const { op, body } = bodyFor(combo);
      const response = await call(caller, op, body);
      if (allowed) {
        expect(response.status).toBe(200);
      } else {
        expect(response.status).toBe(403);
        expect(response.body).toBe('{"error":"forbidden"}');
      }
    },
  );

  it('idp の資格情報では、連絡先の暗号文を復号できない', async () => {
    // 攻撃者が持っている情報：侵害した idp の資格情報（ATK-07、TH-61）と、DB から読んだ暗号文と利用者 ID
    // 試す経路：idp の資格情報で、正しい文脈の /v1/decrypt（contact）を呼ぶ
    // 期待する結果：403。平文は返らない。鍵サービスの出力に keysvc.denied が1行あり、暗号文・平文・資格情報は出ない
    // plan 11章：テスト8
    const deniedLines = () =>
      keysvc
        .output()
        .split('\n')
        .filter((line) => line.includes('keysvc.denied')).length;
    await settle();
    const before = deniedLines();
    const response = await call('idp', 'decrypt', bodyFor('decrypt/contact').body);
    expect(response.status).toBe(403);
    expect(response.body).not.toContain(b64(contactPlaintext));
    await settle();
    const output = keysvc.output();
    expect(deniedLines() - before).toBe(1);
    expect(output).not.toContain(contactCiphertext);
    expect(output).not.toContain(contactPlaintext);
    expect(output).not.toContain(b64(contactPlaintext));
    expect(output).not.toContain(keysvc.credentials.idp.split('.')[1]);
  });

  it.each(['export_key', 'get_key', 'generate_data_key', 're_encrypt', 'list_keys'])(
    '表にない操作 %s は、どのサービスでも 403（404 ではない）',
    async (op) => {
      // 攻撃者が持っている情報：侵害した任意のサービスの資格情報（ATK-07）
      // 試す経路：鍵を取り出す操作や、データ鍵を作る操作（表にないもの）を呼ぶ
      // 期待する結果：すべて 403。操作があるかどうかも区別させない
      // plan 11章：テスト8
      for (const caller of ['idp', 'relay', 'company-api'] as const) {
        const response = await call(caller, op, { keyId: 'contact' });
        expect(response.status).toBe(403);
        expect(response.body).toBe('{"error":"forbidden"}');
      }
    },
  );

  it.each([
    ['mac', { purpose: 'desk_code', message: b64('m') }],
    ['mac', { purpose: 'sub', message: b64('m') }],
    ['encrypt', { keyId: 'alias_derive', plaintext: b64('x'), context: {} }],
    ['sign', { keyId: 'set', message: b64('x') }],
    ['sign', { keyId: 'tenant_jwt', message: b64('x') }],
    ['mac', { purpose: 'desk_id', message: b64('m') }],
    ['mac', { purpose: 'desk_lookup', message: b64('m') }],
    ['mac', { message: b64('m') }],
  ])('未知・未来の対象、ほかのサービスの鍵（%s %j）は 403', async (op, body) => {
    // 攻撃者が持っている情報：侵害した idp の資格情報（ATK-07。mac、encrypt、sign の権限を持つ）
    // 試す経路：まだ作っていない用途や鍵（窓口コード、sub、別名の導出鍵）と、company-api の鍵（SET、テナントの
    //           JWT。ADR 0022）と MAC の用途（窓口の ID。ADR 0026）を対象にして呼ぶ
    // 期待する結果：すべて 403
    // plan 11章：テスト8
    const response = await call('idp', op, body);
    expect(response.status).toBe(403);
  });

  it('relay は、連絡先の暗号文を作れない', async () => {
    // 攻撃者が持っている情報：侵害した relay（ATK-07、TH-62）
    // 試す経路：relay の資格情報で encrypt（contact）を呼び、利用者の連絡先の暗号文を偽造しようとする
    // 期待する結果：403
    // plan 11章：テスト8
    const response = await call('relay', 'encrypt', bodyFor('encrypt/contact').body);
    expect(response.status).toBe(403);
  });

  it('資格情報を持たないサービス（sender など）は、何も呼べない', async () => {
    // 攻撃者が持っている情報：侵害した sender（ATK-07、TH-64）。鍵サービスの資格情報を持たない
    // 試す経路：Authorization なし、`sender.<乱数>`、`Bearer <乱数>` で mac を呼ぶ
    // 期待する結果：すべて 403
    // plan 11章：テスト8
    const body = bodyFor('mac/alias_lookup').body;
    for (const authorization of [
      undefined,
      `Bearer sender.${b64(randomBytes(32))}`,
      `Bearer ${b64(randomBytes(32))}`,
    ]) {
      const response =
        authorization === undefined
          ? await call(undefined, 'mac', body)
          : await call(undefined, 'mac', body, authorization);
      expect(response.status).toBe(403);
    }
  });
});
