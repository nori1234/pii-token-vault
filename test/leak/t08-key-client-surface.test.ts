// 鍵のクライアントの表面（不変条件3「型には許した操作のメソッドだけ」、不変条件7、plan 11章 テスト8）。
// 静的な点検と、globalSetup の鍵サービスに対する呼び出しで固定する。

import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseTenantId, parseWarifuUserId } from '../../packages/warifu-core/src/ids.ts';
import {
  type CompanyApiKeyClient,
  createCompanyApiKeyClient,
} from '../../packages/warifu-core/src/keys/company-api.ts';
import { createIdpKeyClient, type IdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import {
  createRelayKeyClient,
  type RelayKeyClient,
} from '../../packages/warifu-core/src/keys/relay.ts';
import { keysvcConnection } from '../setup/keys.ts';
import { importsOf, packageSourceFiles, REPO_ROOT, read, stripComments } from '../setup/source.ts';

// 型の検査だけに使う（呼ばない）。@ts-expect-error が誤りにならなければ、npm run typecheck が失敗する。
function typeOnly(idp: IdpKeyClient, companyApi: CompanyApiKeyClient, relay: RelayKeyClient) {
  const userId = parseWarifuUserId(randomUUID());
  // @ts-expect-error idp は連絡先を復号できない
  void idp.decryptContact({ userId, ciphertext: new Uint8Array() });
  // @ts-expect-error company-api は連絡先を暗号化できない
  void companyApi.encryptContact({ userId, plaintext: new Uint8Array() });
  // @ts-expect-error relay は別名を導けない
  void relay.deriveAlias({ tenantId: parseTenantId(randomUUID()), userId, generation: 1 });
  // @ts-expect-error relay は ID トークンに署名できない（署名は DKIM と ARC の signDkim だけ）
  void relay.sign('id_token', new Uint8Array());
  // @ts-expect-error relay だけの MAC の用途は、idp の型にない
  void idp.mac('message_id', new Uint8Array());
  // @ts-expect-error idp は DKIM の鍵で署名できない
  void idp.signDkim(new Uint8Array());
  // @ts-expect-error sub の導出は idp だけ
  void companyApi.mac('pairwise_sub', new Uint8Array());
  // @ts-expect-error 確認コードの MAC は idp だけ
  void relay.mac('email_verify_code', new Uint8Array());
  // @ts-expect-error company-api は ID トークンに署名できない（tenant_jwt と set だけ。ADR 0022）
  void companyApi.sign('id_token', new Uint8Array());
  // @ts-expect-error idp は SET に署名できない
  void idp.sign('set', new Uint8Array());
  // @ts-expect-error company-api は操作ごとの承認に署名できない（ADR 0026）
  void companyApi.sign('op_approval', new Uint8Array());
  // @ts-expect-error 窓口の ID の MAC は company-api だけ（ADR 0026）
  void idp.mac('desk_id', new Uint8Array());
}

const EXPECTED_METHODS = {
  idp: ['deriveAlias', 'encryptContact', 'mac', 'publicKeys', 'sign'],
  'company-api': ['deriveAlias', 'mac', 'publicKeys', 'sign'],
  relay: [
    'decryptContact',
    'decryptQueueItem',
    'dkimPublicKey',
    'encryptQueueItem',
    'mac',
    'signDkim',
  ],
};

describe('漏えい：鍵のクライアントの表面（plan 11章 テスト8）', () => {
  it('型にないメソッドと用途は、型の検査で誤りになる', () => {
    // 攻撃者が持っている情報：なし（不変条件3「型には許した操作だけ」の固定。侵害されたサービスのコードが、
    //                       型の上で decrypt などを呼べない）
    // 試す経路：typeOnly の中で、idp の decryptContact、company-api の encryptContact、relay の deriveAlias と
    //           sign、idp の mac('message_id') と signDkim、company-api の mac('pairwise_sub')、relay の
    //           mac('email_verify_code') を、型の誤りを期待する注記付きで書く
    // 期待する結果：型の検査で誤りになる（ならなければ npm run typecheck が失敗する）。typeOnly は呼ばない
    // plan 11章：テスト8
    expect(typeof typeOnly).toBe('function');
  });

  it('各クライアントの実体のメソッドは、期待の表と一致する', () => {
    // 攻撃者が持っている情報：なし（不変条件3の固定。侵害されたサービスのコードが、型の上でも実体でも
    //                       許されない操作を呼べない）
    // 試す経路：各クライアントの Object.keys を、テストの中の期待の表と比べる。凍結されていることも確かめる
    // 期待する結果：表と一致する
    // plan 11章：テスト8
    const clients = {
      idp: createIdpKeyClient(keysvcConnection('idp')),
      'company-api': createCompanyApiKeyClient(keysvcConnection('company-api')),
      relay: createRelayKeyClient(keysvcConnection('relay')),
    };
    for (const [name, client] of Object.entries(clients)) {
      expect(Object.keys(client).sort()).toEqual(EXPECTED_METHODS[name as keyof typeof clients]);
      expect(Object.isFrozen(client)).toBe(true);
    }
  });

  it('クライアントのすべてのメソッドが、鍵サービスの能力の表で許される', async () => {
    // 攻撃者が持っている情報：なし（クライアントと鍵サービスの表が食い違っていないことの固定）
    // 試す経路：各クライアントのすべてのメソッドを、globalSetup の鍵サービスに対して呼ぶ
    // 期待する結果：すべて成功する（403 になるメソッドがない）。relay は idp が暗号化した連絡先を復号できる
    // plan 11章：テスト8
    const idp = createIdpKeyClient(keysvcConnection('idp'));
    const companyApi = createCompanyApiKeyClient(keysvcConnection('company-api'));
    const relay = createRelayKeyClient(keysvcConnection('relay'));
    const userId = parseWarifuUserId(randomUUID());
    const tenantId = parseTenantId(randomUUID());
    const plaintext = new Uint8Array(randomBytes(24));
    const message = new Uint8Array([1, 2, 3]);

    const ciphertext = await idp.encryptContact({ userId, plaintext });
    expect(await relay.decryptContact({ userId, ciphertext })).toEqual(plaintext);
    for (const purpose of ['alias_lookup', 'audit_chain'] as const) {
      const a = await idp.mac(purpose, message);
      expect(a.byteLength).toBe(32);
      expect(await companyApi.mac(purpose, message)).toEqual(a);
      expect(await relay.mac(purpose, message)).toEqual(a);
    }
    // idp だけの用途。用途ごとに鍵が違う（同じ入力でも MAC が違う）。
    const idpOnly = [
      'pairwise_sub',
      'oidc_storage_id',
      'email_verify_code',
      'approval_challenge',
    ] as const;
    const macs = [
      await idp.mac('alias_lookup', message),
      await idp.mac('audit_chain', message),
      ...(await Promise.all(idpOnly.map((purpose) => idp.mac(purpose, message)))),
    ].map((mac) => Buffer.from(mac).toString('hex'));
    expect(new Set(macs).size).toBe(macs.length);
    const alias = await idp.deriveAlias({ tenantId, userId, generation: 1 });
    expect(await companyApi.deriveAlias({ tenantId, userId, generation: 1 })).toBe(alias);
    expect((await idp.sign('id_token', message)).signature.byteLength).toBe(64);
    expect(await idp.publicKeys('id_token')).toHaveLength(1);
    const opApproval = await idp.sign('op_approval', message);
    expect(opApproval.signature.byteLength).toBe(64);
    expect((await idp.publicKeys('op_approval'))[0]?.kid).toBe(opApproval.kid);
    // company-api だけの用途（窓口の ID。ADR 0026）。用途ごとに鍵が違う。
    const deskMacs = (
      await Promise.all(
        (['desk_id', 'desk_lookup', 'alias_lookup'] as const).map((purpose) =>
          companyApi.mac(purpose, message),
        ),
      )
    ).map((mac) => Buffer.from(mac).toString('hex'));
    expect(new Set(deskMacs).size).toBe(3);
    // ES256 の鍵は、用途ごとに別（ID トークン、操作ごとの承認、テナントの JWT、SET。ADR 0022、ADR 0026）。
    const kids = new Set([(await idp.publicKeys('id_token'))[0]?.kid, opApproval.kid]);
    for (const keyId of ['tenant_jwt', 'set'] as const) {
      const signed = await companyApi.sign(keyId, message);
      expect(signed.signature.byteLength).toBe(64);
      const [key] = await companyApi.publicKeys(keyId);
      expect(key?.kid).toBe(signed.kid);
      kids.add(signed.kid);
    }
    expect(kids.size).toBe(4);
    const queueItemId = randomUUID();
    const queued = await relay.encryptQueueItem({ queueItemId, plaintext: message });
    expect(await relay.decryptQueueItem({ queueItemId, ciphertext: queued })).toEqual(message);
    // relay だけの用途。ほかの用途の鍵と違う。
    const relayOnly = ['relay_replay', 'relay_thread', 'message_id'] as const;
    const relayMacs = (await Promise.all(relayOnly.map((purpose) => relay.mac(purpose, message))))
      .concat([await relay.mac('alias_lookup', message)])
      .map((mac) => Buffer.from(mac).toString('hex'));
    expect(new Set(relayMacs).size).toBe(relayMacs.length);
    const dkim = await relay.signDkim(message);
    expect(dkim.signature.byteLength).toBe(256);
    expect((await relay.dkimPublicKey()).kid).toBe(dkim.kid);
  });

  it('relay の部品を import できるのは relay だけ', () => {
    // 攻撃者が持っている情報：なし（静的な固定。復号のクライアントと解決関数の入口を、relay の外に広げない）
    // 試す経路：packages/*/src の import から、keys/relay と db/relay を指すものを探す
    // 期待する結果：packages/relay/ の中だけ（M2 では0件）。warifu-core の中の相互の import もない
    // plan 11章：テスト8
    const offenders: string[] = [];
    for (const file of packageSourceFiles()) {
      if (file.startsWith('packages/relay/')) continue;
      for (const info of importsOf(read(file))) {
        if (/(^|\/)(keys|db)\/relay(\.ts)?$/.test(info.specifier)) offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('ほかのパッケージから、warifu-core の内部の部品を読まない', () => {
    // 攻撃者が持っている情報：なし（静的な固定。汎用の call と UDS のクライアントを、外から使わせない）
    // 試す経路：warifu-core 以外の packages/*/src の import に、warifu-core/src/ を含むものを探す。
    //           warifu-core の exports に transport、common、internal がないことを確かめる
    // 期待する結果：0件。exports にない
    // plan 11章：テスト8
    for (const file of packageSourceFiles()) {
      if (file.startsWith('packages/warifu-core/')) continue;
      for (const info of importsOf(read(file))) {
        expect(info.specifier).not.toMatch(/warifu-core\/src\//);
        expect(info.specifier).not.toMatch(/^\.\.\/\.\.\/warifu-core/);
      }
    }
    const pkg = JSON.parse(
      readFileSync(join(REPO_ROOT, 'packages/warifu-core/package.json'), 'utf8'),
    ) as { exports: Record<string, string> };
    for (const [key, target] of Object.entries(pkg.exports)) {
      expect(`${key} ${target}`).not.toMatch(/transport|common|internal/);
    }
  });

  it('UDS のクライアントは、ソケットのパスにしかつながらない', () => {
    // 攻撃者が持っている情報：なし（lint の例外が広がっていないことの固定。不変条件7）
    // 試す経路：uds-client.ts のコメントを除いた中身を調べる。node:http の request を import するファイルを探す
    // 期待する結果：request( の呼び出しは1つで socketPath を含む。host、hostname、port、lookup、agent、
    //               createConnection、localAddress、family が出てこない。request を import するのはこのファイルだけ
    // plan 11章：テスト8
    const file = 'packages/warifu-core/src/internal/uds-client.ts';
    const code = stripComments(read(file));
    expect(code.match(/\brequest\(/g)).toHaveLength(1);
    const start = code.indexOf('request(');
    const options = code.slice(start, code.indexOf('(res)', start));
    expect(options).toContain('socketPath');
    expect(options).toContain("method: 'POST'");
    for (const word of [
      'host',
      'hostname',
      'port',
      'lookup',
      'agent',
      'createConnection',
      'localAddress',
      'family',
      'url',
      'URL',
    ]) {
      expect(code).not.toMatch(new RegExp(`\\b${word}\\b`));
    }
    const importers = packageSourceFiles().filter((f) =>
      importsOf(read(f)).some(
        (info) =>
          (info.specifier === 'node:http' || info.specifier === 'http') &&
          info.names.some(
            (name) =>
              ![
                'createServer',
                'Server',
                'IncomingMessage',
                'ServerResponse',
                'STATUS_CODES',
                'RequestListener',
              ].includes(name),
          ),
      ),
    );
    expect(importers).toEqual([file]);
  });

  it('biome.json の例外は、uds-client.ts の1ファイルで request だけ', () => {
    // 攻撃者が持っている情報：なし（overrides を広げる変更の検出。不変条件7・9）
    // 試す経路：各 override が node:http の request、node:net、node:crypto を許すかを計算する
    // 期待する結果：uds-client の override だけが request を許し、includes はそのファイル1つ。その paths は
    //               ルートのキーをすべて含む（node:crypto も禁止）。ルートの node:http は request を許さない。
    //               uds-client の override は、warifu-core と keysvc の override より後ろ
    // plan 11章：テスト8
    type Paths = Record<string, string | { allowImportNames?: string[] }>;
    type Override = {
      includes: string[];
      linter?: {
        rules?: { style?: { noRestrictedImports?: { options?: { paths?: Paths } } | string } };
      };
    };
    const biome = JSON.parse(readFileSync(join(REPO_ROOT, 'biome.json'), 'utf8')) as {
      linter: { rules: { style: { noRestrictedImports: { options: { paths: Paths } } } } };
      overrides: Override[];
    };
    const rootPaths = biome.linter.rules.style.noRestrictedImports.options.paths;
    const allowsRequest = (paths: Paths | undefined) => {
      const http = paths?.['node:http'];
      return typeof http === 'object' && (http.allowImportNames ?? []).includes('request');
    };
    expect(allowsRequest(rootPaths)).toBe(false);
    const withRequest = biome.overrides
      .map((o, index) => ({ o, index }))
      .filter(({ o }) => {
        const rule = o.linter?.rules?.style?.noRestrictedImports;
        return typeof rule === 'object' && allowsRequest(rule.options?.paths);
      });
    expect(withRequest).toHaveLength(1);
    const uds = withRequest[0];
    expect(uds?.o.includes).toEqual(['packages/warifu-core/src/internal/uds-client.ts']);
    const rule = uds?.o.linter?.rules?.style?.noRestrictedImports;
    const udsPaths = typeof rule === 'object' ? (rule.options?.paths ?? {}) : {};
    for (const key of Object.keys(rootPaths)) expect(Object.keys(udsPaths)).toContain(key);
    expect(udsPaths['node:crypto']).toBeDefined();
    expect(udsPaths['node:net']).toBeDefined();
    const coreIndex = biome.overrides.findIndex((o) =>
      o.includes.includes('packages/warifu-core/**'),
    );
    expect(coreIndex).toBeGreaterThanOrEqual(0);
    expect(uds?.index).toBeGreaterThan(coreIndex);
  });
});
