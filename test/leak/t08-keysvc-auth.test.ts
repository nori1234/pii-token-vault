// 鍵サービスの資格情報（不変条件3、plan 11章 テスト8）。
// このファイルは自分の鍵サービスを起動する。DB は使わない。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type KeysvcProcess, startKeysvc } from '../../scripts/keysvc-up.ts';
import { rawKeysvcCall, startKeysvcExpectingFailure } from '../setup/keys.ts';

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');
const secret = () => b64(randomBytes(32));
const MAC_BODY = { purpose: 'alias_lookup', message: b64('m') };

let keysvc: KeysvcProcess;

function call(authorization: string | undefined, op = 'mac', body: unknown = MAC_BODY) {
  return rawKeysvcCall({ socketPath: keysvc.socketPath, authorization, op, body });
}

function secretOf(service: 'idp' | 'relay' | 'company-api'): string {
  return keysvc.credentials[service].split('.')[1] ?? '';
}

beforeAll(async () => {
  keysvc = await startKeysvc();
});

afterAll(async () => {
  await keysvc.stop();
});

describe('漏えい：鍵サービスの資格情報（plan 11章 テスト8）', () => {
  it('relay の秘密で idp を名乗っても、idp の能力を得られない', async () => {
    // 攻撃者が持っている情報：relay の資格情報（ATK-07。relay の侵害）
    // 試す経路：`idp.<relay の秘密>` で derive_alias を呼び、idp の能力を得ようとする
    // 期待する結果：403
    // plan 11章：テスト8
    const response = await call(`Bearer idp.${secretOf('relay')}`, 'derive_alias', {
      tenantId: '8f14e45f-ceea-467a-9575-0c1f2e3d4b5a',
      userId: '8f14e45f-ceea-467a-9575-0c1f2e3d4b5a',
      generation: 1,
    });
    expect(response.status).toBe(403);
  });

  it.each([
    ['Basic', `Basic ${b64('idp:x')}`],
    ['区切りなし', `Bearer idp${secret()}`],
    ['31バイト', `Bearer idp.${b64(randomBytes(31))}`],
    ['33バイト', `Bearer idp.${b64(randomBytes(33))}`],
    ['base64url の外の文字', `Bearer idp.${secret().slice(0, 42)}+`],
    ['知らないサービス', `Bearer sender.${secret()}`],
    ['大文字のスキーム', `BEARER idp.${secret()}`],
    ['空', ''],
  ])('壊れた資格情報（%s）は 403', async (_label, authorization) => {
    // 攻撃者が持っている情報：なし（鍵サービスのソケットに届くだけ。届く者を最大に見積もる）
    // 試す経路：形の違う資格情報、知らないサービスの名前で mac を呼ぶ
    // 期待する結果：すべて 403
    // plan 11章：テスト8
    const response = await call(authorization);
    expect(response.status).toBe(403);
    expect(response.body).toBe('{"error":"forbidden"}');
  });

  it('403 の本文とヘッダーは、理由によらずバイト単位で同じ', async () => {
    // 攻撃者が持っている情報：上の全部と、侵害した company-api の資格情報
    // 試す経路：認証の失敗の 403 と、表にない操作の 403（本文の解析の前）と、表にない対象の 403 を比べる
    // 期待する結果：本文とヘッダーがバイト単位で同じ。理由を区別できない
    // plan 11章：テスト8
    const authFailure = await call(`Bearer idp.${secret()}`);
    const opDenied = await call(`Bearer ${keysvc.credentials['company-api']}`, 'decrypt', '{');
    const targetDenied = await call(`Bearer ${keysvc.credentials['company-api']}`, 'mac', {
      purpose: 'desk_code',
      message: b64('m'),
    });
    for (const response of [opDenied, targetDenied]) {
      expect(response.status).toBe(403);
      expect(response.body).toBe(authFailure.body);
      expect(response.rawHeaders).toEqual(authFailure.rawHeaders);
    }
  });

  it.each([
    [
      'sender を足す',
      (dir: string) => ({
        version: 1,
        socketDir: dir,
        credentials: { idp: secret(), relay: secret(), 'company-api': secret(), sender: secret() },
      }),
    ],
    [
      'relay の秘密を配列で2つ渡す',
      (dir: string) => ({
        version: 1,
        socketDir: dir,
        credentials: { idp: secret(), relay: [secret(), secret()], 'company-api': secret() },
      }),
    ],
    [
      'relay を欠く',
      (dir: string) => ({
        version: 1,
        socketDir: dir,
        credentials: { idp: secret(), 'company-api': secret() },
      }),
    ],
    [
      '2つのサービスに同じ秘密を入れる',
      (dir: string) => {
        const same = secret();
        return {
          version: 1,
          socketDir: dir,
          credentials: { idp: secret(), relay: same, 'company-api': same },
        };
      },
    ],
  ])('decrypt の資格情報を増やす設定（%s）では起動しない', async (_label, config) => {
    // 攻撃者が持っている情報：なし（運用の誤りへの備え。不変条件3の「relay の1つだけ」を起動時に強制する）
    // 試す経路：資格情報の一覧を広げた設定や、資格情報を共有させる設定で起動する
    // 期待する結果：起動しない（終了コード 2）。ソケットを作らない。出力に秘密が出ない
    // plan 11章：テスト8
    const result = await startKeysvcExpectingFailure(config);
    expect(result.exitCode).toBe(2);
    expect(result.socketCreated).toBe(false);
    expect(result.output).toContain('keysvc.config_invalid');
  });

  it('group や other が読めるディレクトリでは起動しない', async () => {
    // 攻撃者が持っている情報：なし（同じホストの別の OS 利用者がソケットに届く設定への備え）
    // 試す経路：0755 のソケットのディレクトリで起動する
    // 期待する結果：起動しない（終了コード 2）。ソケットを作らない
    // plan 11章：テスト8
    const result = await startKeysvcExpectingFailure(
      (dir: string) => ({
        version: 1,
        socketDir: dir,
        credentials: { idp: secret(), relay: secret(), 'company-api': secret() },
      }),
      { socketDirMode: 0o755 },
    );
    expect(result.exitCode).toBe(2);
    expect(result.socketCreated).toBe(false);
  });
});
