// 鍵サービスに外から届かないこと、出力に値が出ないこと（不変条件3・4・7、plan 11章 テスト8）。
// このファイルは自分の鍵サービスを起動する。DB は使わない。

import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, readlinkSync, statSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type KeysvcProcess, startKeysvc } from '../../scripts/keysvc-up.ts';
import { rawKeysvcCall } from '../setup/keys.ts';

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');
const onLinux = process.platform === 'linux';

let keysvc: KeysvcProcess;

beforeAll(async () => {
  keysvc = await startKeysvc();
});

afterAll(async () => {
  await keysvc.stop();
});

function socketInodes(pid: number): Set<string> {
  const inodes = new Set<string>();
  for (const fd of readdirSync(`/proc/${pid}/fd`)) {
    try {
      const match = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${pid}/fd/${fd}`));
      if (match?.[1] !== undefined) inodes.add(match[1]);
    } catch {
      // 読む間に閉じた fd。
    }
  }
  return inodes;
}

function inetInodes(pid: number): Set<string> {
  const inodes = new Set<string>();
  for (const table of ['tcp', 'tcp6', 'udp', 'udp6']) {
    const path = `/proc/${pid}/net/${table}`;
    if (!existsSync(path)) continue;
    for (const line of readFileSync(path, 'utf8').split('\n').slice(1)) {
      const inode = line.trim().split(/\s+/)[9];
      if (inode !== undefined && inode !== '0') inodes.add(inode);
    }
  }
  return inodes;
}

describe('漏えい：鍵サービスの隔離（plan 11章 テスト8）', () => {
  it.skipIf(!onLinux)('TCP と UDP で待ち受けず、Unix ソケットだけを使う', async () => {
    // 攻撃者が持っている情報：割符の外のネットワーク、または侵害した別のホスト（ATK-02、TH-39）
    // 試す経路：鍵サービスのプロセスのソケットの inode を、/proc/<pid>/net/{tcp,tcp6,udp,udp6} と突き合わせる
    // 期待する結果：一致が0件。/proc/net/unix に keysvc.sock のパスがある
    // plan 11章：テスト8（CAP-38 の鍵サービスの確かめ方）
    const sockets = socketInodes(keysvc.pid);
    expect(sockets.size).toBeGreaterThan(0);
    const inet = inetInodes(keysvc.pid);
    expect([...sockets].filter((inode) => inet.has(inode))).toEqual([]);
    expect(readFileSync('/proc/net/unix', 'utf8')).toContain(keysvc.socketPath);
  });

  it('ソケットは 0600、ディレクトリは 0700 で、持ち主は起動した利用者', () => {
    // 攻撃者が持っている情報：同じホストの別の OS 利用者
    // 試す経路：ソケットとディレクトリの mode と持ち主を調べる
    // 期待する結果：ディレクトリは 0700、ソケットは 0600、持ち主は鍵サービスを起動した利用者
    // plan 11章：テスト8
    const dir = statSync(keysvc.socketDir);
    const socket = statSync(keysvc.socketPath);
    expect(dir.mode & 0o777).toBe(0o700);
    expect(socket.isSocket()).toBe(true);
    expect(socket.mode & 0o777).toBe(0o600);
    expect(dir.uid).toBe(process.getuid?.());
    expect(socket.uid).toBe(process.getuid?.());
  });

  it('鍵サービスの出力に、入力の値も出力の値も出ない', async () => {
    // 攻撃者が持っている情報：鍵サービスのログを読める運用者（ATK-06、TH-36）
    // 試す経路：乱数の目印を入れた平文、文脈、MAC の入力、署名の対象で、許される呼び出しと拒否される呼び出しを
    //           すべて行い、鍵サービスの出力を検索する
    // 期待する結果：目印（そのままと base64url）、暗号文、MAC、署名、資格情報の秘密が0件
    // plan 11章：テスト8（テスト7の前倒しの一部）
    const marker = `mk${b64(randomBytes(12))}`;
    const userId = randomUUID();
    const values: string[] = [];
    const call = async (
      caller: 'idp' | 'relay' | 'company-api' | 'none',
      op: string,
      body: unknown,
    ) => {
      const response = await rawKeysvcCall({
        socketPath: keysvc.socketPath,
        authorization:
          caller === 'none' ? `Bearer idp.${marker}` : `Bearer ${keysvc.credentials[caller]}`,
        op,
        body,
      });
      if (response.status === 200) {
        for (const value of Object.values(JSON.parse(response.body) as Record<string, unknown>)) {
          if (typeof value === 'string' && value.length >= 16) values.push(value);
        }
      }
      return response;
    };
    const plaintext = b64(`${marker}@example.com`);
    const encrypted = await call('idp', 'encrypt', {
      keyId: 'contact',
      plaintext,
      context: { field: 'email', user_id: userId },
    });
    const { ciphertext } = JSON.parse(encrypted.body) as { ciphertext: string };
    await call('relay', 'decrypt', {
      keyId: 'contact',
      ciphertext,
      context: { field: 'email', user_id: userId },
    });
    await call('idp', 'decrypt', {
      keyId: 'contact',
      ciphertext,
      context: { field: 'email', user_id: userId },
    });
    await call('relay', 'mac', { purpose: 'alias_lookup', message: b64(marker) });
    await call('idp', 'sign', { keyId: 'id_token', message: b64(marker) });
    await call('company-api', 'derive_alias', { tenantId: userId, userId, generation: 1 });
    await call('idp', 'mac', { purpose: marker, message: b64(marker) });
    await call('idp', 'encrypt', {
      keyId: 'contact',
      plaintext,
      context: { field: marker, user_id: userId },
    });
    await call('none', 'mac', { purpose: 'alias_lookup', message: b64(marker) });
    await call(
      'idp',
      marker
        .toLowerCase()
        .replaceAll(/[^a-z]/g, '_')
        .slice(0, 32),
      { marker },
    );

    // 鍵サービスは応答を送った後にログを書くので、出力が増えなくなるまで待つ。
    let last = -1;
    while (keysvc.output().length !== last) {
      last = keysvc.output().length;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const output = keysvc.output();
    expect(output).toContain('keysvc.request');
    for (const needle of [
      marker,
      plaintext,
      b64(marker),
      userId,
      ciphertext,
      ...values,
      ...Object.values(keysvc.credentials).map((credential) => credential.split('.')[1] ?? ''),
    ]) {
      expect(output).not.toContain(needle);
    }
  });
});
