import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkSocketDir, KeysvcConfigError, parseKeysvcConfig } from '../src/config.ts';

const secret = () => randomBytes(32).toString('base64url');

function valid(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    socketDir: '/tmp/x',
    credentials: { idp: secret(), relay: secret(), 'company-api': secret() },
    ...overrides,
  };
}

function reasonOf(config: unknown): string | undefined {
  try {
    parseKeysvcConfig(typeof config === 'string' ? config : JSON.stringify(config));
    return undefined;
  } catch (error) {
    return error instanceof KeysvcConfigError ? error.reason : 'other';
  }
}

describe('設定の検査', () => {
  it('正しい設定を受け付ける', () => {
    expect(reasonOf(valid())).toBeUndefined();
  });

  it.each([
    ['JSON でない', '{', 'not_json'],
    ['知らない項目', valid({ extra: 1 }), 'shape'],
    ['版が違う', valid({ version: 2 }), 'version'],
    ['ソケットのディレクトリが文字列でない', valid({ socketDir: 1 }), 'socket_dir'],
    [
      'sender の資格情報を足す',
      valid({
        credentials: { idp: secret(), relay: secret(), 'company-api': secret(), sender: secret() },
      }),
      'credentials_keys',
    ],
    [
      'relay を欠く',
      valid({ credentials: { idp: secret(), 'company-api': secret() } }),
      'credentials_keys',
    ],
    ['配列', valid({ credentials: [secret(), secret(), secret()] }), 'credentials_keys'],
    [
      '短い秘密',
      valid({
        credentials: {
          idp: randomBytes(31).toString('base64url'),
          relay: secret(),
          'company-api': secret(),
        },
      }),
      'credential_format',
    ],
    [
      'relay の秘密を2つ渡す',
      valid({
        credentials: { idp: secret(), relay: [secret(), secret()], 'company-api': secret() },
      }),
      'credential_format',
    ],
  ])('%s を拒否する', (_label, config, reason) => {
    expect(reasonOf(config)).toBe(reason);
  });

  it('2つのサービスに同じ秘密を入れた設定を拒否する', () => {
    const same = secret();
    expect(
      reasonOf(valid({ credentials: { idp: same, relay: same, 'company-api': secret() } })),
    ).toBe('credential_duplicate');
  });

  it('例外に値を入れない', () => {
    const marker = secret();
    try {
      parseKeysvcConfig(
        JSON.stringify(valid({ credentials: { idp: marker, relay: marker, 'company-api': 1 } })),
      );
    } catch (error) {
      expect(String(error)).not.toContain(marker);
      expect(JSON.stringify(error)).not.toContain(marker);
    }
  });
});

describe('ソケットのディレクトリの検査', () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'warifu-ks-test-'));
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('0700 の自分のディレクトリだけを受け付ける', async () => {
    await chmod(dir, 0o700);
    expect(checkSocketDir(dir)).toBe(join(dir, 'keysvc.sock'));
    await chmod(dir, 0o755);
    expect(() => checkSocketDir(dir)).toThrow(KeysvcConfigError);
    await chmod(dir, 0o700);
  });

  it('相対パス、正規化されていないパス、ないディレクトリを拒否する', () => {
    expect(() => checkSocketDir('relative')).toThrow(KeysvcConfigError);
    expect(() => checkSocketDir(`${dir}/../${dir.split('/').pop()}`)).toThrow(KeysvcConfigError);
    expect(() => checkSocketDir(join(dir, 'missing'))).toThrow(KeysvcConfigError);
  });
});
