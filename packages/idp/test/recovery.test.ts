import { randomBytes, randomUUID } from 'node:crypto';
import type { WarifuUserId } from '@pii-token-vault/warifu-core';
import { describe, expect, it } from 'vitest';
import { createIdp } from '../src/app.ts';
import { MemoryOutbox } from '../src/mailer.ts';
import {
  crockfordDecode,
  crockfordEncode,
  formatRecoveryCode,
  newShortCode,
  parseRecoveryCode,
  RECOVERY_TIMES,
  recoveredDayOf,
  shortCodeKey,
} from '../src/recovery.ts';

const CROCKFORD = /^[0-9A-HJKMNP-TV-Z]+$/;

describe('Crockford の base32（ADR 0027 の O-73）', () => {
  it('どの長さでも、符号にしてから戻すと同じ値になる', () => {
    for (const length of [1, 5, 10, 15, 16, 26]) {
      for (let i = 0; i < 20; i += 1) {
        const bytes = new Uint8Array(randomBytes(length));
        const text = crockfordEncode(bytes);
        expect(text).toMatch(CROCKFORD);
        expect(text).toHaveLength(Math.ceil((length * 8) / 5));
        expect(crockfordDecode(text, length)).toEqual(bytes);
      }
    }
  });

  it('小文字、区切り、空白、読み間違えやすい文字（O、I、L）を読み替える', () => {
    const bytes = new Uint8Array(randomBytes(15));
    const text = crockfordEncode(bytes);
    const noisy = text
      .toLowerCase()
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/(.{4})/g, '$1- ');
    expect(crockfordDecode(noisy, 15)).toEqual(bytes);
    expect(crockfordDecode(text.replace(/1/g, 'I'), 15)).toEqual(bytes);
  });

  it('長さ、使えない文字、余りのビット、型、長すぎる入力を断る', () => {
    const text = crockfordEncode(new Uint8Array(randomBytes(10)));
    expect(crockfordDecode(text.slice(1), 10)).toBeUndefined();
    expect(crockfordDecode(`${text}0`, 10)).toBeUndefined();
    expect(crockfordDecode(`U${text.slice(1)}`, 10)).toBeUndefined();
    expect(crockfordDecode(`*${text.slice(1)}`, 10)).toBeUndefined();
    // 1バイトは2文字（10ビット）。余りの2ビットが0でなければ、別の値と同じにしないよう断る。
    expect(crockfordDecode('01', 1)).toBeUndefined();
    expect(crockfordDecode('00', 1)).toEqual(new Uint8Array([0]));
    for (const bad of [undefined, null, 42, ['00'], { text }]) {
      expect(crockfordDecode(bad, 10)).toBeUndefined();
    }
    expect(crockfordDecode(`${'-'.repeat(200)}${text}`, 10)).toBeUndefined();
  });
});

describe('回復コード（ADR 0027 の O-73）', () => {
  it('利用者 ID と80ビットの秘密を、6文字ずつ区切った42文字にする', () => {
    const userId = randomUUID() as WarifuUserId;
    const secret = new Uint8Array(randomBytes(10));
    const code = formatRecoveryCode(userId, secret);
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{6}){6}$/);
    expect(code.replace(/-/g, '')).toHaveLength(42);
    const parsed = parseRecoveryCode(code);
    expect(parsed?.userId).toBe(userId);
    expect(parsed?.secret).toEqual(secret);
    expect(parseRecoveryCode(code.toLowerCase().replace(/-/g, ' '))?.userId).toBe(userId);
  });

  it('形の違う入力は undefined（利用者 ID を推測できる形の失敗を返さない）', () => {
    const code = formatRecoveryCode(randomUUID() as WarifuUserId, new Uint8Array(randomBytes(10)));
    for (const bad of ['', 'x', code.slice(0, -1), `${code}0`, newShortCode(), undefined, 1]) {
      expect(parseRecoveryCode(bad)).toBeUndefined();
    }
  });
});

describe('招待と結び付けのコード（ADR 0027 の O-74、O-76）', () => {
  it('120ビットを、6文字ずつ区切った24文字にし、保存先の鍵は区切りのない正規の形', () => {
    const codes = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      const code = newShortCode();
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{6}){3}$/);
      expect(shortCodeKey(code)).toBe(code.replace(/-/g, ''));
      expect(shortCodeKey(code.toLowerCase())).toBe(code.replace(/-/g, ''));
      codes.add(code);
    }
    expect(codes.size).toBe(50);
    expect(shortCodeKey('short')).toBeUndefined();
    expect(shortCodeKey(42)).toBeUndefined();
  });
});

describe('企業に渡す recovered_at（ADR 0027 の O-81）', () => {
  it('UTC の0時の秒にまるめる', () => {
    expect(recoveredDayOf(new Date('2026-11-04T13:17:42.123Z'))).toBe(
      Date.parse('2026-11-04T00:00:00Z') / 1000,
    );
    expect(recoveredDayOf(new Date('2026-11-04T00:00:00Z'))).toBe(
      Date.parse('2026-11-04T00:00:00Z') / 1000,
    );
    expect(recoveredDayOf(new Date('2026-11-03T23:59:59.999Z'))).toBe(
      Date.parse('2026-11-03T00:00:00Z') / 1000,
    );
    expect(recoveredDayOf(new Date()) % 86_400).toBe(0);
  });
});

describe('回復の待機（ADR 0003、ADR 0027 の O-77、PRN-88）', () => {
  it('既定は72時間、本番（https）の下限は24時間', () => {
    expect(RECOVERY_TIMES.defaultWaitSeconds).toBe(72 * 3600);
    expect(RECOVERY_TIMES.minProductionWaitSeconds).toBe(24 * 3600);
    expect(RECOVERY_TIMES.helperFreshDays).toBe(14);
    expect(RECOVERY_TIMES.lockoutDays).toBe(14);
    expect(RECOVERY_TIMES.restrictionDays).toBe(7);
  });

  it('https のオリジンで24時間未満の待機を渡すと、起動しない。0以下と整数でない値も断る', async () => {
    const base = {
      origin: 'https://warifu.example',
      approvalOrigin: 'https://approve.warifu.example',
      rpId: 'warifu.example',
      registry: { tenants: [], clients: [] },
      keysvc: { socketPath: '/nonexistent/keysvc.sock', credential: 'idp.x' },
      db: { host: '/nonexistent', port: 5432, database: 'x' },
      mailer: new MemoryOutbox(),
    };
    for (const waitSeconds of [24 * 3600 - 1, 3600, 0, -1, 1.5, Number.NaN]) {
      await expect(createIdp({ ...base, recovery: { waitSeconds } })).rejects.toThrow(
        '回復の待機は',
      );
    }
    for (const waitSeconds of [0, -1, 1.5]) {
      await expect(
        createIdp({
          ...base,
          origin: 'http://localhost:1',
          approvalOrigin: 'http://localhost:2',
          rpId: 'localhost',
          recovery: { waitSeconds },
        }),
      ).rejects.toThrow('回復の待機は');
    }
  });
});
