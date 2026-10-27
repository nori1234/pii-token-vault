import { describe, expect, it } from 'vitest';
import { aliasLookupMessage } from '../src/aliases.ts';
import {
  canonicalJson,
  EncodingError,
  fromBase64Url,
  lengthPrefixed,
  toBase32Lower,
  toBase64Url,
  u32be,
  u64be,
  utf8,
} from '../src/encoding.ts';
import { InvalidIdError, parseTenantId, parseWarifuUserId, uuidBytes } from '../src/ids.ts';

describe('base32（RFC 4648 10章の例を小文字にしたもの）', () => {
  it.each([
    ['', ''],
    ['f', 'my'],
    ['fo', 'mzxq'],
    ['foo', 'mzxw6'],
    ['foob', 'mzxw6yq'],
    ['fooba', 'mzxw6ytb'],
    ['foobar', 'mzxw6ytboi'],
  ])('%j → %j', (input, expected) => {
    expect(toBase32Lower(utf8(input))).toBe(expected);
  });
});

describe('base64url', () => {
  it('往復する', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });

  it.each([
    ['パディング', 'AA=='],
    ['base64 の字母', 'a+b/'],
    ['長さの余りが1', 'AAAAA'],
    ['余りのビットが0でない', 'AB'],
    ['空白', 'AA AA'],
  ])('%s を拒否する', (_label, text) => {
    expect(() => fromBase64Url(text)).toThrow(EncodingError);
  });
});

describe('lengthPrefixed と整数', () => {
  it('各部分の前に u32 のビッグエンディアンで長さを付ける', () => {
    expect(Array.from(lengthPrefixed(['a', new Uint8Array([1, 2])]))).toEqual([
      0, 0, 0, 1, 0x61, 0, 0, 0, 2, 1, 2,
    ]);
  });

  it('区切りの曖昧さがない', () => {
    expect(lengthPrefixed(['ab', 'c'])).not.toEqual(lengthPrefixed(['a', 'bc']));
  });

  it('範囲の外の整数を拒否する', () => {
    expect(() => u32be(-1)).toThrow(EncodingError);
    expect(() => u32be(2 ** 32)).toThrow(EncodingError);
    expect(() => u64be(-1n)).toThrow(EncodingError);
    expect(Array.from(u64be(258n))).toEqual([0, 0, 0, 0, 0, 0, 1, 2]);
  });
});

describe('canonicalJson', () => {
  it('キーを並べ替える', () => {
    expect(canonicalJson({ b: 1, a: 'x', c: true })).toBe('{"a":"x","b":1,"c":true}');
  });

  it.each([
    ['小数', { a: 1.5 }],
    ['入れ子', { a: { b: 1 } }],
    ['null', { a: null }],
  ])('%s を拒否する', (_label, value) => {
    expect(() => canonicalJson(value as never)).toThrow(EncodingError);
  });
});

describe('ID', () => {
  it('小文字の UUID だけを受け付け、例外に値を入れない', () => {
    const marker = "' OR 1=1 --";
    expect(() => parseTenantId(marker)).toThrow(InvalidIdError);
    try {
      parseWarifuUserId(marker);
    } catch (error) {
      expect(String(error)).not.toContain(marker);
    }
    expect(() => parseTenantId('8F14E45F-CEEA-467A-9575-0C1F2E3D4B5A')).toThrow(InvalidIdError);
    expect(parseTenantId('8f14e45f-ceea-467a-9575-0c1f2e3d4b5a')).toBe(
      '8f14e45f-ceea-467a-9575-0c1f2e3d4b5a',
    );
    expect(uuidBytes('8f14e45f-ceea-467a-9575-0c1f2e3d4b5a').byteLength).toBe(16);
  });
});

describe('aliasLookupMessage', () => {
  it('別名のローカル部の形だけを受け付ける', () => {
    expect(aliasLookupMessage('abcdefghijklmnop').byteLength).toBeGreaterThan(16);
    expect(() => aliasLookupMessage('ABCDEFGHIJKLMNOP')).toThrow(EncodingError);
    expect(() => aliasLookupMessage('abc')).toThrow(EncodingError);
    expect(() => aliasLookupMessage('abcdefghijklmno1')).toThrow(EncodingError);
  });
});
