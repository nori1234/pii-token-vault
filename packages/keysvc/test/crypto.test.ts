import { describe, expect, it } from 'vitest';
import {
  aes256GcmOpen,
  aes256GcmSeal,
  CryptoOpenError,
  hmacSha256,
  newSymmetricKey,
} from '../src/crypto.ts';

const hex = (text: string) => new Uint8Array(Buffer.from(text, 'hex'));
const ascii = (text: string) => new Uint8Array(Buffer.from(text, 'latin1'));

describe('AES-256-GCM', () => {
  // GCM の仕様（McGrew と Viega）の Test Case 16。256ビットの鍵、96ビットの IV、AAD あり。
  const key = hex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
  const iv = hex('cafebabefacedbaddecaf888');
  const aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const plaintext = hex(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
  );
  const ciphertext = hex(
    '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
  );
  const tag = hex('76fc6ece0f4e1768cddf8853bb2d551b');

  it('公開の試験ベクタを復号できる', () => {
    expect(aes256GcmOpen(key, iv, ciphertext, tag, aad)).toEqual(plaintext);
  });

  it('AAD が違えば復号できない', () => {
    expect(() => aes256GcmOpen(key, iv, ciphertext, tag, new Uint8Array([1]))).toThrow(
      CryptoOpenError,
    );
  });

  it('短いタグ、短い IV、短い鍵を受け付けない', () => {
    expect(() => aes256GcmOpen(key, iv, ciphertext, tag.subarray(0, 4), aad)).toThrow(
      CryptoOpenError,
    );
    expect(() => aes256GcmOpen(key, iv.subarray(0, 8), ciphertext, tag, aad)).toThrow(
      CryptoOpenError,
    );
    expect(() => aes256GcmOpen(key.subarray(0, 16), iv, ciphertext, tag, aad)).toThrow(
      CryptoOpenError,
    );
  });

  it('封をするたびに IV が変わる', () => {
    const k = newSymmetricKey();
    const a = aes256GcmSeal(k, plaintext, aad);
    const b = aes256GcmSeal(k, plaintext, aad);
    expect(a.iv.byteLength).toBe(12);
    expect(a.tag.byteLength).toBe(16);
    expect(a.iv).not.toEqual(b.iv);
    expect(aes256GcmOpen(k, a.iv, a.ciphertext, a.tag, aad)).toEqual(plaintext);
  });
});

describe('HMAC-SHA-256（RFC 4231）', () => {
  const key = new Uint8Array(131).fill(0xaa);

  it('テストケース6', () => {
    expect(
      Buffer.from(
        hmacSha256(key, ascii('Test Using Larger Than Block-Size Key - Hash Key First')),
      ).toString('hex'),
    ).toBe('60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
  });

  it('テストケース7', () => {
    const data =
      'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.';
    expect(Buffer.from(hmacSha256(key, ascii(data))).toString('hex')).toBe(
      '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    );
  });

  it('32バイトより短い鍵を受け付けない', () => {
    expect(() => hmacSha256(new Uint8Array(16), ascii('x'))).toThrow(RangeError);
  });
});
