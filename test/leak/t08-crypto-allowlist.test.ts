// 暗号の許可リスト（不変条件9、plan 11章 テスト8）。静的な点検と、小さな実行で固定する。

import { createDecipheriv, createPublicKey, verify } from 'node:crypto';
import { describe, expect, inject, it } from 'vitest';
import {
  aes256GcmOpen,
  aes256GcmSeal,
  CryptoOpenError,
  hmacSha256,
  newSymmetricKey,
} from '../../packages/keysvc/src/crypto.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { keysvcConnection } from '../setup/keys.ts';
import {
  importsOf,
  packageSourceFiles,
  read,
  stringLiterals,
  stripComments,
} from '../setup/source.ts';

// node:crypto を import してよいファイルと、その名前（ADR 0012）。
const CRYPTO_IMPORTERS: Readonly<Record<string, readonly string[]>> = {
  'packages/keysvc/src/crypto.ts': [
    'createCipheriv',
    'createDecipheriv',
    'createHmac',
    'generateKeyPairSync',
    'KeyObject',
    'randomBytes',
    'sign',
  ],
  'packages/warifu-core/src/random.ts': ['randomBytes', 'randomUUID', 'timingSafeEqual'],
};

describe('漏えい：暗号の許可リスト（plan 11章 テスト8）', () => {
  it('node:crypto を import するのは2つのファイルだけで、名前も一覧の中だけ', () => {
    // 攻撃者が持っている情報：なし（静的な固定。暗号の誤用（TH-38）と、依存や貢献者の変更（ATK-09）に備える）
    // 試す経路：packages/*/src の .ts の、静的・動的な import と再エクスポートを調べる
    // 期待する結果：packages/keysvc/src/crypto.ts と packages/warifu-core/src/random.ts だけ。名前は一覧の中だけ。
    //               既定の import、名前空間の import、動的な import はない
    // plan 11章：テスト8
    const found: Record<string, string[]> = {};
    for (const file of packageSourceFiles()) {
      for (const info of importsOf(read(file))) {
        if (info.specifier === '*expression*') {
          throw new Error(`式による動的な import は使わない：${file}`);
        }
        if (info.specifier === 'node:crypto' || info.specifier === 'crypto') {
          expect(info.kind).toBe('static');
          found[file] = [...(found[file] ?? []), ...info.names];
        }
      }
    }
    expect(Object.keys(found).sort()).toEqual(Object.keys(CRYPTO_IMPORTERS).sort());
    for (const [file, names] of Object.entries(found)) {
      for (const name of names) expect(CRYPTO_IMPORTERS[file]).toContain(name);
    }
  });

  it('鍵サービスの暗号のファイルに書いた方式は、許可リストのものだけ', () => {
    // 攻撃者が持っている情報：なし（静的な固定）
    // 試す経路：packages/keysvc/src/crypto.ts の、英数字の文字列リテラルを集める
    // 期待する結果：aes-256-gcm、sha256、ec、P-256、ieee-p1363 と、方式でない語（import 元、jwk、string、
    //               例外の名前）だけ。
    //               authTagLength は16、IV は12バイト
    // plan 11章：テスト8
    const source = read('packages/keysvc/src/crypto.ts');
    const ascii = stringLiterals(source).filter((s) => /^[ -~]+$/.test(s));
    expect(new Set(ascii)).toEqual(
      new Set([
        'node:crypto',
        'aes-256-gcm',
        'sha256',
        'ec',
        'P-256',
        'ieee-p1363',
        'jwk',
        'string',
        'CryptoOpenError',
      ]),
    );
    const code = stripComments(source);
    expect(code).toMatch(/GCM_IV_BYTES = 12;/);
    expect(code).toMatch(/GCM_TAG_BYTES = 16;/);
    expect(code.match(/authTagLength: GCM_TAG_BYTES/g)).toHaveLength(2);
  });

  it('弱い方式の名前と Math.random を、どこにも書かない', () => {
    // 攻撃者が持っている情報：なし（予測できる値をトークンにさせない。弱い方式を使わせない）
    // 試す経路：packages/*/src の .ts（コメントを除く）を検索する
    // 期待する結果：Math.random、md5、sha1、sha-1、des、rc4、ecb、cbc、aes-128 が0件
    // plan 11章：テスト8
    for (const file of packageSourceFiles()) {
      const code = stripComments(read(file));
      expect(code).not.toMatch(/Math\.random/);
      for (const literal of stringLiterals(read(file))) {
        expect(literal.toLowerCase()).not.toMatch(
          /^(md5|sha1|sha-1|des|des-ede3|rc4|aes-128-[a-z]+|aes-256-(cbc|ecb|ctr))$/,
        );
      }
    }
  });

  it('実際の方式：HMAC-SHA-256、AES-256-GCM、ES256', async () => {
    // 攻撃者が持っている情報：なし（実行時の固定）
    // 試す経路：HMAC を RFC 4231 のテストケース6と比べる。AES-GCM の出力を、テストの中の
    //           createDecipheriv('aes-256-gcm') で開く。鍵サービスの ES256 の署名を、公開鍵で検証する
    // 期待する結果：一致する。署名は64バイト（JWS の r‖s）
    // plan 11章：テスト8
    const hmac = hmacSha256(
      new Uint8Array(131).fill(0xaa),
      new Uint8Array(Buffer.from('Test Using Larger Than Block-Size Key - Hash Key First')),
    );
    expect(Buffer.from(hmac).toString('hex')).toBe(
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    );

    const key = newSymmetricKey();
    const aad = new Uint8Array([1, 2, 3]);
    const plaintext = new Uint8Array(Buffer.from('payload'));
    const sealed = aes256GcmSeal(key, plaintext, aad);
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.iv, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.tag);
    expect(Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()])).toEqual(
      Buffer.from(plaintext),
    );

    inject('keysvc');
    const idp = createIdpKeyClient(keysvcConnection('idp'));
    const message = new Uint8Array(Buffer.from('header.payload'));
    const { kid, signature } = await idp.sign('id_token', message);
    expect(signature.byteLength).toBe(64);
    const [jwk] = await idp.publicKeys('id_token');
    expect(jwk?.kid).toBe(kid);
    const publicKey = createPublicKey({ key: { ...jwk }, format: 'jwk' });
    expect(
      verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature),
    ).toBe(true);
  });

  it('短いタグを受け付けない', () => {
    // 攻撃者が持っている情報：暗号文を書き換えられる者（ATK-02、ATK-06）
    // 試す経路：タグを4バイトにして aes256GcmOpen に渡す（短いタグでの偽造を試す）
    // 期待する結果：CryptoOpenError
    // plan 11章：テスト8
    const key = newSymmetricKey();
    const sealed = aes256GcmSeal(key, new Uint8Array([1]), new Uint8Array());
    expect(() =>
      aes256GcmOpen(key, sealed.iv, sealed.ciphertext, sealed.tag.subarray(0, 4), new Uint8Array()),
    ).toThrow(CryptoOpenError);
  });
});
