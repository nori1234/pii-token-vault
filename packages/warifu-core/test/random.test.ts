import { describe, expect, it } from 'vitest';
import { constantTimeEqual, randomBytesOf, randomUuid } from '../src/random.ts';

describe('乱数と比較', () => {
  it('指定した長さの乱数を返す', () => {
    expect(randomBytesOf(32).byteLength).toBe(32);
    expect(randomBytesOf(32)).not.toEqual(randomBytesOf(32));
    expect(() => randomBytesOf(0)).toThrow(RangeError);
  });

  it('UUID は小文字の version 4', () => {
    expect(randomUuid()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('長さが違うときは例外ではなく false', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
  });
});
