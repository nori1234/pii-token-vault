import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { codeMessage, newVerificationCode, normalizeEmail } from '../src/email.ts';
import { RateLimiter } from '../src/rate-limit.ts';
import { MacMemoryStore } from '../src/storage.ts';
import { deriveSub, subjectMessage } from '../src/subject.ts';
import { isNoneAttestation, userIdFromHandle, uuidFromBytes } from '../src/webauthn.ts';

// 鍵サービスの代わり（入力をそのまま32バイトに詰める。鍵を使わないので、テストの中だけで使う）。
const fakeMac = {
  async mac(_purpose: string, message: Uint8Array) {
    const out = new Uint8Array(32);
    for (const [i, b] of message.entries()) out[i % 32] = ((out[i % 32] ?? 0) + b * (i + 1)) & 0xff;
    return out;
  },
};

describe('メールの入力の整え方（ADR 0018）', () => {
  it('前後の空白を除き、ドメインだけを小文字にする', () => {
    expect(normalizeEmail('  Taro.Yamada@Example.COM ')).toBe('Taro.Yamada@example.com');
  });

  it.each([
    'no-at',
    'a@b',
    '@example.com',
    'a@@example.com',
    'a b@example.com',
    'a@example.com\r\nBcc: x@example.com',
    '"a"@example.com',
    'a<b>@example.com',
    '.a@example.com',
    'a..b@example.com',
    `${'a'.repeat(65)}@example.com`,
    'a@-example.com',
  ])('形が違う入力（%j）は受け付けない', (input) => {
    expect(normalizeEmail(input)).toBeUndefined();
  });

  it('確認コードは8桁の数字で、偏りがない（棄却法）', () => {
    const counts = new Array(10).fill(0);
    for (let i = 0; i < 2000; i += 1) {
      const code = newVerificationCode();
      expect(code).toMatch(/^[0-9]{8}$/);
      for (const c of code) counts[Number(c)] += 1;
    }
    for (const count of counts) expect(count).toBeGreaterThan(1300);
  });

  it('コードの MAC の入力は、利用者に結び付く', () => {
    const a = codeMessage(randomUUID() as never, '12345678');
    const b = codeMessage(randomUUID() as never, '12345678');
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('レート制限（固定窓）', () => {
  it('上限を超えたら false、窓が変われば戻る。キーごとに独立', () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    for (let i = 0; i < 3; i += 1) expect(limiter.take('emailSendByUser', 'u1')).toBe(true);
    expect(limiter.take('emailSendByUser', 'u1')).toBe(false);
    expect(limiter.take('emailSendByUser', 'u2')).toBe(true);
    now += 900 * 1000;
    expect(limiter.take('emailSendByUser', 'u1')).toBe(true);
  });
});

describe('短命な保存先（storage.ts）', () => {
  it('鍵は MAC で、元の id は保存先に残らない。期限が過ぎたら読めない', async () => {
    let now = 0;
    const store = new MacMemoryStore(fakeMac, () => now);
    const id = 'secret-token-value-123456';
    await store.set('AccessToken', id, { grantId: 'g1' }, 10);
    expect(await store.get('AccessToken', id)).toEqual({ grantId: 'g1' });
    expect(store.dump()).not.toContain(id);
    expect(await store.keyOf('AccessToken', id)).not.toBe(await store.keyOf('Grant', id));
    now += 10_000;
    expect(await store.get('AccessToken', id)).toBeUndefined();
  });

  it('oidc-provider のアダプタは、payload から jti を除き、consume と revokeByGrantId を持つ', async () => {
    const store = new MacMemoryStore(fakeMac);
    const adapter = store.adapterFactory()('AuthorizationCode');
    await adapter.upsert('code-1', { jti: 'code-1', grantId: 'g1', kind: 'AuthorizationCode' }, 60);
    expect(store.dump()).not.toContain('code-1');
    expect(await adapter.find('code-1')).toMatchObject({ jti: 'code-1', grantId: 'g1' });
    await adapter.consume('code-1');
    expect((await adapter.find('code-1'))?.consumed).toBeTypeOf('number');
    await adapter.revokeByGrantId('g1');
    expect(await adapter.find('code-1')).toBeUndefined();
    await expect(store.adapterFactory()('Client').upsert('c', {}, 1)).rejects.toThrow();
    expect(await store.adapterFactory()('Client').find('c')).toBeUndefined();
  });
});

describe('sub の導出の入力', () => {
  it('テナントと利用者の16バイトずつ。どちらかが違えば入力も違う', async () => {
    const tenant = randomUUID() as never;
    const user = randomUUID() as never;
    expect(
      Buffer.from(subjectMessage(tenant, user)).equals(
        Buffer.from(subjectMessage(randomUUID() as never, user)),
      ),
    ).toBe(false);
    expect(await deriveSub(fakeMac, tenant, user)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('WebAuthn の補助', () => {
  it('userHandle は利用者 ID の16バイト。形が違えば undefined', () => {
    const id = randomUUID();
    const bytes = Buffer.from(id.replaceAll('-', ''), 'hex');
    expect(uuidFromBytes(bytes)).toBe(id);
    expect(userIdFromHandle(bytes.toString('base64url'))).toBe(id);
    expect(userIdFromHandle(Buffer.alloc(32).toString('base64url'))).toBeUndefined();
    expect(userIdFromHandle(undefined)).toBeUndefined();
    expect(userIdFromHandle('!!')).toBeUndefined();
  });

  it('attestation が none で attStmt が空のときだけ true', () => {
    // CBOR：{ fmt: 'none', attStmt: {}, authData: h'' }
    const none = Buffer.from([
      0xa3, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65, 0x67, 0x61, 0x74, 0x74, 0x53,
      0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x40,
    ]);
    const response = (bytes: Buffer) => ({
      response: { attestationObject: bytes.toString('base64url') },
    });
    expect(isNoneAttestation(response(none))).toBe(true);
    const packed = Buffer.from(none);
    packed.set(Buffer.from('pack'), 6);
    expect(isNoneAttestation(response(packed))).toBe(false);
    expect(isNoneAttestation({ response: {} })).toBe(false);
    expect(isNoneAttestation(null)).toBe(false);
  });
});
