import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { OUTBOUND_CLIENT_METADATA, parseRegistry, RegistryError } from '../src/registry.ts';

const tenantId = randomUUID();
const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'a'.repeat(43),
  y: 'b'.repeat(43),
  kid: 'k1',
  alg: 'ES256',
  use: 'sig',
};
const tenant = { tenantId, displayName: 'A社', relayDomain: 'a.relay.warifu.test' };
const client = {
  clientId: 'rp-a',
  tenantId,
  redirectUris: ['https://rp.example/callback'],
  jwks: { keys: [jwk] },
};

function parse(
  clientOverrides: Record<string, unknown> = {},
  tenantOverrides: Record<string, unknown> = {},
) {
  return parseRegistry({
    tenants: [{ ...tenant, ...tenantOverrides }],
    clients: [{ ...client, ...clientOverrides }],
  });
}

describe('静的な登録簿の検査（不変条件7・9、ADR 0018）', () => {
  it('正しい設定を受け付け、aliasClaim の既定は email', () => {
    const registry = parse();
    expect(registry.clients.get('rp-a')?.aliasClaim).toBe('email');
    expect(registry.tenants.get(tenantId as never)?.displayName).toBe('A社');
  });

  it.each(OUTBOUND_CLIENT_METADATA)('外へ取りに行く項目 %s は受け付けない', (name) => {
    expect(() => parse({ [name]: 'https://rp.example/x' })).toThrow(RegistryError);
  });

  it('知らない項目、秘密鍵、P-256 以外、ES256 以外は受け付けない', () => {
    expect(() => parse({ client_name: 'x' })).toThrow(RegistryError);
    expect(() => parse({ jwks: { keys: [{ ...jwk, d: 'c'.repeat(43) }] } })).toThrow(RegistryError);
    expect(() => parse({ jwks: { keys: [{ ...jwk, crv: 'P-384' }] } })).toThrow(RegistryError);
    expect(() => parse({ jwks: { keys: [{ ...jwk, alg: 'RS256' }] } })).toThrow(RegistryError);
    expect(() => parse({ jwks: { keys: [{ ...jwk, x5u: 'https://x' }] } })).toThrow(RegistryError);
  });

  it('redirect_uris は https（開発では http://localhost）で、ホストは1つ、フラグメントやワイルドカードなし', () => {
    expect(() => parse({ redirectUris: ['http://rp.example/cb'] })).toThrow(RegistryError);
    expect(() => parse({ redirectUris: ['https://rp.example/cb#x'] })).toThrow(RegistryError);
    expect(() => parse({ redirectUris: ['https://*.rp.example/cb'] })).toThrow(RegistryError);
    expect(() =>
      parse({ redirectUris: ['https://a.rp.example/cb', 'https://b.rp.example/cb'] }),
    ).toThrow(RegistryError);
    expect(parse({ redirectUris: ['http://localhost:3000/cb'] }).clients.size).toBe(1);
  });

  it('企業名に制御文字や双方向の制御文字を入れさせない。relay ドメインはテナントごとに違う', () => {
    expect(() => parse({}, { displayName: 'A‮社' })).toThrow(RegistryError);
    expect(() => parse({}, { displayName: 'A\n社' })).toThrow(RegistryError);
    expect(() => parse({}, { relayDomain: 'Not_A_Domain' })).toThrow(RegistryError);
    expect(() =>
      parseRegistry({
        tenants: [tenant, { ...tenant, tenantId: randomUUID() }],
        clients: [],
      }),
    ).toThrow(RegistryError);
  });
});
