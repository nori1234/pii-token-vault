// company-api の登録簿の検査（ADR 0010、ADR 0022）。起動の時点で、許していない登録を止める。

import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseCompanyApiConfig } from '../src/config.ts';

const jwk = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43), alg: 'ES256' };

function tenant(extra: Record<string, unknown> = {}) {
  return {
    tenantId: randomUUID(),
    relayDomain: `t${randomUUID().slice(0, 8)}.relay.warifu.test`,
    participation: 'full',
    apiClients: [{ clientId: `c-${randomUUID().slice(0, 8)}`, jwks: { keys: [jwk] } }],
    ...extra,
  };
}

const parse = (tenants: unknown[], issuer = 'https://api.warifu.example') =>
  parseCompanyApiConfig({ issuer, tenants });

describe('company-api の登録簿（ADR 0010、ADR 0022）', () => {
  it('参加の状態、移行中の期限、確かめた入り口を持つ。M9 までは、完全な参加で、期限なし、確かめた入り口は空だけ', () => {
    const [parsed] = [
      ...parse([tenant({ migrationDeadline: null, verifiedEntries: [] })]).tenants.values(),
    ];
    expect([parsed?.participation, parsed?.migrationDeadline, parsed?.verifiedEntries]).toEqual([
      'full',
      null,
      [],
    ]);
    expect(parse([tenant()]).tenants.size).toBe(1);
    expect(() => parse([tenant({ participation: 'migrating' })])).toThrow('参加の状態は full だけ');
    expect(() => parse([tenant({ participation: undefined })])).toThrow('参加の状態は full だけ');
    expect(() => parse([tenant({ migrationDeadline: '2027-01-01' })])).toThrow('移行中の期限');
    expect(() =>
      parse([tenant({ verifiedEntries: [{ entry: 'ENT-01', verifiedAt: '2026-10-28' }] })]),
    ).toThrow('確かめた入り口');
    expect(() => parse([tenant({ verifiedEntries: 'ENT-01' })])).toThrow('確かめた入り口');
    expect(() => parse([tenant({ verifiedAt: '2026-10-28' })])).toThrow('許可していない項目');
  });

  it('企業の鍵は jwks の ES256 だけ。外へ取りに行く項目と秘密鍵は受け付けない', () => {
    const withClient = (client: Record<string, unknown>) =>
      parse([tenant({ apiClients: [{ clientId: 'c1', jwks: { keys: [jwk] }, ...client }] })]);
    expect(() => withClient({ jwks_uri: 'https://company.example/jwks' })).toThrow(
      '許可していない項目',
    );
    expect(() => withClient({ jwks: { keys: [{ ...jwk, d: 'C'.repeat(43) }] } })).toThrow(
      '許可していない項目',
    );
    expect(() => withClient({ jwks: { keys: [{ ...jwk, alg: 'RS256' }] } })).toThrow('ES256');
    expect(() => withClient({ jwks: { keys: [{ ...jwk, crv: 'P-384' }] } })).toThrow('ES256');
    expect(() => withClient({ jwks: { keys: [{ ...jwk, x5u: 'https://x.example' }] } })).toThrow(
      '許可していない項目',
    );
  });

  it('受け口は https の 443 番だけ。client_id と relay ドメインはテナントをまたいで重複させない', () => {
    for (const url of [
      'http://hooks.company.example/set',
      'https://hooks.company.example:8443/set',
      'https://user:pw@hooks.company.example/set',
      'https://hooks.company.example/set#x',
    ]) {
      expect(() => parse([tenant({ webhookUrl: url })])).toThrow('webhookUrl');
    }
    const a = tenant();
    expect(() => parse([a, { ...tenant(), apiClients: a.apiClients }])).toThrow('client_id が重複');
    expect(() => parse([a, { ...tenant(), relayDomain: a.relayDomain }])).toThrow('relay ドメイン');
    expect(() => parse([tenant()], 'http://api.warifu.example')).toThrow('issuer');
    expect(() => parse([tenant()], 'https://api.warifu.example/')).toThrow('issuer');
  });
});
