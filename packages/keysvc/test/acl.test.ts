import { describe, expect, it } from 'vitest';
import { ACL, allowedOp, allowedTarget } from '../src/acl.ts';

describe('能力の表の性質（不変条件3）', () => {
  it('decrypt を持つのは relay だけ', () => {
    expect(new Set(ACL.filter(([, op]) => op === 'decrypt').map(([caller]) => caller))).toEqual(
      new Set(['relay']),
    );
  });

  it('relay は derive_alias を持たず、sign と public_keys は dkim だけ、encrypt は relay_queue だけ', () => {
    expect(allowedOp('relay', 'derive_alias')).toBe(false);
    expect(allowedTarget('relay', 'sign', 'id_token')).toBe(false);
    expect(allowedTarget('relay', 'sign', 'dkim')).toBe(true);
    expect(allowedTarget('relay', 'public_keys', 'id_token')).toBe(false);
    expect(allowedTarget('relay', 'public_keys', 'dkim')).toBe(true);
    expect(allowedTarget('relay', 'encrypt', 'contact')).toBe(false);
    expect(allowedTarget('relay', 'encrypt', 'relay_queue')).toBe(true);
  });

  it('dkim の鍵で署名できるのは relay だけ。id_token の鍵で署名できるのは idp だけ', () => {
    const signers = (key: string) =>
      ACL.filter(([, op, target]) => op === 'sign' && target === key).map(([caller]) => caller);
    expect(signers('dkim')).toEqual(['relay']);
    expect(signers('id_token')).toEqual(['idp']);
  });

  it('返信、リプレイ、Message-ID の MAC は relay だけ', () => {
    for (const purpose of ['relay_replay', 'relay_thread', 'message_id']) {
      const callers = ACL.filter(([, op, target]) => op === 'mac' && target === purpose).map(
        ([caller]) => caller,
      );
      expect(callers).toEqual(['relay']);
    }
  });

  it('company-api は encrypt と decrypt を持たない。sign と public_keys は tenant_jwt と set だけ', () => {
    expect(allowedOp('company-api', 'encrypt')).toBe(false);
    expect(allowedOp('company-api', 'decrypt')).toBe(false);
    expect(allowedTarget('company-api', 'sign', 'id_token')).toBe(false);
    expect(allowedTarget('company-api', 'sign', 'dkim')).toBe(false);
    const targets = (op: string) =>
      ACL.filter(([caller, o]) => caller === 'company-api' && o === op).map(([, , t]) => t);
    expect(targets('sign')).toEqual(['tenant_jwt', 'set']);
    expect(targets('public_keys')).toEqual(['tenant_jwt', 'set']);
  });

  it('tenant_jwt と set の鍵で署名できるのは company-api だけ', () => {
    for (const key of ['tenant_jwt', 'set']) {
      const signers = ACL.filter(([, op, target]) => op === 'sign' && target === key).map(
        ([caller]) => caller,
      );
      expect(signers).toEqual(['company-api']);
    }
  });

  it('知らない呼び出し元、操作、対象は false', () => {
    expect(allowedOp('sender' as never, 'mac')).toBe(false);
    expect(allowedOp('idp', 'export_key')).toBe(false);
    expect(allowedTarget('idp', 'mac', 'desk_code')).toBe(false);
    expect(allowedTarget('idp', 'mac', undefined)).toBe(false);
  });

  it('sub の導出、保存の id、確認コードの MAC は idp だけ', () => {
    for (const purpose of ['pairwise_sub', 'oidc_storage_id', 'email_verify_code']) {
      const callers = ACL.filter(([, op, target]) => op === 'mac' && target === purpose).map(
        ([caller]) => caller,
      );
      expect(callers).toEqual(['idp']);
    }
  });

  it('同じ行が2回ない', () => {
    const keys = ACL.map((row) => row.join('/'));
    expect(new Set(keys).size).toBe(keys.length);
  });
});
