import { describe, expect, it } from 'vitest';
import { ACL, allowedOp, allowedTarget } from '../src/acl.ts';

describe('能力の表の性質（不変条件3）', () => {
  it('decrypt を持つのは relay だけ', () => {
    expect(new Set(ACL.filter(([, op]) => op === 'decrypt').map(([caller]) => caller))).toEqual(
      new Set(['relay']),
    );
  });

  it('relay は derive_alias、sign、public_keys を持たず、encrypt は relay_queue だけ', () => {
    expect(allowedOp('relay', 'derive_alias')).toBe(false);
    expect(allowedOp('relay', 'sign')).toBe(false);
    expect(allowedOp('relay', 'public_keys')).toBe(false);
    expect(allowedTarget('relay', 'encrypt', 'contact')).toBe(false);
    expect(allowedTarget('relay', 'encrypt', 'relay_queue')).toBe(true);
  });

  it('company-api は encrypt と decrypt を持たない', () => {
    expect(allowedOp('company-api', 'encrypt')).toBe(false);
    expect(allowedOp('company-api', 'decrypt')).toBe(false);
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
