// 複数のクライアントが共有する操作（mac、derive_alias、ES256 の sign と public_keys）。exports に載せない。

import { ALIAS_LOCAL_PART_PATTERN } from '../aliases.ts';
import { parseTenantId, parseWarifuUserId, type TenantId, type WarifuUserId } from '../ids.ts';
import { KeysvcError } from './errors.ts';
import {
  type Es256PublicJwk,
  LIMITS,
  MAX_ALIAS_GENERATION,
  MAX_MAC_KEY_VERSIONS,
  type MacPurpose,
  type SigningKeyId,
  VERSIONED_MAC_PURPOSES,
  type VersionedMacPurpose,
} from './protocol.ts';
import {
  arrayFrom,
  assertOneOf,
  bytesFrom,
  ES256_SIGNATURE_BYTES,
  encodeBytes,
  type KeysvcCall,
  MAC_BYTES,
  stringFrom,
} from './transport.ts';

export async function macWith(
  call: KeysvcCall,
  allowed: readonly MacPurpose[],
  purpose: MacPurpose,
  message: Uint8Array,
): Promise<Uint8Array> {
  const response = await call('mac', {
    purpose: assertOneOf(purpose, allowed),
    message: encodeBytes(message, LIMITS.macMessageBytes),
  });
  return bytesFrom(response, 'mac', MAC_BYTES);
}

/** 版を持つ用途の MAC と、作った版（ADR 0028 の O-87）。 */
export interface VersionedMac {
  readonly version: number;
  readonly mac: Uint8Array;
}

function versionFrom(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 0xffff_ffff
  ) {
    throw new KeysvcError('internal');
  }
  return value;
}

export async function macVersionedWith(
  call: KeysvcCall,
  purpose: VersionedMacPurpose,
  message: Uint8Array,
  version?: number,
): Promise<VersionedMac> {
  const body: Record<string, unknown> = {
    purpose: assertOneOf(purpose, VERSIONED_MAC_PURPOSES),
    message: encodeBytes(message, LIMITS.macMessageBytes),
  };
  if (version !== undefined) {
    if (!Number.isSafeInteger(version) || version < 1) throw new KeysvcError('invalid_request');
    body.version = version;
  }
  const response = await call('mac', body);
  const got = versionFrom((response as Record<string, unknown>).version);
  if (version !== undefined && got !== version) throw new KeysvcError('internal');
  return Object.freeze({ version: got, mac: bytesFrom(response, 'mac', MAC_BYTES) });
}

export async function macAllVersionsWith(
  call: KeysvcCall,
  purpose: VersionedMacPurpose,
  message: Uint8Array,
): Promise<readonly VersionedMac[]> {
  const response = await call('mac', {
    purpose: assertOneOf(purpose, VERSIONED_MAC_PURPOSES),
    message: encodeBytes(message, LIMITS.macMessageBytes),
    allVersions: true,
  });
  const list = arrayFrom(response, 'macs');
  if (list.length < 1 || list.length > MAX_MAC_KEY_VERSIONS) throw new KeysvcError('internal');
  let previous = 0;
  const out: VersionedMac[] = [];
  for (const item of list) {
    const version = versionFrom((item as Record<string, unknown> | null)?.version);
    if (version <= previous) throw new KeysvcError('internal');
    previous = version;
    out.push(Object.freeze({ version, mac: bytesFrom(item, 'mac', MAC_BYTES) }));
  }
  return Object.freeze(out);
}

export async function deriveAliasWith(
  call: KeysvcCall,
  input: {
    readonly tenantId: TenantId;
    readonly userId: WarifuUserId;
    readonly generation: number;
  },
): Promise<string> {
  const { generation } = input;
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > MAX_ALIAS_GENERATION) {
    throw new KeysvcError('invalid_request');
  }
  const response = await call('derive_alias', {
    tenantId: parseTenantId(input.tenantId),
    userId: parseWarifuUserId(input.userId),
    generation,
  });
  return stringFrom(response, 'localPart', ALIAS_LOCAL_PART_PATTERN);
}

const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function toJwk(value: unknown): Es256PublicJwk {
  if (value === null || typeof value !== 'object') throw new KeysvcError('internal');
  const jwk = value as Record<string, unknown>;
  if (
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    jwk.alg !== 'ES256' ||
    jwk.use !== 'sig' ||
    Object.hasOwn(jwk, 'd') ||
    typeof jwk.kid !== 'string' ||
    !KID_PATTERN.test(jwk.kid) ||
    typeof jwk.x !== 'string' ||
    !COORDINATE_PATTERN.test(jwk.x) ||
    typeof jwk.y !== 'string' ||
    !COORDINATE_PATTERN.test(jwk.y)
  ) {
    throw new KeysvcError('internal');
  }
  return Object.freeze({
    kid: jwk.kid,
    kty: 'EC',
    crv: 'P-256',
    x: jwk.x,
    y: jwk.y,
    alg: 'ES256',
    use: 'sig',
  });
}

export async function signEs256With<K extends SigningKeyId>(
  call: KeysvcCall,
  allowed: readonly K[],
  keyId: K,
  message: Uint8Array,
): Promise<{ readonly kid: string; readonly signature: Uint8Array }> {
  const response = await call('sign', {
    keyId: assertOneOf(keyId, allowed),
    message: encodeBytes(message, LIMITS.signMessageBytes),
  });
  return {
    kid: stringFrom(response, 'kid', KID_PATTERN),
    signature: bytesFrom(response, 'signature', ES256_SIGNATURE_BYTES),
  };
}

export async function publicKeysWith<K extends SigningKeyId>(
  call: KeysvcCall,
  allowed: readonly K[],
  keyId: K,
): Promise<readonly Es256PublicJwk[]> {
  const response = await call('public_keys', { keyId: assertOneOf(keyId, allowed) });
  return Object.freeze(arrayFrom(response, 'keys').map(toJwk));
}
