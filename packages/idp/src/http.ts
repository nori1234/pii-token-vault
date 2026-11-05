// idp の HTTP の小さな部品（app.ts と routes/ で共有する）。
// 応答の本文は固定の形だけにする。受け取った値もライブラリのメッセージも入れない。

import type { FastifyRequest } from 'fastify';

export const FAILED = Object.freeze({ error: 'failed' });
export const RATE_LIMITED = Object.freeze({ error: 'rate_limited' });
export const LOGIN_REQUIRED = Object.freeze({ error: 'login_required' });

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** JSON の本文。オブジェクトでなければ空のオブジェクト。 */
export function bodyOf(request: FastifyRequest): Record<string, unknown> {
  return isRecord(request.body) ? request.body : {};
}

export function cookieOf(request: FastifyRequest, name: string): string | undefined {
  const header = request.headers.cookie;
  if (typeof header !== 'string') return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}
