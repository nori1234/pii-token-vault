import { describe, expect, it } from 'vitest';
import { cancellationOutcomeOf } from '../src/outbox.ts';

describe('取消の SET の配送の結果の分け方（ADR 0026 の O-67）', () => {
  it('202 だけを配送済みにし、set_too_old は送り直し、一時的な失敗は再試行、ほかは保留', () => {
    expect(cancellationOutcomeOf({ ok: true, status: 202 })).toBe('delivered');
    expect(cancellationOutcomeOf({ ok: true, status: 200 })).toBe('held');
    expect(cancellationOutcomeOf({ ok: true, status: 204 })).toBe('held');
    expect(
      cancellationOutcomeOf({
        ok: false,
        reason: 'http_status',
        status: 400,
        setError: 'set_too_old',
      }),
    ).toBe('reissue');
    expect(
      cancellationOutcomeOf({
        ok: false,
        reason: 'http_status',
        status: 400,
        setError: 'iat_in_future',
      }),
    ).toBe('held');
    for (const status of [400, 401, 403, 404, 410]) {
      expect(cancellationOutcomeOf({ ok: false, reason: 'http_status', status })).toBe('held');
    }
    for (const status of [429, 500, 502, 503]) {
      expect(cancellationOutcomeOf({ ok: false, reason: 'http_status', status })).toBe('retry');
    }
    for (const reason of ['connect_failed', 'timeout', 'dns_failed', 'no_address'] as const) {
      expect(cancellationOutcomeOf({ ok: false, reason })).toBe('retry');
    }
    for (const reason of ['invalid_destination', 'blocked_address', 'too_large'] as const) {
      expect(cancellationOutcomeOf({ ok: false, reason })).toBe('held');
    }
    expect(cancellationOutcomeOf({ ok: false, reason: 'redirect', status: 302 })).toBe('held');
    // sender につながらない（例外）は、再試行。
    expect(cancellationOutcomeOf(undefined)).toBe('retry');
  });
});
