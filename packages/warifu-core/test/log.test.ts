import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { createLogger, REDACTED_MESSAGE } from '../src/log/index.ts';
import { randomBytesOf } from '../src/random.ts';
import { toBase32Lower } from '../src/encoding.ts';

function marker(): string {
  return `m${toBase32Lower(randomBytesOf(10))}`;
}

function collect() {
  const lines: string[] = [];
  const logger = createLogger({
    component: 'idp',
    level: 'trace',
    write: (line) => {
      lines.push(line);
    },
  });
  return { lines, logger, text: () => lines.join('') };
}

describe('ログの伏せ字（不変条件4）', () => {
  it('許可リストにないフィールドを落とし、数だけを出す', () => {
    const { logger, lines, text } = collect();
    const m = marker();
    logger.info({
      event: 'test.probe',
      email: `${m}@example.com`,
      token: m,
      headers: { cookie: `sid=${m}`, authorization: `Bearer ${m}` },
      body: { password: m },
    });
    expect(text()).not.toContain(m);
    const record = JSON.parse(lines[0] ?? '{}');
    expect(record.event).toBe('test.probe');
    expect(record.dropped).toBe(4);
    expect(record.component).toBe('idp');
  });

  it('形の合わない値を落とす（許可したキーでも）', () => {
    const { logger, text } = collect();
    const m = marker();
    logger.info({ op: `${m}@example.com`, route: `/v1/x?email=${m}`, status: m });
    expect(text()).not.toContain(m);
  });

  it('値を埋め込んだメッセージを伏せる', () => {
    const { logger, lines, text } = collect();
    const m = marker();
    logger.info(`user ${m}@example.com logged in`);
    logger.warn({ event: 'test.probe' }, `token=${m}`);
    expect(text()).not.toContain(m);
    expect(JSON.parse(lines[0] ?? '{}').msg).toBe(REDACTED_MESSAGE);
  });

  it('例外は名前とコードだけ', () => {
    const { logger, text } = collect();
    const m = marker();
    const error = Object.assign(new Error(`duplicate key ${m}`), {
      code: '23505',
      detail: `Key (lookup_mac)=(${m}) already exists.`,
      cause: new Error(m),
    });
    logger.error({ err: error });
    const out = text();
    expect(out).not.toContain(m);
    expect(out).toContain('"errorCode":"23505"');
    expect(out).toContain('"errorName":"Error"');
  });

  it('子のロガーの束縛も伏せる', () => {
    const { logger, text } = collect();
    const m = marker();
    logger.child({ reqId: 'req-1', user: m }).info({ event: 'test.probe' });
    expect(text()).not.toContain(m);
    expect(text()).toContain('"reqId":"req-1"');
  });

  it('レベルより軽いものは出さない', () => {
    const lines: string[] = [];
    const logger = createLogger({ component: 'keysvc', write: (line) => lines.push(line) });
    logger.debug({ event: 'test.probe' });
    logger.info({ event: 'test.probe' });
    expect(lines).toHaveLength(1);
  });

  it('Fastify 5 の loggerInstance として、URL のクエリ、Cookie、Authorization、本文を出さない', async () => {
    const { logger, text } = collect();
    const app = Fastify({ loggerInstance: logger as never });
    app.post('/v1/:op', async () => ({ ok: true }));
    const m = marker();
    const response = await app.inject({
      method: 'POST',
      url: `/v1/${m}?email=${m}%40example.com`,
      headers: { cookie: `sid=${m}`, authorization: `Bearer ${m}` },
      payload: { email: `${m}@example.com` },
    });
    await app.close();
    expect(response.statusCode).toBe(200);
    const out = text();
    expect(out).toContain('"route":"/v1/:op"');
    expect(out).toContain('"msg":"request completed"');
    expect(out).not.toContain(m);
  });
});
