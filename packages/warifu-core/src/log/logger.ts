// ロガー。1行の JSON を出す。Fastify 5 の loggerInstance に渡せる形にする（M3 でつなぐ）。
// 伏せ字の規則は redact.ts だけに置き、ここでは必ずそれを通す。ログは例外を投げない。

import type { Component } from '../ids.ts';
import { sanitizeFields, sanitizeMessage } from './redact.ts';

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export type LogMethod = (
  fieldsOrMessage: Readonly<Record<string, unknown>> | string,
  message?: string,
) => void;

export interface Logger {
  level: LogLevel;
  trace: LogMethod;
  debug: LogMethod;
  info: LogMethod;
  warn: LogMethod;
  error: LogMethod;
  fatal: LogMethod;
  child(bindings: Readonly<Record<string, unknown>>, options?: unknown): Logger;
}

const LEVEL_VALUE: Readonly<Record<LogLevel, number>> = Object.freeze({
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
});

const LEVELS = Object.keys(LEVEL_VALUE) as LogLevel[];

export interface LoggerOptions {
  readonly component: Component;
  readonly level?: LogLevel;
  /** 既定は標準出力。テストは配列に集める。 */
  readonly write?: (line: string) => void;
  readonly now?: () => Date;
}

function defaultWrite(line: string): void {
  process.stdout.write(line);
}

function build(
  options: LoggerOptions,
  bindings: Readonly<Record<string, string | number | boolean>>,
  initialLevel: LogLevel,
): Logger {
  const write = options.write ?? defaultWrite;
  const now = options.now ?? (() => new Date());
  let level: LogLevel = LEVEL_VALUE[initialLevel] === undefined ? 'info' : initialLevel;

  const emit = (lvl: LogLevel, first: unknown, second: unknown): void => {
    try {
      if (LEVEL_VALUE[lvl] < LEVEL_VALUE[level]) return;
      let fields: Record<string, string | number | boolean> = {};
      let message: string | undefined;
      if (typeof first === 'string') {
        message = sanitizeMessage(first);
      } else {
        fields = sanitizeFields((first ?? {}) as Readonly<Record<string, unknown>>);
        message = sanitizeMessage(second);
      }
      const record: Record<string, string | number | boolean> = {
        time: now().toISOString(),
        level: lvl,
        component: options.component,
        ...bindings,
        ...fields,
      };
      if (message !== undefined) record.msg = message;
      write(`${JSON.stringify(record)}\n`);
    } catch {
      // ログの失敗で、処理を止めない。
    }
  };

  const logger: Logger = {
    get level() {
      return level;
    },
    set level(value: LogLevel) {
      if (LEVELS.includes(value)) level = value;
    },
    trace: (a, b) => emit('trace', a, b),
    debug: (a, b) => emit('debug', a, b),
    info: (a, b) => emit('info', a, b),
    warn: (a, b) => emit('warn', a, b),
    error: (a, b) => emit('error', a, b),
    fatal: (a, b) => emit('fatal', a, b),
    child(childBindings) {
      const merged = { ...bindings, ...sanitizeFields(childBindings ?? {}) };
      return build(options, merged, level);
    },
  };
  return logger;
}

export function createLogger(options: LoggerOptions): Logger {
  return build(options, {}, options.level ?? 'info');
}
