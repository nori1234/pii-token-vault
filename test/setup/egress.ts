// 外へのつなぎの見張り（不変条件7、plan 2章「SSRF を防ぐ」、M10 の SSRF の横断）。
// Vitest の setupFiles（test/setup/egress-guard.ts）が、テストのファイルごとに入れて外す。見張る間は、このプロセスの
// 中の次のものを、ループバック（127.0.0.0/8、::1、localhost）と Unix ドメインソケットのほかへは、つながずに止めて
// 記録する。
// - TCP と TLS の接続（net.Socket の connect。http、https、fetch（undici）、tls、http2、pg が通る）
// - 名前解決（c-ares の問い合わせ（dns.resolve*、dns.promises、Resolver）と、dns.lookup と dns.lookupService）
// - UDP の送信（dgram）
// テストの中の割符のサービス（idp、relay、company-api、keysvc、sender）は、テストと同じプロセスで動く。送信サービスの
// 名前解決と最後の接続は、テストの補助が差し替える（test/setup/sender.ts）。そのため、割符のコードやライブラリ
// （oidc-provider、mailauth、nodemailer など）が、テストの中で外へつなごうとしたり、注入したリゾルバを通さずに名前を
// 引こうとしたりすると、ここで止まり、そのファイルが落ちる。
// 記録には、宛先（ホストとポート、名前）と、呼び出した場所（ファイルと行）だけを残す。URL のパスとクエリ、本文は
// 受け取らないので残らない（不変条件4）。
// 見張れないもの：ワーカースレッドと子プロセスの中の通信（割符のサービスは使わない。lint が child_process を止める）。

import dgram from 'node:dgram';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import { isIP, Socket } from 'node:net';
import { getSystemErrorMap } from 'node:util';

export interface EgressAttempt {
  /** tcp（TCP と TLS の接続）、dns（名前解決）、udp（UDP の送信）。 */
  readonly kind: 'tcp' | 'dns' | 'udp';
  /** 宛先。tcp と udp は「ホスト:ポート」、dns は名前。 */
  readonly destination: string;
  /** 止めた入口（例：net.Socket.connect、dns.queryTxt、dns.lookup、dgram.send）。 */
  readonly via: string;
  /** 呼び出した場所（node の内部とこのファイルを除いた、最初のファイルと行）。分からなければ unknown。 */
  readonly origin: string;
}

interface GuardState {
  readonly attempts: EgressAttempt[];
  restore: (() => void) | undefined;
}

// setupFiles とテストのファイルが別々にこのモジュールを読み込んでも、同じ記録を見るように、プロセスに置く。
const STATE_KEY = Symbol.for('warifu.test.egressGuard');

function state(): GuardState {
  const holder = process as unknown as Record<symbol, GuardState | undefined>;
  let found = holder[STATE_KEY];
  if (found === undefined) {
    found = { attempts: [], restore: undefined };
    holder[STATE_KEY] = found;
  }
  return found;
}

const BLOCKED_CODE = 'EGRESS_BLOCKED_IN_TESTS';

function blockedError(): Error {
  return Object.assign(new Error('テストの中では、外へつながない（test/setup/egress.ts）'), {
    code: BLOCKED_CODE,
  });
}

/** c-ares の問い合わせを断るときに返す値（libuv の ECONNREFUSED。dns の側が DNSException にする）。 */
const UV_ECONNREFUSED = (() => {
  for (const [code, [name]] of getSystemErrorMap()) if (name === 'ECONNREFUSED') return code;
  throw new Error('ECONNREFUSED の値が見つからない');
})();

/** ループバックのアドレスか、localhost か。名前は localhost だけ（Node は *.localhost を引けない）。 */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[(.*)\]$/, '$1');
  if (h === 'localhost') return true;
  const version = isIP(h);
  if (version === 4) return h.startsWith('127.');
  if (version === 6) return h === '::1' || /^::ffff:127\./.test(h);
  return false;
}

function originOf(): string {
  const limit = Error.stackTraceLimit;
  Error.stackTraceLimit = 60;
  const stack = new Error().stack ?? '';
  Error.stackTraceLimit = limit;
  for (const line of stack.split('\n').slice(1)) {
    if (line.includes('node:') || line.includes('test/setup/egress.ts')) continue;
    const match = /(?:\(|at )(?:file:\/\/)?([^()\s]+):(\d+):\d+\)?\s*$/.exec(line.trim());
    if (match === null) continue;
    const file = match[1] ?? '';
    const cwd = `${process.cwd()}/`;
    return `${file.startsWith(cwd) ? file.slice(cwd.length) : file}:${match[2]}`;
  }
  return 'unknown';
}

function record(kind: EgressAttempt['kind'], destination: string, via: string): void {
  state().attempts.push({ kind, destination, via, origin: originOf() });
}

type ConnectTarget =
  | { readonly ipc: true }
  | { readonly ipc: false; readonly host: string; readonly port: string };

/** net.Socket の connect の引数（net.connect が渡す正規化した配列も）から、宛先を取り出す。 */
function connectTarget(args: readonly unknown[]): ConnectTarget {
  const normalized = Array.isArray(args[0]) ? (args[0] as unknown[]) : args;
  const first = normalized[0];
  const isPort = (value: unknown) =>
    typeof value === 'number' || (typeof value === 'string' && /^\d+$/.test(value));
  if (typeof first === 'string' && !isPort(first)) return { ipc: true };
  if (isPort(first)) {
    const host = normalized[1];
    return { ipc: false, host: typeof host === 'string' ? host : 'localhost', port: String(first) };
  }
  if (first !== null && typeof first === 'object') {
    const options = first as { path?: unknown; host?: unknown; port?: unknown };
    if (typeof options.path === 'string' && options.path !== '') return { ipc: true };
    return {
      ipc: false,
      host: typeof options.host === 'string' ? options.host : 'localhost',
      port: String(options.port),
    };
  }
  return { ipc: false, host: 'unknown', port: 'unknown' };
}

type ResolverHandle = Record<string, (...args: unknown[]) => unknown>;

/** 見張りを入れる（入っていれば何もしない）。 */
export function installEgressGuard(): void {
  const guard = state();
  if (guard.restore !== undefined) return;
  const undo: (() => void)[] = [];

  // TCP と TLS（tls.TLSSocket も net.Socket の connect を通る）。
  const connect = Socket.prototype.connect;
  Socket.prototype.connect = function (this: Socket, ...args: unknown[]) {
    const target = connectTarget(args);
    if (target.ipc || isLoopbackHost(target.host)) {
      return (connect as (...a: unknown[]) => Socket).apply(this, args);
    }
    record('tcp', `${target.host}:${target.port}`, 'net.Socket.connect');
    process.nextTick(() => this.destroy(blockedError()));
    return this;
  } as typeof connect;
  undo.push(() => {
    Socket.prototype.connect = connect;
  });

  // c-ares の問い合わせ（dns.resolve*、dns.promises.resolve*、Resolver のどれも、同じクラスの handle を通る）。
  // ループバックの名前も断る（テストの名前解決は、すべて注入したリゾルバを通すため）。
  const sample = new dns.Resolver() as unknown as { _handle?: object };
  if (sample._handle === undefined)
    throw new Error('dns.Resolver の handle が見つからない（Node の版を確かめる）');
  const handleProto = Object.getPrototypeOf(sample._handle) as ResolverHandle;
  for (const name of Object.getOwnPropertyNames(handleProto)) {
    if (!/^query[A-Z]/.test(name) && name !== 'getHostByAddr') continue;
    const original = handleProto[name] as ResolverHandle[string];
    handleProto[name] = (_req: unknown, host: unknown) => {
      record('dns', String(host), `dns.${name}`);
      return UV_ECONNREFUSED;
    };
    undo.push(() => {
      handleProto[name] = original;
    });
  }

  // dns.lookup（getaddrinfo）。localhost とループバックだけを通す。
  const lookup = dns.lookup;
  const promisesLookup = dns.promises.lookup;
  const patchedLookup = function (this: unknown, hostname: string, ...rest: unknown[]) {
    if (isLoopbackHost(String(hostname))) {
      return (lookup as (...a: unknown[]) => unknown).call(this, hostname, ...rest);
    }
    record('dns', String(hostname), 'dns.lookup');
    const callback = rest.at(-1);
    if (typeof callback === 'function')
      process.nextTick(callback as (e: Error) => void, blockedError());
    return {};
  };
  const patchedPromisesLookup = async (hostname: string, ...rest: unknown[]) => {
    if (isLoopbackHost(String(hostname))) {
      return (promisesLookup as (...a: unknown[]) => Promise<unknown>)(hostname, ...rest);
    }
    record('dns', String(hostname), 'dns.promises.lookup');
    throw blockedError();
  };

  // dns.lookupService（getnameinfo）。dns.lookup とも c-ares の handle とも別の入口で、どちらの差し替えも通らない
  // ので、別に差し替える。ループバックのアドレスだけを通す。IP アドレスでない引数は、元の関数がつながずに断る。
  const lookupService = dns.lookupService;
  const promisesLookupService = dns.promises.lookupService;
  const passesLookupService = (address: string) =>
    isIP(String(address)) === 0 || isLoopbackHost(String(address));
  const patchedLookupService = function (this: unknown, address: string, ...rest: unknown[]) {
    if (passesLookupService(address)) {
      return (lookupService as (...a: unknown[]) => unknown).call(this, address, ...rest);
    }
    record('dns', String(address), 'dns.lookupService');
    const callback = rest.at(-1);
    if (typeof callback === 'function')
      process.nextTick(callback as (e: Error) => void, blockedError());
    return {};
  };
  const patchedPromisesLookupService = async (address: string, ...rest: unknown[]) => {
    if (passesLookupService(address)) {
      return (promisesLookupService as (...a: unknown[]) => Promise<unknown>)(address, ...rest);
    }
    record('dns', String(address), 'dns.promises.lookupService');
    throw blockedError();
  };

  (dns as { lookup: unknown }).lookup = patchedLookup;
  (dns.promises as { lookup: unknown }).lookup = patchedPromisesLookup;
  (dns as { lookupService: unknown }).lookupService = patchedLookupService;
  (dns.promises as { lookupService: unknown }).lookupService = patchedPromisesLookupService;
  // `import { lookup, lookupService } from 'node:dns'`（と 'node:dns/promises'）の束縛も、差し替えた関数を指すようにする。
  syncBuiltinESMExports();
  undo.push(() => {
    (dns as { lookup: unknown }).lookup = lookup;
    (dns.promises as { lookup: unknown }).lookup = promisesLookup;
    (dns as { lookupService: unknown }).lookupService = lookupService;
    (dns.promises as { lookupService: unknown }).lookupService = promisesLookupService;
    syncBuiltinESMExports();
  });

  // UDP。connect した後の send は、connect で確かめる。宛先を省いた send は、ループバックに送る。
  const udpConnect = dgram.Socket.prototype.connect;
  const udpSend = dgram.Socket.prototype.send;
  dgram.Socket.prototype.connect = function (this: dgram.Socket, ...args: unknown[]) {
    const [port, address] = args;
    if (typeof address === 'string' && !isLoopbackHost(address)) {
      record('udp', `${address}:${String(port)}`, 'dgram.connect');
      throw blockedError();
    }
    return (udpConnect as (...a: unknown[]) => void).apply(this, args);
  } as typeof udpConnect;
  dgram.Socket.prototype.send = function (this: dgram.Socket, ...args: unknown[]) {
    // 宛先のアドレスは、本文の後ろの引数のうち、最後の文字列（ポートは数）。
    const strings = args.slice(1).filter((a): a is string => typeof a === 'string');
    const address = strings.at(-1);
    if (address !== undefined && !isLoopbackHost(address)) {
      const port = args
        .slice(1)
        .filter((a) => typeof a === 'number')
        .at(-1);
      record('udp', `${address}:${String(port)}`, 'dgram.send');
      throw blockedError();
    }
    return (udpSend as (...a: unknown[]) => void).apply(this, args);
  } as typeof udpSend;
  undo.push(() => {
    dgram.Socket.prototype.connect = udpConnect;
    dgram.Socket.prototype.send = udpSend;
  });

  guard.restore = () => {
    for (const step of undo.reverse()) step();
  };
}

/** 見張りを外す（入っていなければ何もしない）。記録は残す（takeEgressAttempts で取り出す）。 */
export function uninstallEgressGuard(): void {
  const guard = state();
  guard.restore?.();
  guard.restore = undefined;
}

export function egressGuardInstalled(): boolean {
  return state().restore !== undefined;
}

/** 止めたつなぎの記録を取り出して、空にする。 */
export function takeEgressAttempts(): EgressAttempt[] {
  return state().attempts.splice(0);
}

/** 見張りが止めたつなぎで出た誤りか（テストで、止まったことを確かめるとき）。 */
export function isEgressBlocked(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current !== null && typeof current === 'object'; depth += 1) {
    if ((current as { code?: unknown }).code === BLOCKED_CODE) return true;
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}
